//
// Copyright 2014 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/Microsoft/hcsshim"
	"strings"
	"log"
)

type NetConf struct {
	types.NetConf
	additionalArgs []json.RawMessage `json:"AdditionalArgs,omitempty"`
}

type gwInfo struct {
	gws               []net.IPNet
	family            int
	defaultRouteFound bool
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func loadNetConf(bytes []byte) (*NetConf, string, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", fmt.Errorf("failed to load netconf: %v", err)
	}
	return n, n.CNIVersion, nil
}

func constructResult(hnsNetwork *hcsshim.HNSNetwork, hnsEndpoint *hcsshim.HNSEndpoint) (*current.Result, error) {
	resultInterface := &current.Interface{
		Name: hnsEndpoint.Name,
		Mac:  hnsEndpoint.MacAddress,
	}
	_, ipSubnet, err := net.ParseCIDR(hnsNetwork.Subnets[0].AddressPrefix)
	if err != nil {
		return nil, err
	}

	resultIPConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   hnsEndpoint.IPAddress,
			Mask: ipSubnet.Mask},
		Gateway: net.ParseIP(hnsEndpoint.GatewayAddress),
	}
	result := &current.Result{}
	result.Interfaces = []*current.Interface{resultInterface}
	result.IPs = []*current.IPConfig{resultIPConfig}

	return result, nil
}

func getEndpointName(args *skel.CmdArgs, n *NetConf) string {
	containerIDToUse := args.ContainerID
	if args.Netns != "" {
		splits := strings.Split(args.Netns, ":")
		if len(splits) == 2 {
			containerIDToUse = splits[1]
		}
	}
	epName := containerIDToUse + "_" + n.Name
	return epName
}

func cmdAdd(args *skel.CmdArgs) error {
	n, cniVersion, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	networkName := n.Name
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
	if err != nil {
		return err
	}

	if hnsNetwork == nil  {
		return fmt.Errorf("network %v not found", networkName)
	}

	if hnsNetwork.Type != "L2Bridge" {
		return fmt.Errorf("network %v is of an unexpected type: %v", networkName, hnsNetwork.Type)
	}

	epName := getEndpointName(args, n)

	// check if endpoint already exists
	createEndpoint := true
	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(epName)
	if hnsEndpoint != nil && hnsEndpoint.VirtualNetwork != hnsNetwork.Id {
		log.Printf("[win-cni] Found existing endpoint %v", epName)
		createEndpoint = false
	}

	if createEndpoint {
		if hnsEndpoint != nil {
			_, err = hnsEndpoint.Delete()
			if err != nil {
				log.Printf("[win-cni] Failed to delete stale endpoint %v, err:%v", epName, err)
			}
		}

		// run the IPAM plugin and get back the config to apply
		r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
		if err != nil {
			return err
		}

		// Convert whatever the IPAM result was into the current Result type
		result, err := current.NewResultFromResult(r)
		if err != nil {
			return err
		}

		if len(result.IPs) == 0 {
			return errors.New("IPAM plugin return is missing IP config")
		}

		// Calculate gateway for bridge network
		gw := result.IPs[0].Address.IP.Mask(result.IPs[0].Address.Mask)
		gw[len(gw)-1] += 2

		hnsEndpoint := &hcsshim.HNSEndpoint{
			Name:           epName,
			VirtualNetwork: hnsNetwork.Id,
			DNSServerList:  strings.Join(n.DNS.Nameservers, ","),
			DNSSuffix:      result.DNS.Domain,
			GatewayAddress: gw.String(),
			IPAddress:      result.IPs[0].Address.IP,
			Policies:       n.additionalArgs,
		}

		if hnsEndpoint, err = hnsEndpoint.Create(); err != nil {
			return err
		}
	}

	// hot attach
	if err = hcsshim.HotAttachEndpoint(args.ContainerID, hnsEndpoint.Id); err != nil {
		return err
	}

	result, err := constructResult(hnsNetwork, hnsEndpoint)
	if err != nil {
		return err
	}

	return types.PrintResult(result, cniVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	n, _, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	if err := ipam.ExecDel(n.IPAM.Type, args.StdinData); err != nil {
		return err
	}

	if args.Netns == "" {
		return nil
	}

	epName := getEndpointName(args, n)
	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(epName)
	if err != nil {
		log.Printf("[win-cni] Failed to find endpoint %v, err:%v", epName, err)
		return err
	}

	if hnsEndpoint != nil {
		if args.Netns != "none" {
			// Shared endpoint removal. Do not remove the endpoint.
			err = hnsEndpoint.ContainerDetach(args.ContainerID)
			if err != nil {
				log.Printf("[win-cni] Failed to detach the container endpoint %v, err:%v", epName, err)
			}
			return nil
		}

		err = hcsshim.HotDetachEndpoint(args.ContainerID, hnsEndpoint.Id)
		if err != nil {
			log.Printf("[win-cni] Failed to detach endpoint %v, err:%v", epName, err)
			return nil
		}

		_, err = hnsEndpoint.Delete()
		if err != nil {
			log.Printf("[win-cni] Failed to delete endpoint %v, err:%v", epName, err)
			return nil
		}
	}

	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
