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
	"github.com/containernetworking/plugins/pkg/hns"
)

type NetConf struct {
	hns.NetConf

	IPMasq bool
	clusterNetworkPrefix net.IPNet
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

	epName := hns.ConstructEndpointName(args.ContainerID, args.Netns, n.Name)

	hnsEndpoint, err := hns.ProvisionEndpoint(epName, hnsNetwork.Id, args.ContainerID, func() (*hcsshim.HNSEndpoint, error) {
		// run the IPAM plugin and get back the config to apply
		r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
		if err != nil {
			return nil, err
		}

		// Convert whatever the IPAM result was into the current Result type
		result, err := current.NewResultFromResult(r)
		if err != nil {
			return nil, err
		}

		if len(result.IPs) == 0 {
			return nil, errors.New("IPAM plugin return is missing IP config")
		}

		// Calculate gateway for bridge network (needs to be x.2)
		gw := result.IPs[0].Address.IP.Mask(result.IPs[0].Address.Mask)
		gw[len(gw)-1] += 2

		// NAT based on the the configured cluster network
		if n.IPMasq {
			n.ApplyOutboundNatPolicy(n.clusterNetworkPrefix.String())
		}

		hnsEndpoint := &hcsshim.HNSEndpoint{
			Name:           epName,
			VirtualNetwork: hnsNetwork.Id,
			DNSServerList:  strings.Join(result.DNS.Nameservers, ","),
			DNSSuffix:      result.DNS.Domain,
			GatewayAddress: gw.String(),
			IPAddress:      result.IPs[0].Address.IP,
			Policies:       n.MarshalPolicies(),
		}

		return hnsEndpoint, nil
	})

	if err != nil {
		return err
	}

	result, err := hns.ConstructResult(hnsNetwork, hnsEndpoint)
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

	epName := hns.ConstructEndpointName(args.ContainerID, args.Netns, n.Name)

	return hns.DeprovisionEndpoint(epName, args.Netns, args.ContainerID)
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
