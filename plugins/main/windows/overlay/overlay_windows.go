// +build windows
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
	"runtime"

	"github.com/Microsoft/hcsshim"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/hns"
	"github.com/containernetworking/plugins/pkg/ipam"
	"strings"
)

type NetConf struct {
	hns.NetConf

	IPMasq            bool
	endpointMacPrefix string `json:"endpointMacPrefix,omitempty"`
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

	if n.endpointMacPrefix != "" {
		if len(n.endpointMacPrefix) != 5 || n.endpointMacPrefix[2] != '-' {
			return fmt.Errorf("endpointMacPrefix [%v] is invalid, value must be of the format xx-xx", n.endpointMacPrefix)
		}
	} else{
	    n.endpointMacPrefix="0E-2A"
	}

	networkName := n.Name
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
	if err != nil {
		return fmt.Errorf("Error while GETHNSNewtorkByName(%v): %v",networkName,err)
	}

	if hnsNetwork == nil {
		return fmt.Errorf("network %v not found", networkName)
	}

	if hnsNetwork.Type != "Overlay" {
		return fmt.Errorf("network %v is of an unexpected type: %v", networkName, hnsNetwork.Type)
	}

	epName := hns.ConstructEndpointName(args.ContainerID, args.Netns, n.Name)

	hnsEndpoint, err := hns.ProvisionEndpoint(epName, hnsNetwork.Id, args.ContainerID, func() (*hcsshim.HNSEndpoint, error) {
		// run the IPAM plugin and get back the config to apply
		r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
		if err != nil {
			return nil, fmt.Errorf("Error while ipam.ExecAdd: %v",err)
		}

		// Convert whatever the IPAM result was into the current Result type
		result, err := current.NewResultFromResult(r)
		if err != nil {
			return nil, fmt.Errorf("Error while NewResultFromResult: %v",err)
		}

		if len(result.IPs) == 0 {
			return nil, errors.New("IPAM plugin return is missing IP config")
		}

		ipAddr := result.IPs[0].Address.IP.To4()
		// conjure a MAC based on the IP for Overlay
		macAddr := fmt.Sprintf("%v-%02x-%02x-%02x-%02x", n.endpointMacPrefix, ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3])
		// use the HNS network gateway
		gw := hnsNetwork.Subnets[0].GatewayAddress
		n.ApplyDefaultPAPolicy(hnsNetwork.ManagementIP)
		if n.IPMasq {
			n.ApplyOutboundNatPolicy(hnsNetwork.Subnets[0].AddressPrefix)
		}

		hnsEndpoint := &hcsshim.HNSEndpoint{
			Name:           epName,
			VirtualNetwork: hnsNetwork.Id,
			DNSServerList:  strings.Join(result.DNS.Nameservers, ","),
			DNSSuffix:      result.DNS.Domain,
			GatewayAddress: gw,
			IPAddress:      ipAddr,
			MacAddress:     macAddr,
			Policies:       n.MarshalPolicies(),
		}

		return hnsEndpoint, nil
	})

	if err != nil {
		return fmt.Errorf("Error while ProvisionEndpoint(%v,%v,%v) :%v",epName, hnsNetwork.Id,args.ContainerID, err)
	}

	result, err := hns.ConstructResult(hnsNetwork, hnsEndpoint)
	if err != nil {
		return fmt.Errorf("Error while constructResult: %v",err)
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
