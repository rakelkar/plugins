package hns

import (
	"github.com/Microsoft/hcsshim"
	"log"
	"strings"
	"github.com/containernetworking/cni/pkg/types/current"
	"net"
)

func ConstructEndpointName(containerID string, netNs string, networkName string) string {
	if netNs != "" {
		splits := strings.Split(netNs, ":")
		if len(splits) == 2 {
			containerID = splits[1]
		}
	}
	epName := containerID + "_" + networkName
	return epName
}

func DeprovisionEndpoint(epName string, netns string, containerID string) error {
	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(epName)
	if err != nil {
		log.Printf("[win-cni] Failed to find endpoint %v, err:%v", epName, err)
		return err
	}

	if netns != "none" {
		// Shared endpoint removal. Do not remove the endpoint.
		err := hnsEndpoint.ContainerDetach(containerID)
		if err != nil {
			log.Printf("[win-cni] Failed to detach the container endpoint %v, err:%v", epName, err)
		}
		return nil
	}

	err = hcsshim.HotDetachEndpoint(containerID, hnsEndpoint.Id)
	if err != nil {
		log.Printf("[win-cni] Failed to detach endpoint %v, err:%v", epName, err)
		return nil
	}

	_, err = hnsEndpoint.Delete()
	if err != nil {
		log.Printf("[win-cni] Failed to delete endpoint %v, err:%v", epName, err)
		return nil
	}

	return nil
}

type EndpointMakerFunc func() (*hcsshim.HNSEndpoint, error)

func ProvisionEndpoint(epName string, expectedNetworkId string, containerID string, makeEndpoint EndpointMakerFunc) (*hcsshim.HNSEndpoint, error) {
	// check if endpoint already exists
	createEndpoint := true
	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(epName)
	if hnsEndpoint != nil && hnsEndpoint.VirtualNetwork != expectedNetworkId {
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

		if hnsEndpoint, err = makeEndpoint(); err != nil {
			return nil, err
		}

		if hnsEndpoint, err = hnsEndpoint.Create(); err != nil {
			return nil, err
		}

	}

	// hot attach
	if err = hcsshim.HotAttachEndpoint(containerID, hnsEndpoint.Id); err != nil {
		return nil, err
	}

	return hnsEndpoint, nil
}

func ConstructResult(hnsNetwork *hcsshim.HNSNetwork, hnsEndpoint *hcsshim.HNSEndpoint) (*current.Result, error) {
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
