package hns

import (
	"strings"
	"encoding/json"
	"github.com/containernetworking/cni/pkg/types"
)

type NetConf struct {
	types.NetConf

	additionalArgs    []policyArgument `json:"AdditionalArgs,omitempty"`
}

type policyArgument struct {
	Type string
	Value map[string]interface{}
}

func (n *NetConf) MarshalPolicies() []json.RawMessage {
	if n.additionalArgs == nil {
		n.additionalArgs = []policyArgument{}
	}

	var result []json.RawMessage
	for policyArg := range n.additionalArgs {
		if data, err := json.Marshal(policyArg); err == nil {
			result = append(result, data)
		}
	}

	return result
}

func (n *NetConf) ApplyOutboundNatPolicy(nwToNat string) {
	if n.additionalArgs == nil {
		n.additionalArgs = []policyArgument{}
	}

	for _, policy := range n.additionalArgs {
		if !strings.EqualFold(policy.Type, "EndpointPolicy") {
			continue
		}

		pv := policy.Value
		if !hasKey(pv, "Type") {
			continue
		}

		if !strings.EqualFold(pv["Type"].(string), "OutBoundNAT") {
			continue
		}

		if !hasKey(pv, "ExceptionList") {
			// add the exception since there weren't any
			pv["ExceptionList"] = []interface{}{nwToNat}
			return
		}

		nets := pv["ExceptionList"].([]interface{})
		for _, net := range nets {
			if net.(string) == nwToNat {
				// found it - do nothing
				return
			}
		}

		// its not in the list of exceptions, add it and we're done
		pv["ExceptionList"] = append(nets, nwToNat)
		return
	}

	// didn't find the policy, add it
	natEntry := policyArgument{
		Type: "EndpointPolicy",
		Value: map[string]interface{}{
			"Type": "OutBoundNAT",
			"ExceptionList": []interface{}{
				nwToNat,
			},
		},
	}

	n.additionalArgs = append(n.additionalArgs, natEntry)
}

func (n *NetConf) ApplyDefaultPAPolicy(paAddress string) {
	if n.additionalArgs == nil {
		 n.additionalArgs = []policyArgument{}
	}

	// if its already present, leave untouched
	for _, policy := range n.additionalArgs {
		if policy.Type == "EndpointPolicy" {
			if hasKey(policy.Value, "PA") {
				// found it, don't override
				return
			}
		}
	}

	// did not find, add it now
	paPolicyData := map[string]interface{}{
		"Type": "PA",
		"PA":   paAddress,
	}
	paPolicy := &policyArgument{
		Type:  "EndpointPolicy",
		Value: paPolicyData,
	}

	n.additionalArgs = append(n.additionalArgs, *paPolicy)

	return
}

func hasKey(m map[string]interface{}, k string) bool {
	_, ok := m[k]
	return ok
}

