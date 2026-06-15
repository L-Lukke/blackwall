package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

type policyFile struct {
	Devices map[string]devicePolicy `json:"devices"`
}

type devicePolicy struct {
	AllowedActions []string `json:"allowed_actions"`
}

func main() {
	path := flag.String("file", "configs/policies/devices.json", "policy file path")
	device := flag.String("device", "", "device id to update")
	actions := flag.String("actions", "", "comma-separated allowed actions for the device")
	flag.Parse()

	policies, err := loadPolicyFile(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load policy file: %v\n", err)
		os.Exit(1)
	}

	if *device == "" && *actions == "" {
		printPolicies(policies)
		return
	}
	if *device == "" || *actions == "" {
		fmt.Fprintln(os.Stderr, "-device and -actions must be provided together")
		os.Exit(2)
	}

	nextActions := parseActions(*actions)
	if len(nextActions) == 0 {
		fmt.Fprintln(os.Stderr, "-actions must contain at least one action")
		os.Exit(2)
	}

	if policies.Devices == nil {
		policies.Devices = map[string]devicePolicy{}
	}
	policies.Devices[*device] = devicePolicy{AllowedActions: nextActions}

	if err := savePolicyFile(*path, policies); err != nil {
		fmt.Fprintf(os.Stderr, "save policy file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("updated %s allowed_actions=%s\n", *device, strings.Join(nextActions, ","))
}

func loadPolicyFile(path string) (policyFile, error) {
	var policies policyFile
	raw, err := os.ReadFile(path)
	if err != nil {
		return policies, err
	}
	if err := json.Unmarshal(raw, &policies); err != nil {
		return policies, err
	}
	if policies.Devices == nil {
		policies.Devices = map[string]devicePolicy{}
	}
	return policies, nil
}

func savePolicyFile(path string, policies policyFile) error {
	raw, err := json.MarshalIndent(policies, "", "\t")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o644)
}

func printPolicies(policies policyFile) {
	devices := make([]string, 0, len(policies.Devices))
	for device := range policies.Devices {
		devices = append(devices, device)
	}
	sort.Strings(devices)

	for _, device := range devices {
		actions := append([]string(nil), policies.Devices[device].AllowedActions...)
		sort.Strings(actions)
		fmt.Printf("%s: %s\n", device, strings.Join(actions, ","))
	}
}

func parseActions(raw string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		action := strings.TrimSpace(part)
		if action == "" {
			continue
		}
		if _, ok := seen[action]; ok {
			continue
		}
		seen[action] = struct{}{}
		out = append(out, action)
	}
	sort.Strings(out)
	return out
}
