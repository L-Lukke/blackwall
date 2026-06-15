package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/L-Lukke/blackwall/scenarios/internal/procmanager"
	"github.com/L-Lukke/blackwall/scenarios/internal/runner"
)

func main() {
	deviceFlag := flag.String("device", "sensor", "device to test: sensor, lock, light, all")
	flowFlag := flag.String("flow", "all", "flow to run: owner-control, delegation, revocation, ownership-transfer, vp-challenge, data-flow-mediation, all")
	jsonFlag := flag.Bool("json", false, "emit JSON output")
	timeoutFlag := flag.Duration("timeout", 40*time.Second, "service health timeout")
	flag.Parse()

	cfg := runner.LoadConfig()
	client := runner.New(cfg)
	manager := procmanager.New(procmanager.FindRepoRoot())

	if err := manager.StartAll(); err != nil {
		fmt.Fprintf(os.Stderr, "start managed services: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := manager.StopAll(); err != nil {
			fmt.Fprintf(os.Stderr, "stop managed services: %v\n", err)
		}
	}()

	if ok := waitForHealthy(client, *timeoutFlag); !ok {
		fmt.Fprintln(os.Stderr, "services did not become healthy in time")
		printHealth(client.CheckHealth())
		os.Exit(1)
	}

	targets, err := selectedTargets(client, *deviceFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	failed := false
	var allResults []runner.ScenarioResult
	for _, target := range targets {
		if !*jsonFlag {
			fmt.Printf("== %s ==\n", target.Name)
		}
		results, err := runSelected(client, target, *flowFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		for _, result := range results {
			allResults = append(allResults, result)
			if !*jsonFlag {
				printResult(result)
			}
			if !result.Passed {
				failed = true
			}
		}
	}

	if *jsonFlag {
		if err := json.NewEncoder(os.Stdout).Encode(allResults); err != nil {
			fmt.Fprintf(os.Stderr, "encode JSON results: %v\n", err)
			os.Exit(1)
		}
	}

	if failed {
		os.Exit(1)
	}
}

func selectedTargets(client *runner.Client, device string) ([]runner.DeviceTarget, error) {
	switch strings.ToLower(strings.TrimSpace(device)) {
	case "sensor":
		return []runner.DeviceTarget{client.SensorTarget()}, nil
	case "lock":
		return []runner.DeviceTarget{client.LockTarget()}, nil
	case "light":
		return []runner.DeviceTarget{client.LightTarget()}, nil
	case "all":
		return []runner.DeviceTarget{
			client.SensorTarget(),
			client.LockTarget(),
			client.LightTarget(),
		}, nil
	default:
		return nil, fmt.Errorf("unknown device %q; expected sensor, lock, light, or all", device)
	}
}

func runSelected(client *runner.Client, target runner.DeviceTarget, flow string) ([]runner.ScenarioResult, error) {
	switch strings.ToLower(strings.TrimSpace(flow)) {
	case "owner-control":
		return []runner.ScenarioResult{client.RunOwnerControlOn(target)}, nil
	case "delegation":
		return []runner.ScenarioResult{client.RunDelegationOn(target)}, nil
	case "revocation":
		return []runner.ScenarioResult{client.RunRevocationOn(target)}, nil
	case "ownership-transfer":
		return []runner.ScenarioResult{client.RunOwnershipTransferOn(target)}, nil
	case "vp-challenge":
		return []runner.ScenarioResult{client.RunVPChallengeFlowOn(target)}, nil
	case "data-flow-mediation":
		return []runner.ScenarioResult{client.RunDataFlowMediationOn(target)}, nil
	case "all":
		results := []runner.ScenarioResult{
			client.RunOwnerControlOn(target),
			client.RunDelegationOn(target),
			client.RunRevocationOn(target),
			client.RunOwnershipTransferOn(target),
			client.RunVPChallengeFlowOn(target),
		}

		if target.SupportsDataFlow {
			results = append(results, client.RunDataFlowMediationOn(target))
		}
		return results, nil
	default:
		return nil, fmt.Errorf("unknown flow %q", flow)
	}
}

func waitForHealthy(client *runner.Client, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		allOK := true
		for _, health := range client.CheckHealth() {
			if !health.OK {
				allOK = false
				break
			}
		}
		if allOK {
			return true
		}
		time.Sleep(time.Second)
	}
	return false
}

func printHealth(health []runner.ServiceHealth) {
	for _, h := range health {
		if h.OK {
			fmt.Printf("[OK] %s status=%d\n", h.Name, h.StatusCode)
			continue
		}
		if h.Error != "" {
			fmt.Printf("[FAIL] %s error=%s\n", h.Name, h.Error)
			continue
		}
		fmt.Printf("[FAIL] %s status=%d\n", h.Name, h.StatusCode)
	}
}

func printResult(result runner.ScenarioResult) {
	status := "PASS"
	if !result.Passed {
		status = "FAIL"
	}
	fmt.Printf("[%s] %s (%s)\n", status, result.Name, result.Duration)
	if result.Error != "" {
		fmt.Printf("  error: %s\n", result.Error)
	}
}
