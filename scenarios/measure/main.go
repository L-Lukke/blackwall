package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/L-Lukke/blackwall/scenarios/internal/procmanager"
	"github.com/L-Lukke/blackwall/scenarios/internal/runner"
)

func main() {
	deviceFlag := flag.String("device", "sensor", "device to measure: sensor, lock, light")
	flowFlag := flag.String("flow", "owner-control", "flow to measure: owner-control, delegation, revocation, ownership-transfer, vp-challenge, data-flow-mediation")
	iterations := flag.Int("n", 10, "number of iterations")
	timeout := flag.Duration("timeout", 40*time.Second, "service health timeout")
	flag.Parse()

	if *iterations <= 0 {
		fmt.Fprintln(os.Stderr, "-n must be greater than zero")
		os.Exit(2)
	}

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

	if !waitForHealthy(client, *timeout) {
		fmt.Fprintln(os.Stderr, "services did not become healthy in time")
		os.Exit(1)
	}

	target, err := selectedTarget(client, *deviceFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	var durations []time.Duration
	failures := 0
	for i := 0; i < *iterations; i++ {
		result, err := runFlow(client, target, *flowFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if !result.Passed {
			failures++
			fmt.Printf("[%02d] FAIL %s %s error=%s\n", i+1, result.Name, result.Duration, result.Error)
			continue
		}
		durations = append(durations, result.Duration)
		fmt.Printf("[%02d] PASS %s %s\n", i+1, result.Name, result.Duration)
	}

	printSummary(*deviceFlag, *flowFlag, *iterations, failures, durations)
	if failures > 0 {
		os.Exit(1)
	}
}

func selectedTarget(client *runner.Client, device string) (runner.DeviceTarget, error) {
	switch strings.ToLower(strings.TrimSpace(device)) {
	case "sensor":
		return client.SensorTarget(), nil
	case "lock":
		return client.LockTarget(), nil
	case "light":
		return client.LightTarget(), nil
	default:
		return runner.DeviceTarget{}, fmt.Errorf("unknown device %q", device)
	}
}

func runFlow(client *runner.Client, target runner.DeviceTarget, flow string) (runner.ScenarioResult, error) {
	switch strings.ToLower(strings.TrimSpace(flow)) {
	case "owner-control":
		return client.RunOwnerControlOn(target), nil
	case "delegation":
		return client.RunDelegationOn(target), nil
	case "revocation":
		return client.RunRevocationOn(target), nil
	case "ownership-transfer":
		return client.RunOwnershipTransferOn(target), nil
	case "vp-challenge":
		return client.RunVPChallengeFlowOn(target), nil
	case "data-flow-mediation":
		return client.RunDataFlowMediationOn(target), nil
	default:
		return runner.ScenarioResult{}, fmt.Errorf("unknown flow %q", flow)
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

func printSummary(device, flow string, total, failures int, durations []time.Duration) {
	if len(durations) == 0 {
		fmt.Printf("summary device=%s flow=%s total=%d failures=%d\n", device, flow, total, failures)
		return
	}

	min := durations[0]
	max := durations[0]
	var sum time.Duration
	for _, duration := range durations {
		if duration < min {
			min = duration
		}
		if duration > max {
			max = duration
		}
		sum += duration
	}
	avg := sum / time.Duration(len(durations))

	fmt.Printf(
		"summary device=%s flow=%s total=%d passed=%d failures=%d min=%s avg=%s max=%s\n",
		device,
		flow,
		total,
		len(durations),
		failures,
		min,
		avg,
		max,
	)
}
