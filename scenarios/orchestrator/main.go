package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/L-Lukke/blackwall/scenarios/internal/procmanager"
	"github.com/L-Lukke/blackwall/scenarios/internal/runner"
)

func main() {
	cfg := runner.LoadConfig()
	client := runner.New(cfg)
	repoRoot := procmanager.FindRepoRoot()
	manager := procmanager.New(repoRoot)

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	var stopOnce sync.Once
	stopAll := func() {
		stopOnce.Do(func() {
			fmt.Println()
			fmt.Println("stopping managed services...")
			if err := manager.StopAll(); err != nil {
				fmt.Printf("stop error: %v\n", err)
			}
		})
	}
	defer stopAll()

	go func() {
		<-ctx.Done()
		fmt.Println("\nreceived interrupt, shutting down...")
		stopAll()
		os.Exit(0)
	}()

	reader := bufio.NewReader(os.Stdin)

	printHeader(repoRoot, cfg)

	if !startServicesAutomatically(manager, client) {
		return
	}

	for {
		printInitialMenu()
		choice := readChoice(reader)

		switch choice {
		case "1":
			printManagedStatus(manager)
			fmt.Println()
			printHealth(client.CheckHealth())

		case "2":
			if quit := useDevicesMenu(reader, client); quit {
				fmt.Println("bye")
				return
			}

		case "3":
			if quit := testFlowsMenu(reader, client); quit {
				fmt.Println("bye")
				return
			}

		case "4", "q", "quit", "exit":
			fmt.Println("bye")
			return

		default:
			fmt.Println("invalid option")
		}

		fmt.Println()
	}
}

func printHeader(repoRoot string, cfg runner.Config) {
	fmt.Println("Blackwall orchestrator")
	fmt.Println("----------------------")
	fmt.Printf("Repo Root     : %s\n", repoRoot)
	fmt.Printf("Issuer URL    : %s\n", cfg.IssuerURL)
	fmt.Printf("Gateway URL   : %s\n", cfg.GatewayURL)
	fmt.Printf("Gateway ID    : %s\n", cfg.GatewayID)
	fmt.Printf("Sensor Device : %s\n", cfg.SensorDeviceID)
	fmt.Printf("Lock Device   : %s\n", cfg.DeviceID)
	fmt.Printf("Light Device  : %s\n", cfg.LightDeviceID)
	fmt.Println()
}

func startServicesAutomatically(manager *procmanager.Manager, client *runner.Client) bool {
	fmt.Println("starting managed services...")

	if err := manager.StartAll(); err != nil {
		fmt.Printf("start error: %v\n", err)
		return false
	}

	printManagedStatus(manager)
	fmt.Println()

	fmt.Println("waiting for service health...")
	if ok := waitForHealthy(client, 40*time.Second); !ok {
		fmt.Println("services did not become healthy in time")
		printHealth(client.CheckHealth())
		fmt.Println("check logs under scenarios/.logs/")
		return false
	}

	fmt.Println("services are healthy")
	printHealth(client.CheckHealth())
	fmt.Println()

	return true
}

func printInitialMenu() {
	fmt.Println("1) Show status / health")
	fmt.Println("2) Use devices")
	fmt.Println("3) Test flows")
	fmt.Println("4) Quit")
}

func useDevicesMenu(reader *bufio.Reader, client *runner.Client) bool {
	for {
		fmt.Println()
		fmt.Println("Use devices")
		fmt.Println("-----------")
		fmt.Println("1) Sensor")
		fmt.Println("2) Lock")
		fmt.Println("3) Light")
		fmt.Println("4) Previous menu")
		fmt.Println("5) Quit")

		choice := readChoice(reader)

		switch choice {
		case "1", "2", "3":
			target, ok := deviceTargetFromChoice(client, choice)
			if !ok {
				fmt.Println("invalid device")
				continue
			}

			if quit := useDeviceActionMenu(reader, client, target); quit {
				return true
			}

		case "4":
			return false

		case "5", "q", "quit", "exit":
			return true

		default:
			fmt.Println("invalid option")
		}
	}
}

func useDeviceActionMenu(reader *bufio.Reader, client *runner.Client, target runner.DeviceTarget) bool {
	for {
		fmt.Println()
		fmt.Printf("%s actions\n", target.Name)
		fmt.Println(strings.Repeat("-", len(target.Name)+8))

		for i, action := range target.Actions {
			fmt.Printf("%d) %s\n", i+1, action)
		}

		previousOption := len(target.Actions) + 1
		quitOption := len(target.Actions) + 2

		fmt.Printf("%d) Previous menu\n", previousOption)
		fmt.Printf("%d) Quit\n", quitOption)

		choice := readChoice(reader)

		n, err := strconv.Atoi(choice)
		if err != nil {
			fmt.Println("invalid option")
			continue
		}

		switch {
		case n >= 1 && n <= len(target.Actions):
			action := target.Actions[n-1]
			printResult(client.UseDeviceAction(target, action))

		case n == previousOption:
			return false

		case n == quitOption:
			return true

		default:
			fmt.Println("invalid option")
		}
	}
}

func testFlowsMenu(reader *bufio.Reader, client *runner.Client) bool {
	for {
		fmt.Println()
		fmt.Println("Test flows")
		fmt.Println("----------")
		fmt.Println("1) Run owner-control")
		fmt.Println("2) Run delegation")
		fmt.Println("3) Run revocation")
		fmt.Println("4) Run ownership-transfer")
		fmt.Println("5) Run data-flow-mediation")
		fmt.Println("6) Run all tests")
		fmt.Println("7) Previous menu")
		fmt.Println("8) Quit")

		flowChoice := readChoice(reader)

		switch flowChoice {
		case "1", "2", "3", "4", "5", "6":
			target, canceled, quit := selectDeviceForTest(reader, client)
			if quit {
				return true
			}
			if canceled {
				continue
			}

			runSelectedFlow(client, flowChoice, target)

		case "7":
			return false

		case "8", "q", "quit", "exit":
			return true

		default:
			fmt.Println("invalid option")
		}
	}
}

func selectDeviceForTest(reader *bufio.Reader, client *runner.Client) (runner.DeviceTarget, bool, bool) {
	for {
		fmt.Println()
		fmt.Println("Choose device to test")
		fmt.Println("---------------------")
		fmt.Println("1) Sensor")
		fmt.Println("2) Lock")
		fmt.Println("3) Light")
		fmt.Println("4) Cancel test")
		fmt.Println("5) Quit")

		choice := readChoice(reader)

		switch choice {
		case "1", "2", "3":
			target, ok := deviceTargetFromChoice(client, choice)
			if !ok {
				fmt.Println("invalid device")
				continue
			}
			return target, false, false

		case "4":
			return runner.DeviceTarget{}, true, false

		case "5", "q", "quit", "exit":
			return runner.DeviceTarget{}, false, true

		default:
			fmt.Println("invalid option")
		}
	}
}

func runSelectedFlow(client *runner.Client, flowChoice string, target runner.DeviceTarget) {
	fmt.Println()

	switch flowChoice {
	case "1":
		printResult(client.RunOwnerControlOn(target))

	case "2":
		printResult(client.RunDelegationOn(target))

	case "3":
		printResult(client.RunRevocationOn(target))

	case "4":
		printResult(client.RunOwnershipTransferOn(target))

	case "5":
		printResult(client.RunDataFlowMediationOn(target))

	case "6":
		runAll(client, target)
	}
}

func runAll(client *runner.Client, target runner.DeviceTarget) {
	printHealth(client.CheckHealth())
	fmt.Println()

	printResult(client.RunOwnerControlOn(target))
	fmt.Println()

	printResult(client.RunDelegationOn(target))
	fmt.Println()

	printResult(client.RunRevocationOn(target))
	fmt.Println()

	printResult(client.RunOwnershipTransferOn(target))

	if target.SupportsDataFlow {
		fmt.Println()
		printResult(client.RunDataFlowMediationOn(target))
	} else {
		fmt.Println()
		fmt.Println("Scenario: data-flow-mediation")
		fmt.Println("Passed : skipped")
		fmt.Printf("Reason : data-flow-mediation is only supported for mediated data devices; selected device=%s\n", target.Name)
	}
}

func deviceTargetFromChoice(client *runner.Client, choice string) (runner.DeviceTarget, bool) {
	switch choice {
	case "1":
		return client.SensorTarget(), true
	case "2":
		return client.LockTarget(), true
	case "3":
		return client.LightTarget(), true
	default:
		return runner.DeviceTarget{}, false
	}
}

func readChoice(reader *bufio.Reader) string {
	fmt.Print("Choose an option: ")

	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("input error: %v\n", err)
		return ""
	}

	return strings.TrimSpace(strings.ToLower(input))
}

func printManagedStatus(manager *procmanager.Manager) {
	fmt.Println("Managed services")
	fmt.Println("----------------")
	for _, line := range manager.StatusLines() {
		fmt.Println(line)
	}
}

func waitForHealthy(client *runner.Client, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		health := client.CheckHealth()
		allOK := true

		for _, h := range health {
			if !h.OK {
				allOK = false
				break
			}
		}

		if allOK {
			return true
		}

		time.Sleep(1 * time.Second)
	}

	return false
}

func printHealth(health []runner.ServiceHealth) {
	fmt.Println("Service health")
	fmt.Println("--------------")

	for _, h := range health {
		if h.OK {
			fmt.Printf("[OK] %s (%s) status=%d\n", h.Name, h.URL, h.StatusCode)
		} else if h.Error != "" {
			fmt.Printf("[FAIL] %s (%s) error=%s\n", h.Name, h.URL, h.Error)
		} else {
			fmt.Printf("[FAIL] %s (%s) status=%d\n", h.Name, h.URL, h.StatusCode)
		}
	}
}

func printResult(r runner.ScenarioResult) {
	fmt.Printf("Scenario: %s\n", r.Name)
	fmt.Printf("Passed : %v\n", r.Passed)
	fmt.Printf("Duration: %s\n", r.Duration)

	if len(r.Steps) > 0 {
		fmt.Println("Steps:")
		for _, step := range r.Steps {
			fmt.Printf(" - %s\n", step)
		}
	}

	if r.Error != "" {
		fmt.Printf("Error : %s\n", r.Error)
	}
}
