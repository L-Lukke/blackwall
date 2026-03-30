package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/L-Lukke/blackwall/scenarios/internal/procmanager"
	"github.com/L-Lukke/blackwall/scenarios/internal/runner"
)

func main() {
	cfg := runner.LoadConfig()
	client := runner.New(cfg)
	manager := procmanager.New(".")

	reader := bufio.NewReader(os.Stdin)

	defer func() {
		fmt.Println()
		fmt.Println("stopping managed services...")
		if err := manager.StopAll(); err != nil {
			fmt.Printf("stop error: %v\n", err)
		}
	}()

	fmt.Println("Blackwall orchestrator")
	fmt.Println("----------------------")
	fmt.Printf("Issuer URL : %s\n", cfg.IssuerURL)
	fmt.Printf("Gateway URL: %s\n", cfg.GatewayURL)
	fmt.Printf("Gateway ID : %s\n", cfg.GatewayID)
	fmt.Printf("Device ID  : %s\n", cfg.DeviceID)
	fmt.Println()

	for {
		printMenu()
		fmt.Print("Choose an option: ")

		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("input error: %v\n", err)
			continue
		}

		switch strings.TrimSpace(input) {
		case "1":
			startServices(manager, client)
		case "2":
			stopServices(manager)
		case "3":
			printManagedStatus(manager)
			fmt.Println()
			printHealth(client.CheckHealth())
		case "4":
			printResult(client.RunOwnerControl())
		case "5":
			printResult(client.RunDelegation())
		case "6":
			printResult(client.RunRevocation())
		case "7":
			printResult(client.RunOwnershipTransfer())
		case "8":
			printHealth(client.CheckHealth())
			fmt.Println()
			printResult(client.RunOwnerControl())
			fmt.Println()
			printResult(client.RunDelegation())
			fmt.Println()
			printResult(client.RunRevocation())
			fmt.Println()
			printResult(client.RunOwnershipTransfer())
		case "0", "q", "quit", "exit":
			fmt.Println("bye")
			return
		default:
			fmt.Println("invalid option")
		}

		fmt.Println()
	}
}

func printMenu() {
	fmt.Println("1) Start all services")
	fmt.Println("2) Stop all services")
	fmt.Println("3) Show status / health")
	fmt.Println("4) Run owner-control")
	fmt.Println("5) Run delegation")
	fmt.Println("6) Run revocation")
	fmt.Println("7) Run ownership-transfer")
	fmt.Println("8) Run all tests")
	fmt.Println("0) Exit")
}

func startServices(manager *procmanager.Manager, client *runner.Client) {
	fmt.Println("starting services...")
	if err := manager.StartAll(); err != nil {
		fmt.Printf("start error: %v\n", err)
		return
	}

	printManagedStatus(manager)

	fmt.Println()
	fmt.Println("waiting for issuer and gateway health...")
	if ok := waitForHealthy(client, 40*time.Second); !ok {
		fmt.Println("services did not become healthy in time")
		printHealth(client.CheckHealth())
		fmt.Println("check logs under scenarios/.logs/")
		return
	}

	fmt.Println("services are healthy")
	printHealth(client.CheckHealth())
}

func stopServices(manager *procmanager.Manager) {
	fmt.Println("stopping services...")
	if err := manager.StopAll(); err != nil {
		fmt.Printf("stop error: %v\n", err)
		return
	}
	printManagedStatus(manager)
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
			fmt.Printf("[OK]   %s (%s) status=%d\n", h.Name, h.URL, h.StatusCode)
		} else if h.Error != "" {
			fmt.Printf("[FAIL] %s (%s) error=%s\n", h.Name, h.URL, h.Error)
		} else {
			fmt.Printf("[FAIL] %s (%s) status=%d\n", h.Name, h.URL, h.StatusCode)
		}
	}
}

func printResult(r runner.ScenarioResult) {
	fmt.Printf("Scenario: %s\n", r.Name)
	fmt.Printf("Passed  : %v\n", r.Passed)
	fmt.Printf("Duration: %s\n", r.Duration)

	if len(r.Steps) > 0 {
		fmt.Println("Steps:")
		for _, step := range r.Steps {
			fmt.Printf("  - %s\n", step)
		}
	}

	if r.Error != "" {
		fmt.Printf("Error   : %s\n", r.Error)
	}
}