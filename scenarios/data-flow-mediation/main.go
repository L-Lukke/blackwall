package main

import (
	"encoding/json"
	"fmt"

	"github.com/L-Lukke/blackwall/scenarios/internal/runner"
)

func main() {
	cfg := runner.LoadConfig()
	alice := "did:example:alice"

	fmt.Println("[1/3] issuing owner credential for Alice for the mediated sensor")
	owner := runner.IssueOwnerCredentialForDevice(cfg, cfg.SensorDeviceID, alice, "read_sensor")
	fmt.Printf(" owner credential id: %s\n", owner.ID)

	fmt.Println("[2/3] Alice reads the sensor through the gateway")
	resp := runner.AccessDevice(cfg, cfg.SensorDeviceID, alice, "read_sensor", owner, 200)
	runner.ExpectAllowed(resp, "allowed_by_owner_credential")
	runner.ExpectPersisted(resp)

	fmt.Printf(" result: allowed=%v reason=%s\n", resp.Allowed, resp.Reason)
	fmt.Printf(" persisted to: %s\n", resp.PersistedTo)

	if len(resp.DeviceResult) > 0 {
		var reading map[string]any
		if err := json.Unmarshal(resp.DeviceResult, &reading); err == nil {
			fmt.Printf(" reading: %v\n", reading)
		}
	}

	fmt.Println("[3/3] data-flow mediation scenario completed successfully")
}