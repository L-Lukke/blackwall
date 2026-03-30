package main

import (
	"fmt"

	"github.com/L-Lukke/blackwall/scenarios/internal/runner"
)

func main() {
	cfg := runner.LoadConfig()
	alice := "did:example:alice"

	fmt.Println("[1/2] issuing owner credential for Alice")
	owner := runner.IssueOwnerCredential(cfg, alice, "unlock", "lock")
	fmt.Printf("  owner credential id: %s\n", owner.ID)

	fmt.Println("[2/2] Alice unlocks front door")
	resp := runner.Access(cfg, alice, "unlock", owner, 200)
	runner.ExpectAllowed(resp, "allowed_by_owner_credential")
	fmt.Printf("  result: allowed=%v reason=%s\n", resp.Allowed, resp.Reason)

	fmt.Println("owner-control scenario completed successfully")
}