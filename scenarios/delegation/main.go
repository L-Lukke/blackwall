package main

import (
	"fmt"

	"github.com/L-Lukke/blackwall/scenarios/internal/runner"
)

func main() {
	cfg := runner.LoadConfig()
	alice := "did:example:alice"
	bob := "did:example:bob"

	fmt.Println("[1/4] issuing owner credential for Alice")
	owner := runner.IssueOwnerCredential(cfg, alice, "unlock", "lock")
	fmt.Printf("  owner credential id: %s\n", owner.ID)

	fmt.Println("[2/4] issuing delegation credential for Bob")
	delegation := runner.IssueDelegationCredential(cfg, alice, bob, owner, 120, "unlock")
	fmt.Printf("  delegation credential id: %s\n", delegation.ID)

	fmt.Println("[3/4] Bob unlocks front door")
	allow := runner.Access(cfg, bob, "unlock", delegation, 200)
	runner.ExpectAllowed(allow, "allowed_by_delegation_credential")
	fmt.Printf("  result: allowed=%v reason=%s\n", allow.Allowed, allow.Reason)

	fmt.Println("[4/4] Bob tries to lock front door")
	deny := runner.Access(cfg, bob, "lock", delegation, 403)
	runner.ExpectDenied(deny, "action_out_of_scope")
	fmt.Printf("  result: allowed=%v reason=%s\n", deny.Allowed, deny.Reason)

	fmt.Println("delegation scenario completed successfully")
}