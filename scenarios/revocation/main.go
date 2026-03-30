package main

import (
	"fmt"

	"github.com/L-Lukke/blackwall/scenarios/internal/runner"
)

func main() {
	cfg := runner.LoadConfig()
	alice := "did:example:alice"
	bob := "did:example:bob"

	fmt.Println("[1/5] issuing owner credential for Alice")
	owner := runner.IssueOwnerCredential(cfg, alice, "unlock", "lock")
	fmt.Printf("  owner credential id: %s\n", owner.ID)

	fmt.Println("[2/5] issuing delegation credential for Bob")
	delegation := runner.IssueDelegationCredential(cfg, alice, bob, owner, 120, "unlock")
	fmt.Printf("  delegation credential id: %s\n", delegation.ID)

	fmt.Println("[3/5] Bob unlocks before revocation")
	before := runner.Access(cfg, bob, "unlock", delegation, 200)
	runner.ExpectAllowed(before, "allowed_by_delegation_credential")
	fmt.Printf("  result: allowed=%v reason=%s\n", before.Allowed, before.Reason)

	fmt.Println("[4/5] revoking Bob's delegation credential")
	runner.RevokeCredential(cfg, delegation.ID, "manual_test_revocation")
	fmt.Printf("  revoked credential id: %s\n", delegation.ID)

	fmt.Println("[5/5] Bob unlocks after revocation")
	after := runner.Access(cfg, bob, "unlock", delegation, 403)
	runner.ExpectDenied(after, "credential_revoked")
	fmt.Printf("  result: allowed=%v reason=%s\n", after.Allowed, after.Reason)

	fmt.Println("revocation scenario completed successfully")
}