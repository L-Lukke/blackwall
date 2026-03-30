package main

import (
	"fmt"

	"github.com/L-Lukke/blackwall/scenarios/internal/runner"
)

func main() {
	cfg := runner.LoadConfig()
	alice := "did:example:alice"
	carol := "did:example:carol"

	fmt.Println("[1/5] issuing owner credential for Alice")
	owner := runner.IssueOwnerCredential(cfg, alice, "unlock", "lock")
	fmt.Printf("  owner credential id: %s\n", owner.ID)

	fmt.Println("[2/5] Alice unlocks before transfer")
	before := runner.Access(cfg, alice, "unlock", owner, 200)
	runner.ExpectAllowed(before, "allowed_by_owner_credential")
	fmt.Printf("  result: allowed=%v reason=%s\n", before.Allowed, before.Reason)

	fmt.Println("[3/5] transferring ownership from Alice to Carol")
	transfer := runner.TransferOwnership(cfg, alice, carol, owner)
	fmt.Printf("  revoked credential id: %s\n", transfer.RevokedCredentialID)
	fmt.Printf("  new owner credential id: %s\n", transfer.NewOwnerCredential.ID)

	fmt.Println("[4/5] Alice unlocks after transfer")
	oldOwner := runner.Access(cfg, alice, "unlock", owner, 403)
	runner.ExpectDenied(oldOwner, "credential_revoked")
	fmt.Printf("  result: allowed=%v reason=%s\n", oldOwner.Allowed, oldOwner.Reason)

	fmt.Println("[5/5] Carol unlocks after transfer")
	newOwner := runner.Access(cfg, carol, "unlock", transfer.NewOwnerCredential, 200)
	runner.ExpectAllowed(newOwner, "allowed_by_transferred_owner_credential")
	fmt.Printf("  result: allowed=%v reason=%s\n", newOwner.Allowed, newOwner.Reason)

	fmt.Println("ownership-transfer scenario completed successfully")
}