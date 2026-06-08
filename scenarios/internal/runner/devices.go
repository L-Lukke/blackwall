package runner

import (
	"fmt"
	"net/http"
	"time"
)

type DeviceKind string

const (
	DeviceKindSensor DeviceKind = "sensor"
	DeviceKindLock   DeviceKind = "lock"
	DeviceKindLight  DeviceKind = "light"
)

type DeviceTarget struct {
	Name             string
	Kind             DeviceKind
	DeviceID         string
	Actions          []string
	PrimaryAction    string
	DeniedAction     string
	SupportsDataFlow bool
}

func (c *Client) SensorTarget() DeviceTarget {
	return DeviceTarget{
		Name:             "Sensor",
		Kind:             DeviceKindSensor,
		DeviceID:         c.cfg.SensorDeviceID,
		Actions:          []string{"read_sensor"},
		PrimaryAction:    "read_sensor",
		DeniedAction:     "unlock",
		SupportsDataFlow: true,
	}
}

func (c *Client) LockTarget() DeviceTarget {
	return DeviceTarget{
		Name:             "Lock",
		Kind:             DeviceKindLock,
		DeviceID:         c.cfg.DeviceID,
		Actions:          []string{"lock", "unlock"},
		PrimaryAction:    "unlock",
		DeniedAction:     "lock",
		SupportsDataFlow: false,
	}
}

func (c *Client) LightTarget() DeviceTarget {
	return DeviceTarget{
		Name:             "Light",
		Kind:             DeviceKindLight,
		DeviceID:         c.cfg.LightDeviceID,
		Actions:          []string{"turn_on", "turn_off"},
		PrimaryAction:    "turn_on",
		DeniedAction:     "turn_off",
		SupportsDataFlow: false,
	}
}

func (c *Client) UseDeviceAction(target DeviceTarget, action string) ScenarioResult {
	start := time.Now()
	result := ScenarioResult{Name: "use-" + string(target.Kind) + "-" + action}

	alice := uniqueDID("alice")

	owner, err := c.issueOwnerCredentialForDevice(alice, target.DeviceID, target.Actions)
	if err != nil {
		return fail(result, start, "issue owner credential failed", err)
	}

	result.Steps = append(result.Steps, fmt.Sprintf(
		"issued owner credential for %s id=%s device=%s",
		alice,
		owner.ID,
		target.DeviceID,
	))

	resp, err := c.accessDevice(alice, target.DeviceID, action, owner, http.StatusOK)
	if err != nil {
		return fail(result, start, "device access failed", err)
	}

	if !resp.Allowed || resp.Reason != "allowed_by_owner_credential" {
		return fail(
			result,
			start,
			"unexpected device access outcome",
			fmt.Errorf("allowed=%v reason=%s", resp.Allowed, resp.Reason),
		)
	}

	result.Steps = append(result.Steps, fmt.Sprintf(
		"%s action %s allowed with reason=%s",
		target.Name,
		action,
		resp.Reason,
	))

	if resp.PersistedTo != "" {
		result.Steps = append(result.Steps, "data persisted to "+resp.PersistedTo)
	}

	result.Passed = true
	result.Duration = time.Since(start)
	return result
}

func (c *Client) RunOwnerControlOn(target DeviceTarget) ScenarioResult {
	start := time.Now()
	result := ScenarioResult{Name: "owner-control/" + string(target.Kind)}

	alice := uniqueDID("alice")

	owner, err := c.issueOwnerCredentialForDevice(alice, target.DeviceID, target.Actions)
	if err != nil {
		return fail(result, start, "issue owner credential failed", err)
	}

	result.Steps = append(result.Steps, fmt.Sprintf(
		"issued owner credential for %s id=%s device=%s",
		alice,
		owner.ID,
		target.DeviceID,
	))

	allowResp, err := c.accessDevice(alice, target.DeviceID, target.PrimaryAction, owner, http.StatusOK)
	if err != nil {
		return fail(result, start, "owner access request failed", err)
	}

	if !allowResp.Allowed || allowResp.Reason != "allowed_by_owner_credential" {
		return fail(
			result,
			start,
			"unexpected owner-control outcome",
			fmt.Errorf("allowed=%v reason=%s", allowResp.Allowed, allowResp.Reason),
		)
	}

	result.Steps = append(result.Steps, fmt.Sprintf(
		"owner %s allowed with reason=%s",
		target.PrimaryAction,
		allowResp.Reason,
	))

	result.Passed = true
	result.Duration = time.Since(start)
	return result
}

func (c *Client) RunVPChallengeFlowOn(target DeviceTarget) ScenarioResult {
	start := time.Now()
	result := ScenarioResult{Name: "vp-challenge/" + string(target.Kind)}

	holderDID, err := c.walletDID()
	if err != nil {
		return fail(result, start, "resolve wallet did failed", err)
	}
	result.Steps = append(result.Steps, "wallet holder did="+holderDID)

	owner, err := c.issueOwnerCredentialForDevice(holderDID, target.DeviceID, []string{target.PrimaryAction})
	if err != nil {
		return fail(result, start, "issue owner credential failed", err)
	}
	result.Steps = append(result.Steps, fmt.Sprintf(
		"issued owner credential id=%s device=%s action=%s",
		owner.ID,
		target.DeviceID,
		target.PrimaryAction,
	))

	if err := c.storeCredentialInWallet(owner); err != nil {
		return fail(result, start, "store credential in wallet failed", err)
	}
	result.Steps = append(result.Steps, "stored credential in holder wallet")

	challenge, err := c.requestChallenge(holderDID, target.DeviceID, target.PrimaryAction)
	if err != nil {
		return fail(result, start, "request gateway challenge failed", err)
	}
	result.Steps = append(result.Steps, "gateway challenge issued for domain="+challenge.Domain)

	presentation, err := c.createPresentation(owner.ID, challenge.Challenge, challenge.Domain)
	if err != nil {
		return fail(result, start, "create presentation failed", err)
	}
	result.Steps = append(result.Steps, "wallet signed verifiable presentation id="+presentation.ID)

	allowResp, err := c.accessDeviceWithPresentation(
		holderDID,
		target.DeviceID,
		target.PrimaryAction,
		challenge.Challenge,
		presentation,
		http.StatusOK,
	)
	if err != nil {
		return fail(result, start, "vp access request failed", err)
	}
	if !allowResp.Allowed || allowResp.Reason != "allowed_by_owner_credential" {
		return fail(result, start, "unexpected vp-challenge outcome", fmt.Errorf("allowed=%v reason=%s", allowResp.Allowed, allowResp.Reason))
	}
	result.Steps = append(result.Steps, fmt.Sprintf(
		"vp %s allowed with reason=%s",
		target.PrimaryAction,
		allowResp.Reason,
	))
	if allowResp.PersistedTo != "" {
		result.Steps = append(result.Steps, "data persisted to "+allowResp.PersistedTo)
	}

	result.Passed = true
	result.Duration = time.Since(start)
	return result
}

func (c *Client) RunDelegationOn(target DeviceTarget) ScenarioResult {
	start := time.Now()
	result := ScenarioResult{Name: "delegation/" + string(target.Kind)}

	alice := uniqueDID("alice")
	bob := uniqueDID("bob")

	owner, err := c.issueOwnerCredentialForDevice(alice, target.DeviceID, target.Actions)
	if err != nil {
		return fail(result, start, "issue owner credential failed", err)
	}

	result.Steps = append(result.Steps, fmt.Sprintf(
		"issued owner credential for %s id=%s device=%s",
		alice,
		owner.ID,
		target.DeviceID,
	))

	delegation, err := c.issueDelegationCredentialForDevice(
		alice,
		bob,
		owner,
		target.DeviceID,
		[]string{target.PrimaryAction},
		120,
	)
	if err != nil {
		return fail(result, start, "issue delegation credential failed", err)
	}

	result.Steps = append(result.Steps, fmt.Sprintf(
		"issued delegation credential for %s id=%s action_scope=%s",
		bob,
		delegation.ID,
		target.PrimaryAction,
	))

	allowResp, err := c.accessDevice(bob, target.DeviceID, target.PrimaryAction, delegation, http.StatusOK)
	if err != nil {
		return fail(result, start, "delegated allowed action failed", err)
	}

	if !allowResp.Allowed || allowResp.Reason != "allowed_by_delegation_credential" {
		return fail(
			result,
			start,
			"unexpected delegation allow outcome",
			fmt.Errorf("allowed=%v reason=%s", allowResp.Allowed, allowResp.Reason),
		)
	}

	result.Steps = append(result.Steps, fmt.Sprintf(
		"delegated %s allowed with reason=%s",
		target.PrimaryAction,
		allowResp.Reason,
	))

	denyResp, err := c.accessDevice(bob, target.DeviceID, target.DeniedAction, delegation, http.StatusForbidden)
	if err != nil {
		return fail(result, start, "delegated denied action failed", err)
	}

	if denyResp.Allowed || denyResp.Reason != "action_out_of_scope" {
		return fail(
			result,
			start,
			"unexpected delegation deny outcome",
			fmt.Errorf("allowed=%v reason=%s", denyResp.Allowed, denyResp.Reason),
		)
	}

	result.Steps = append(result.Steps, fmt.Sprintf(
		"delegated %s denied with reason=%s",
		target.DeniedAction,
		denyResp.Reason,
	))

	result.Passed = true
	result.Duration = time.Since(start)
	return result
}

func (c *Client) RunRevocationOn(target DeviceTarget) ScenarioResult {
	start := time.Now()
	result := ScenarioResult{Name: "revocation/" + string(target.Kind)}

	alice := uniqueDID("alice")
	bob := uniqueDID("bob")

	owner, err := c.issueOwnerCredentialForDevice(alice, target.DeviceID, target.Actions)
	if err != nil {
		return fail(result, start, "issue owner credential failed", err)
	}

	result.Steps = append(result.Steps, fmt.Sprintf(
		"issued owner credential for %s id=%s device=%s",
		alice,
		owner.ID,
		target.DeviceID,
	))

	delegation, err := c.issueDelegationCredentialForDevice(
		alice,
		bob,
		owner,
		target.DeviceID,
		[]string{target.PrimaryAction},
		120,
	)
	if err != nil {
		return fail(result, start, "issue delegation credential failed", err)
	}

	result.Steps = append(result.Steps, fmt.Sprintf(
		"issued delegation credential for %s id=%s",
		bob,
		delegation.ID,
	))

	beforeResp, err := c.accessDevice(bob, target.DeviceID, target.PrimaryAction, delegation, http.StatusOK)
	if err != nil {
		return fail(result, start, "delegated access before revocation failed", err)
	}

	if !beforeResp.Allowed || beforeResp.Reason != "allowed_by_delegation_credential" {
		return fail(
			result,
			start,
			"unexpected pre-revocation outcome",
			fmt.Errorf("allowed=%v reason=%s", beforeResp.Allowed, beforeResp.Reason),
		)
	}

	result.Steps = append(result.Steps, fmt.Sprintf(
		"pre-revocation %s allowed with reason=%s",
		target.PrimaryAction,
		beforeResp.Reason,
	))

	if err := c.revokeCredentialViaIssuer(delegation.ID, alice, owner); err != nil {
		return fail(result, start, "revoke delegation credential failed", err)
	}

	result.Steps = append(result.Steps, "revoked delegation credential id="+delegation.ID)

	afterResp, err := c.accessDevice(bob, target.DeviceID, target.PrimaryAction, delegation, http.StatusForbidden)
	if err != nil {
		return fail(result, start, "delegated access after revocation failed", err)
	}

	if afterResp.Allowed || afterResp.Reason != "credential_revoked" {
		return fail(
			result,
			start,
			"unexpected post-revocation outcome",
			fmt.Errorf("allowed=%v reason=%s", afterResp.Allowed, afterResp.Reason),
		)
	}

	result.Steps = append(result.Steps, fmt.Sprintf(
		"post-revocation %s denied with reason=%s",
		target.PrimaryAction,
		afterResp.Reason,
	))

	result.Passed = true
	result.Duration = time.Since(start)
	return result
}

func (c *Client) RunOwnershipTransferOn(target DeviceTarget) ScenarioResult {
	start := time.Now()
	result := ScenarioResult{Name: "ownership-transfer/" + string(target.Kind)}

	alice := uniqueDID("alice")
	carol := uniqueDID("carol")

	owner, err := c.issueOwnerCredentialForDevice(alice, target.DeviceID, target.Actions)
	if err != nil {
		return fail(result, start, "issue owner credential failed", err)
	}

	result.Steps = append(result.Steps, fmt.Sprintf(
		"issued owner credential for %s id=%s device=%s",
		alice,
		owner.ID,
		target.DeviceID,
	))

	beforeResp, err := c.accessDevice(alice, target.DeviceID, target.PrimaryAction, owner, http.StatusOK)
	if err != nil {
		return fail(result, start, "owner access before transfer failed", err)
	}

	if !beforeResp.Allowed || beforeResp.Reason != "allowed_by_owner_credential" {
		return fail(
			result,
			start,
			"unexpected pre-transfer owner outcome",
			fmt.Errorf("allowed=%v reason=%s", beforeResp.Allowed, beforeResp.Reason),
		)
	}

	result.Steps = append(result.Steps, fmt.Sprintf(
		"pre-transfer %s allowed with reason=%s",
		target.PrimaryAction,
		beforeResp.Reason,
	))

	transferResp, err := c.transferOwnershipForDevice(
		alice,
		carol,
		owner,
		[]string{target.DeviceID},
		target.Actions,
	)
	if err != nil {
		return fail(result, start, "ownership transfer failed", err)
	}

	result.Steps = append(result.Steps, "transferred ownership from "+alice+" to "+carol)
	result.Steps = append(result.Steps, "revoked previous owner credential id="+transferResp.RevokedCredentialID)
	result.Steps = append(result.Steps, "issued new owner credential id="+transferResp.NewOwnerCredential.ID)

	oldOwnerResp, err := c.accessDevice(alice, target.DeviceID, target.PrimaryAction, owner, http.StatusForbidden)
	if err != nil {
		return fail(result, start, "old owner access after transfer failed", err)
	}

	if oldOwnerResp.Allowed || oldOwnerResp.Reason != "credential_revoked" {
		return fail(
			result,
			start,
			"unexpected old-owner post-transfer outcome",
			fmt.Errorf("allowed=%v reason=%s", oldOwnerResp.Allowed, oldOwnerResp.Reason),
		)
	}

	result.Steps = append(result.Steps, "old owner denied after transfer with reason="+oldOwnerResp.Reason)

	newOwnerResp, err := c.accessDevice(carol, target.DeviceID, target.PrimaryAction, transferResp.NewOwnerCredential, http.StatusOK)
	if err != nil {
		return fail(result, start, "new owner access after transfer failed", err)
	}

	if !newOwnerResp.Allowed {
		return fail(
			result,
			start,
			"new owner denied after transfer",
			fmt.Errorf("reason=%s", newOwnerResp.Reason),
		)
	}

	result.Steps = append(result.Steps, "new owner allowed after transfer with reason="+newOwnerResp.Reason)

	result.Passed = true
	result.Duration = time.Since(start)
	return result
}

func (c *Client) RunDataFlowMediationOn(target DeviceTarget) ScenarioResult {
	start := time.Now()
	result := ScenarioResult{Name: "data-flow-mediation/" + string(target.Kind)}

	if !target.SupportsDataFlow {
		return fail(
			result,
			start,
			"data-flow-mediation is not supported for selected device",
			fmt.Errorf("selected device=%s", target.Name),
		)
	}

	alice := uniqueDID("alice")

	owner, err := c.issueOwnerCredentialForDevice(alice, target.DeviceID, []string{target.PrimaryAction})
	if err != nil {
		return fail(result, start, "issue owner credential for data device failed", err)
	}

	result.Steps = append(result.Steps, fmt.Sprintf(
		"issued data-device owner credential for %s id=%s device=%s",
		alice,
		owner.ID,
		target.DeviceID,
	))

	readResp, err := c.accessDevice(alice, target.DeviceID, target.PrimaryAction, owner, http.StatusOK)
	if err != nil {
		return fail(result, start, "mediated data read failed", err)
	}

	if !readResp.Allowed || readResp.Reason != "allowed_by_owner_credential" {
		return fail(
			result,
			start,
			"unexpected data-flow mediation outcome",
			fmt.Errorf("allowed=%v reason=%s", readResp.Allowed, readResp.Reason),
		)
	}

	if readResp.PersistedTo == "" {
		return fail(result, start, "data result was not persisted", fmt.Errorf("persisted_to missing"))
	}

	result.Steps = append(result.Steps, target.Name+" read allowed with reason="+readResp.Reason)
	result.Steps = append(result.Steps, "data persisted to "+readResp.PersistedTo)

	result.Passed = true
	result.Duration = time.Since(start)
	return result
}
