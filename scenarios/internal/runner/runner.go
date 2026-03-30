package runner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type Config struct {
	IssuerURL string
	GatewayURL string
	GatewayID string
	DeviceID  string
	Timeout   time.Duration
}

type Client struct {
	cfg  Config
	http *http.Client
}

type Proof struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Credential struct {
	ID                  string   `json:"id"`
	Type                string   `json:"type"`
	Issuer              string   `json:"issuer"`
	Subject             string   `json:"subject"`
	Gateway             string   `json:"gateway"`
	DeviceScopes        []string `json:"device_scopes"`
	ActionScopes        []string `json:"action_scopes"`
	DelegatedBy         string   `json:"delegated_by,omitempty"`
	ParentCredentialID  string   `json:"parent_credential_id,omitempty"`
	TransferredBy       string   `json:"transferred_by,omitempty"`
	ReplacesCredentialID string  `json:"replaces_credential_id,omitempty"`
	IssuedAt            string   `json:"issued_at"`
	ExpiresAt           string   `json:"expires_at"`
	Status              string   `json:"status"`
	Proof               Proof    `json:"proof"`
}

type OwnerCredentialRequest struct {
	Subject      string   `json:"subject"`
	Gateway      string   `json:"gateway"`
	DeviceScopes []string `json:"device_scopes"`
	ActionScopes []string `json:"action_scopes"`
}

type DelegationCredentialRequest struct {
	DelegatedBy     string     `json:"delegated_by"`
	Subject         string     `json:"subject"`
	Gateway         string     `json:"gateway"`
	DeviceScopes    []string   `json:"device_scopes"`
	ActionScopes    []string   `json:"action_scopes"`
	TTLMinutes      int        `json:"ttl_minutes"`
	OwnerCredential Credential `json:"owner_credential"`
}

type RevokeCredentialRequest struct {
	CredentialID    string     `json:"credential_id"`
	RevokedBy       string     `json:"revoked_by"`
	OwnerCredential Credential `json:"owner_credential"`
}

type TransferOwnershipRequest struct {
	TransferredBy   string     `json:"transferred_by"`
	NewSubject      string     `json:"new_subject"`
	Gateway         string     `json:"gateway"`
	DeviceScopes    []string   `json:"device_scopes,omitempty"`
	ActionScopes    []string   `json:"action_scopes,omitempty"`
	OwnerCredential Credential `json:"owner_credential"`
}

type TransferOwnershipResponse struct {
	OK                  bool       `json:"ok"`
	RevokedCredentialID string     `json:"revoked_credential_id"`
	NewOwnerCredential  Credential `json:"new_owner_credential"`
}

type AccessRequest struct {
	Subject    string     `json:"subject"`
	DeviceID   string     `json:"device_id"`
	Action     string     `json:"action"`
	Credential Credential `json:"credential"`
}

type AccessResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

type ServiceHealth struct {
	Name       string
	URL        string
	OK         bool
	StatusCode int
	Error      string
}

type ScenarioResult struct {
	Name     string
	Passed   bool
	Duration time.Duration
	Steps    []string
	Error    string
}

func LoadConfig() Config {
	return Config{
		IssuerURL:  getenv("ISSUER_URL", "http://127.0.0.1:8082"),
		GatewayURL: getenv("GATEWAY_URL", "http://127.0.0.1:8080"),
		GatewayID:  getenv("GATEWAY_ID", "gateway-home-1"),
		DeviceID:   getenv("DEVICE_ID", "lock-front-door"),
		Timeout:    10 * time.Second,
	}
}

func New(cfg Config) *Client {
	return &Client{
		cfg: cfg,
		http: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

func (c *Client) CheckHealth() []ServiceHealth {
	return []ServiceHealth{
		c.checkOne("issuer", c.cfg.IssuerURL+"/health"),
		c.checkOne("gateway", c.cfg.GatewayURL+"/health"),
	}
}

func (c *Client) checkOne(name, url string) ServiceHealth {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return ServiceHealth{Name: name, URL: url, OK: false, Error: err.Error()}
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return ServiceHealth{Name: name, URL: url, OK: false, Error: err.Error()}
	}
	defer resp.Body.Close()

	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	return ServiceHealth{
		Name:       name,
		URL:        url,
		OK:         ok,
		StatusCode: resp.StatusCode,
	}
}

func (c *Client) RunOwnerControl() ScenarioResult {
	start := time.Now()
	result := ScenarioResult{Name: "owner-control"}

	alice := uniqueDID("alice")

	owner, err := c.issueOwnerCredential(alice, []string{"unlock", "lock"})
	if err != nil {
		return fail(result, start, "issue owner credential failed", err)
	}
	result.Steps = append(result.Steps, "issued owner credential for "+alice+" id="+owner.ID)

	allowResp, err := c.access(alice, "unlock", owner, http.StatusOK)
	if err != nil {
		return fail(result, start, "owner unlock request failed", err)
	}
	if !allowResp.Allowed || allowResp.Reason != "allowed_by_owner_credential" {
		return fail(result, start, "unexpected owner-control outcome", fmt.Errorf("allowed=%v reason=%s", allowResp.Allowed, allowResp.Reason))
	}
	result.Steps = append(result.Steps, "owner unlock allowed with reason="+allowResp.Reason)

	result.Passed = true
	result.Duration = time.Since(start)
	return result
}

func (c *Client) RunDelegation() ScenarioResult {
	start := time.Now()
	result := ScenarioResult{Name: "delegation"}

	alice := uniqueDID("alice")
	bob := uniqueDID("bob")

	owner, err := c.issueOwnerCredential(alice, []string{"unlock", "lock"})
	if err != nil {
		return fail(result, start, "issue owner credential failed", err)
	}
	result.Steps = append(result.Steps, "issued owner credential for "+alice+" id="+owner.ID)

	delegation, err := c.issueDelegationCredential(alice, bob, owner, []string{"unlock"}, 120)
	if err != nil {
		return fail(result, start, "issue delegation credential failed", err)
	}
	result.Steps = append(result.Steps, "issued delegation credential for "+bob+" id="+delegation.ID)

	allowResp, err := c.access(bob, "unlock", delegation, http.StatusOK)
	if err != nil {
		return fail(result, start, "delegated unlock request failed", err)
	}
	if !allowResp.Allowed || allowResp.Reason != "allowed_by_delegation_credential" {
		return fail(result, start, "unexpected delegation allow outcome", fmt.Errorf("allowed=%v reason=%s", allowResp.Allowed, allowResp.Reason))
	}
	result.Steps = append(result.Steps, "delegated unlock allowed with reason="+allowResp.Reason)

	denyResp, err := c.access(bob, "lock", delegation, http.StatusForbidden)
	if err != nil {
		return fail(result, start, "delegated lock request failed", err)
	}
	if denyResp.Allowed || denyResp.Reason != "action_out_of_scope" {
		return fail(result, start, "unexpected delegation deny outcome", fmt.Errorf("allowed=%v reason=%s", denyResp.Allowed, denyResp.Reason))
	}
	result.Steps = append(result.Steps, "delegated lock denied with reason="+denyResp.Reason)

	result.Passed = true
	result.Duration = time.Since(start)
	return result
}

func (c *Client) RunRevocation() ScenarioResult {
	start := time.Now()
	result := ScenarioResult{Name: "revocation"}

	alice := uniqueDID("alice")
	bob := uniqueDID("bob")

	owner, err := c.issueOwnerCredential(alice, []string{"unlock", "lock"})
	if err != nil {
		return fail(result, start, "issue owner credential failed", err)
	}
	result.Steps = append(result.Steps, "issued owner credential for "+alice+" id="+owner.ID)

	delegation, err := c.issueDelegationCredential(alice, bob, owner, []string{"unlock"}, 120)
	if err != nil {
		return fail(result, start, "issue delegation credential failed", err)
	}
	result.Steps = append(result.Steps, "issued delegation credential for "+bob+" id="+delegation.ID)

	beforeResp, err := c.access(bob, "unlock", delegation, http.StatusOK)
	if err != nil {
		return fail(result, start, "delegated unlock before revocation failed", err)
	}
	if !beforeResp.Allowed || beforeResp.Reason != "allowed_by_delegation_credential" {
		return fail(result, start, "unexpected pre-revocation outcome", fmt.Errorf("allowed=%v reason=%s", beforeResp.Allowed, beforeResp.Reason))
	}
	result.Steps = append(result.Steps, "pre-revocation unlock allowed with reason="+beforeResp.Reason)

	if err := c.revokeCredential(delegation.ID, alice, owner); err != nil {
		return fail(result, start, "revoke delegation credential failed", err)
	}
	result.Steps = append(result.Steps, "revoked delegation credential id="+delegation.ID)

	afterResp, err := c.access(bob, "unlock", delegation, http.StatusForbidden)
	if err != nil {
		return fail(result, start, "delegated unlock after revocation failed", err)
	}
	if afterResp.Allowed || afterResp.Reason != "credential_revoked" {
		return fail(result, start, "unexpected post-revocation outcome", fmt.Errorf("allowed=%v reason=%s", afterResp.Allowed, afterResp.Reason))
	}
	result.Steps = append(result.Steps, "post-revocation unlock denied with reason="+afterResp.Reason)

	result.Passed = true
	result.Duration = time.Since(start)
	return result
}

func (c *Client) RunOwnershipTransfer() ScenarioResult {
	start := time.Now()
	result := ScenarioResult{Name: "ownership-transfer"}

	alice := uniqueDID("alice")
	carol := uniqueDID("carol")

	owner, err := c.issueOwnerCredential(alice, []string{"unlock", "lock"})
	if err != nil {
		return fail(result, start, "issue owner credential failed", err)
	}
	result.Steps = append(result.Steps, "issued owner credential for "+alice+" id="+owner.ID)

	beforeResp, err := c.access(alice, "unlock", owner, http.StatusOK)
	if err != nil {
		return fail(result, start, "owner unlock before transfer failed", err)
	}
	if !beforeResp.Allowed || beforeResp.Reason != "allowed_by_owner_credential" {
		return fail(result, start, "unexpected pre-transfer owner outcome", fmt.Errorf("allowed=%v reason=%s", beforeResp.Allowed, beforeResp.Reason))
	}
	result.Steps = append(result.Steps, "pre-transfer unlock allowed with reason="+beforeResp.Reason)

	transferResp, err := c.transferOwnership(
		alice,
		carol,
		owner,
		[]string{c.cfg.DeviceID},
		[]string{"unlock", "lock"},
	)
	if err != nil {
		return fail(result, start, "ownership transfer failed", err)
	}
	result.Steps = append(result.Steps, "transferred ownership from "+alice+" to "+carol)
	result.Steps = append(result.Steps, "revoked previous owner credential id="+transferResp.RevokedCredentialID)
	result.Steps = append(result.Steps, "issued new owner credential id="+transferResp.NewOwnerCredential.ID)

	oldOwnerResp, err := c.access(alice, "unlock", owner, http.StatusForbidden)
	if err != nil {
		return fail(result, start, "old owner unlock after transfer failed", err)
	}
	if oldOwnerResp.Allowed || oldOwnerResp.Reason != "credential_revoked" {
		return fail(result, start, "unexpected old-owner post-transfer outcome", fmt.Errorf("allowed=%v reason=%s", oldOwnerResp.Allowed, oldOwnerResp.Reason))
	}
	result.Steps = append(result.Steps, "old owner denied after transfer with reason="+oldOwnerResp.Reason)

	newOwnerResp, err := c.access(carol, "unlock", transferResp.NewOwnerCredential, http.StatusOK)
	if err != nil {
		return fail(result, start, "new owner unlock after transfer failed", err)
	}
	if !newOwnerResp.Allowed {
		return fail(result, start, "new owner denied after transfer", fmt.Errorf("reason=%s", newOwnerResp.Reason))
	}
	result.Steps = append(result.Steps, "new owner allowed after transfer with reason="+newOwnerResp.Reason)

	result.Passed = true
	result.Duration = time.Since(start)
	return result
}

func (c *Client) issueOwnerCredential(subject string, actions []string) (Credential, error) {
	var cred Credential
	err := c.postJSON(
		c.cfg.IssuerURL+"/credentials/owner",
		OwnerCredentialRequest{
			Subject:      subject,
			Gateway:      c.cfg.GatewayID,
			DeviceScopes: []string{c.cfg.DeviceID},
			ActionScopes: actions,
		},
		&cred,
		http.StatusOK,
	)
	return cred, err
}

func (c *Client) issueDelegationCredential(delegatedBy, subject string, owner Credential, actions []string, ttlMinutes int) (Credential, error) {
	var cred Credential
	err := c.postJSON(
		c.cfg.IssuerURL+"/credentials/delegation",
		DelegationCredentialRequest{
			DelegatedBy:     delegatedBy,
			Subject:         subject,
			Gateway:         c.cfg.GatewayID,
			DeviceScopes:    []string{c.cfg.DeviceID},
			ActionScopes:    actions,
			TTLMinutes:      ttlMinutes,
			OwnerCredential: owner,
		},
		&cred,
		http.StatusOK,
	)
	return cred, err
}

func (c *Client) revokeCredential(credentialID, revokedBy string, ownerCredential Credential) error {
	var out map[string]any
	return c.postJSON(
		c.cfg.IssuerURL+"/credentials/revoke",
		RevokeCredentialRequest{
			CredentialID:    credentialID,
			RevokedBy:       revokedBy,
			OwnerCredential: ownerCredential,
		},
		&out,
		http.StatusOK,
	)
}

func (c *Client) transferOwnership(transferredBy string, newSubject string, ownerCredential Credential, deviceScopes []string, actionScopes []string) (TransferOwnershipResponse, error) {
	var out TransferOwnershipResponse

	err := c.postJSON(
		c.cfg.IssuerURL+"/credentials/transfer",
		TransferOwnershipRequest{
			TransferredBy:   transferredBy,
			NewSubject:      newSubject,
			Gateway:         c.cfg.GatewayID,
			DeviceScopes:    deviceScopes,
			ActionScopes:    actionScopes,
			OwnerCredential: ownerCredential,
		},
		&out,
		http.StatusOK,
	)

	return out, err
}

func (c *Client) access(subject, action string, cred Credential, expectedStatus int) (AccessResponse, error) {
	var out AccessResponse
	err := c.postJSON(
		c.cfg.GatewayURL+"/access/request",
		AccessRequest{
			Subject:    subject,
			DeviceID:   c.cfg.DeviceID,
			Action:     action,
			Credential: cred,
		},
		&out,
		expectedStatus,
	)
	return out, err
}

func (c *Client) postJSON(url string, in any, out any, expectedStatus int) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != expectedStatus {
		return fmt.Errorf("unexpected status=%d expected=%d body=%s", resp.StatusCode, expectedStatus, string(body))
	}

	if out == nil || len(body) == 0 {
		return nil
	}

	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response failed: %w body=%s", err, string(body))
	}

	return nil
}

func fail(result ScenarioResult, start time.Time, step string, err error) ScenarioResult {
	result.Passed = false
	result.Duration = time.Since(start)
	result.Error = step + ": " + err.Error()
	result.Steps = append(result.Steps, result.Error)
	return result
}

func uniqueDID(name string) string {
	return fmt.Sprintf("did:example:%s-%d", name, time.Now().UnixNano())
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}