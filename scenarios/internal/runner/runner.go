package runner

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type Config struct {
	IssuerURL      string
	GatewayURL     string
	WalletURL      string
	AuthzHealthURL string
	LockURL        string
	SensorURL      string
	LightURL       string
	GatewayID      string
	DeviceID       string
	SensorDeviceID string
	LightDeviceID  string
	Timeout        time.Duration
}

type Client struct {
	cfg  Config
	http *http.Client
}

type Proof struct {
	Type               string `json:"type"`
	Cryptosuite        string `json:"cryptosuite"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	ProofValue         string `json:"proofValue"`
}

type Credential struct {
	Context           []string          `json:"@context"`
	ID                string            `json:"id"`
	Type              []string          `json:"type"`
	Issuer            string            `json:"issuer"`
	ValidFrom         string            `json:"validFrom"`
	ValidUntil        string            `json:"validUntil"`
	CredentialSubject CredentialSubject `json:"credentialSubject"`
	CredentialStatus  CredentialStatus  `json:"credentialStatus"`
	Proof             *Proof            `json:"proof,omitempty"`
}

type CredentialSubject struct {
	ID                   string   `json:"id"`
	Gateway              string   `json:"gateway"`
	DeviceScopes         []string `json:"deviceScopes"`
	ActionScopes         []string `json:"actionScopes"`
	DelegatedBy          string   `json:"delegatedBy,omitempty"`
	ParentCredentialID   string   `json:"parentCredentialId,omitempty"`
	TransferredBy        string   `json:"transferredBy,omitempty"`
	ReplacesCredentialID string   `json:"replacesCredentialId,omitempty"`
}

type CredentialStatus struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	StatusPurpose string `json:"statusPurpose"`
	Status        string `json:"status"`
}

type OwnerCredentialRequest struct {
	Subject      string   `json:"subject"`
	Gateway      string   `json:"gateway"`
	DeviceScopes []string `json:"device_scopes"`
	ActionScopes []string `json:"action_scopes"`
}

type DelegationCredentialRequest struct {
	DelegatedBy       string                 `json:"delegated_by"`
	Subject           string                 `json:"subject"`
	Gateway           string                 `json:"gateway"`
	DeviceScopes      []string               `json:"device_scopes"`
	ActionScopes      []string               `json:"action_scopes"`
	TTLMinutes        int                    `json:"ttl_minutes"`
	Challenge         string                 `json:"challenge"`
	OwnerPresentation VerifiablePresentation `json:"owner_presentation"`
}

type RevokeCredentialRequest struct {
	CredentialID      string                 `json:"credential_id"`
	RevokedBy         string                 `json:"revoked_by"`
	Challenge         string                 `json:"challenge"`
	OwnerPresentation VerifiablePresentation `json:"owner_presentation"`
}

type TransferOwnershipRequest struct {
	TransferredBy     string                 `json:"transferred_by"`
	NewSubject        string                 `json:"new_subject"`
	Gateway           string                 `json:"gateway"`
	DeviceScopes      []string               `json:"device_scopes,omitempty"`
	ActionScopes      []string               `json:"action_scopes,omitempty"`
	Challenge         string                 `json:"challenge"`
	OwnerPresentation VerifiablePresentation `json:"owner_presentation"`
}

type TransferOwnershipResponse struct {
	OK                  bool       `json:"ok"`
	RevokedCredentialID string     `json:"revoked_credential_id"`
	NewOwnerCredential  Credential `json:"new_owner_credential"`
}

type AccessRequest struct {
	Subject      string                  `json:"subject"`
	DeviceID     string                  `json:"device_id"`
	Action       string                  `json:"action"`
	Challenge    string                  `json:"challenge,omitempty"`
	Presentation *VerifiablePresentation `json:"presentation,omitempty"`
}

type VerifiablePresentation struct {
	Context              []string     `json:"@context"`
	ID                   string       `json:"id"`
	Type                 []string     `json:"type"`
	Holder               string       `json:"holder"`
	VerifiableCredential []Credential `json:"verifiableCredential"`
	Proof                *VPProof     `json:"proof,omitempty"`
}

type VPProof struct {
	Type               string `json:"type"`
	Cryptosuite        string `json:"cryptosuite"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	Challenge          string `json:"challenge"`
	Domain             string `json:"domain"`
	ProofValue         string `json:"proofValue"`
}

type ChallengeRequest struct {
	Subject  string `json:"subject"`
	DeviceID string `json:"device_id"`
	Action   string `json:"action"`
}

type ChallengeResponse struct {
	Challenge string `json:"challenge"`
	Domain    string `json:"domain"`
	ExpiresAt string `json:"expires_at"`
}

type IssuerChallengeRequest struct {
	Subject   string `json:"subject"`
	Operation string `json:"operation"`
}

type WalletDIDResponse struct {
	DID string `json:"did"`
}

type StoreCredentialRequest struct {
	Credential Credential `json:"credential"`
}

type PresentationRequest struct {
	CredentialID string `json:"credential_id,omitempty"`
	Challenge    string `json:"challenge"`
	Domain       string `json:"domain"`
}

type GatewayAccessResponse struct {
	Allowed      bool            `json:"allowed"`
	Reason       string          `json:"reason"`
	DeviceResult json.RawMessage `json:"device_result,omitempty"`
	PersistedTo  string          `json:"persisted_to,omitempty"`
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

type Revocations struct {
	RevokedIDs []string `json:"revoked_ids"`
}

var scenarioActorKeys = map[string]ed25519.PrivateKey{}

func LoadConfig() Config {
	return Config{
		IssuerURL:      getenv("ISSUER_URL", "http://127.0.0.1:8082"),
		GatewayURL:     getenv("GATEWAY_URL", "http://127.0.0.1:8080"),
		WalletURL:      getenv("WALLET_URL", "http://127.0.0.1:8083"),
		AuthzHealthURL: getenv("AUTHZ_HEALTH_URL", "http://127.0.0.1:8081"),
		LockURL:        getenv("LOCK_URL", "http://127.0.0.1:8090"),
		SensorURL:      getenv("SENSOR_URL", "http://127.0.0.1:8091"),
		LightURL:       getenv("LIGHT_URL", "http://127.0.0.1:8092"),
		GatewayID:      getenv("GATEWAY_ID", "gateway-home-1"),
		DeviceID:       getenv("DEVICE_ID", "lock-front-door"),
		SensorDeviceID: getenv("SENSOR_DEVICE_ID", "sensor-living-room"),
		LightDeviceID:  getenv("LIGHT_DEVICE_ID", "light-living-room"),
		Timeout:        10 * time.Second,
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
		c.checkOne("wallet", c.cfg.WalletURL+"/health"),
		c.checkOne("authz", c.cfg.AuthzHealthURL+"/health"),
		c.checkOne("lock-sim", c.cfg.LockURL+"/health"),
		c.checkOne("sensor-sim", c.cfg.SensorURL+"/health"),
		c.checkOne("light-sim", c.cfg.LightURL+"/health"),
	}
}

func (c *Client) RunVPChallengeFlow() ScenarioResult {
	start := time.Now()
	result := ScenarioResult{Name: "vp-challenge"}

	holderDID, err := c.walletDID()
	if err != nil {
		return fail(result, start, "resolve wallet did failed", err)
	}
	result.Steps = append(result.Steps, "wallet holder did="+holderDID)

	owner, err := c.issueOwnerCredentialForDevice(holderDID, c.cfg.DeviceID, []string{"unlock"})
	if err != nil {
		return fail(result, start, "issue owner credential failed", err)
	}
	result.Steps = append(result.Steps, "issued owner credential id="+owner.ID)

	if err := c.storeCredentialInWallet(owner); err != nil {
		return fail(result, start, "store credential in wallet failed", err)
	}
	result.Steps = append(result.Steps, "stored credential in holder wallet")

	challenge, err := c.requestChallenge(holderDID, c.cfg.DeviceID, "unlock")
	if err != nil {
		return fail(result, start, "request gateway challenge failed", err)
	}
	result.Steps = append(result.Steps, "gateway challenge issued")

	presentation, err := c.createPresentation(owner.ID, challenge.Challenge, challenge.Domain)
	if err != nil {
		return fail(result, start, "create presentation failed", err)
	}
	result.Steps = append(result.Steps, "wallet signed verifiable presentation id="+presentation.ID)

	allowResp, err := c.accessDeviceWithPresentation(holderDID, c.cfg.DeviceID, "unlock", challenge.Challenge, presentation, http.StatusOK)
	if err != nil {
		return fail(result, start, "vp access request failed", err)
	}
	if !allowResp.Allowed || allowResp.Reason != "allowed_by_owner_credential" {
		return fail(result, start, "unexpected vp-challenge outcome", fmt.Errorf("allowed=%v reason=%s", allowResp.Allowed, allowResp.Reason))
	}
	result.Steps = append(result.Steps, "vp unlock allowed with reason="+allowResp.Reason)

	result.Passed = true
	result.Duration = time.Since(start)
	return result
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
	owner, err := c.issueOwnerCredentialForDevice(alice, c.cfg.DeviceID, []string{"unlock", "lock"})
	if err != nil {
		return fail(result, start, "issue owner credential failed", err)
	}
	result.Steps = append(result.Steps, "issued owner credential for "+alice+" id="+owner.ID)

	allowResp, err := c.accessDevice(alice, c.cfg.DeviceID, "unlock", owner, http.StatusOK)
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

	owner, err := c.issueOwnerCredentialForDevice(alice, c.cfg.DeviceID, []string{"unlock", "lock"})
	if err != nil {
		return fail(result, start, "issue owner credential failed", err)
	}
	result.Steps = append(result.Steps, "issued owner credential for "+alice+" id="+owner.ID)

	delegation, err := c.issueDelegationCredentialForDevice(alice, bob, owner, c.cfg.DeviceID, []string{"unlock"}, 120)
	if err != nil {
		return fail(result, start, "issue delegation credential failed", err)
	}
	result.Steps = append(result.Steps, "issued delegation credential for "+bob+" id="+delegation.ID)

	allowResp, err := c.accessDevice(bob, c.cfg.DeviceID, "unlock", delegation, http.StatusOK)
	if err != nil {
		return fail(result, start, "delegated unlock request failed", err)
	}
	if !allowResp.Allowed || allowResp.Reason != "allowed_by_delegation_credential" {
		return fail(result, start, "unexpected delegation allow outcome", fmt.Errorf("allowed=%v reason=%s", allowResp.Allowed, allowResp.Reason))
	}
	result.Steps = append(result.Steps, "delegated unlock allowed with reason="+allowResp.Reason)

	denyResp, err := c.accessDevice(bob, c.cfg.DeviceID, "lock", delegation, http.StatusForbidden)
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

	owner, err := c.issueOwnerCredentialForDevice(alice, c.cfg.DeviceID, []string{"unlock", "lock"})
	if err != nil {
		return fail(result, start, "issue owner credential failed", err)
	}
	result.Steps = append(result.Steps, "issued owner credential for "+alice+" id="+owner.ID)

	delegation, err := c.issueDelegationCredentialForDevice(alice, bob, owner, c.cfg.DeviceID, []string{"unlock"}, 120)
	if err != nil {
		return fail(result, start, "issue delegation credential failed", err)
	}
	result.Steps = append(result.Steps, "issued delegation credential for "+bob+" id="+delegation.ID)

	beforeResp, err := c.accessDevice(bob, c.cfg.DeviceID, "unlock", delegation, http.StatusOK)
	if err != nil {
		return fail(result, start, "delegated unlock before revocation failed", err)
	}
	if !beforeResp.Allowed || beforeResp.Reason != "allowed_by_delegation_credential" {
		return fail(result, start, "unexpected pre-revocation outcome", fmt.Errorf("allowed=%v reason=%s", beforeResp.Allowed, beforeResp.Reason))
	}
	result.Steps = append(result.Steps, "pre-revocation unlock allowed with reason="+beforeResp.Reason)

	if err := c.revokeCredentialViaIssuer(delegation.ID, alice, owner); err != nil {
		return fail(result, start, "revoke delegation credential failed", err)
	}
	result.Steps = append(result.Steps, "revoked delegation credential id="+delegation.ID)

	afterResp, err := c.accessDevice(bob, c.cfg.DeviceID, "unlock", delegation, http.StatusForbidden)
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

	owner, err := c.issueOwnerCredentialForDevice(alice, c.cfg.DeviceID, []string{"unlock", "lock"})
	if err != nil {
		return fail(result, start, "issue owner credential failed", err)
	}
	result.Steps = append(result.Steps, "issued owner credential for "+alice+" id="+owner.ID)

	beforeResp, err := c.accessDevice(alice, c.cfg.DeviceID, "unlock", owner, http.StatusOK)
	if err != nil {
		return fail(result, start, "owner unlock before transfer failed", err)
	}
	if !beforeResp.Allowed || beforeResp.Reason != "allowed_by_owner_credential" {
		return fail(result, start, "unexpected pre-transfer owner outcome", fmt.Errorf("allowed=%v reason=%s", beforeResp.Allowed, beforeResp.Reason))
	}
	result.Steps = append(result.Steps, "pre-transfer unlock allowed with reason="+beforeResp.Reason)

	transferResp, err := c.transferOwnershipForDevice(
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

	oldOwnerResp, err := c.accessDevice(alice, c.cfg.DeviceID, "unlock", owner, http.StatusForbidden)
	if err != nil {
		return fail(result, start, "old owner unlock after transfer failed", err)
	}
	if oldOwnerResp.Allowed || oldOwnerResp.Reason != "credential_revoked" {
		return fail(result, start, "unexpected old-owner post-transfer outcome", fmt.Errorf("allowed=%v reason=%s", oldOwnerResp.Allowed, oldOwnerResp.Reason))
	}
	result.Steps = append(result.Steps, "old owner denied after transfer with reason="+oldOwnerResp.Reason)

	newOwnerResp, err := c.accessDevice(carol, c.cfg.DeviceID, "unlock", transferResp.NewOwnerCredential, http.StatusOK)
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

func (c *Client) RunDataFlowMediation() ScenarioResult {
	start := time.Now()
	result := ScenarioResult{Name: "data-flow-mediation"}

	alice := uniqueDID("alice")

	owner, err := c.issueOwnerCredentialForDevice(alice, c.cfg.SensorDeviceID, []string{"read_sensor"})
	if err != nil {
		return fail(result, start, "issue owner credential for sensor failed", err)
	}
	result.Steps = append(result.Steps, "issued sensor owner credential for "+alice+" id="+owner.ID)

	readResp, err := c.accessDevice(alice, c.cfg.SensorDeviceID, "read_sensor", owner, http.StatusOK)
	if err != nil {
		return fail(result, start, "mediated sensor read failed", err)
	}
	if !readResp.Allowed || readResp.Reason != "allowed_by_owner_credential" {
		return fail(result, start, "unexpected sensor mediation outcome", fmt.Errorf("allowed=%v reason=%s", readResp.Allowed, readResp.Reason))
	}
	if readResp.PersistedTo == "" {
		return fail(result, start, "sensor result was not persisted", fmt.Errorf("persisted_to missing"))
	}
	result.Steps = append(result.Steps, "sensor read allowed with reason="+readResp.Reason)
	result.Steps = append(result.Steps, "sensor data persisted to "+readResp.PersistedTo)

	result.Passed = true
	result.Duration = time.Since(start)
	return result
}

func (c *Client) issueOwnerCredentialForDevice(subject, deviceID string, actions []string) (Credential, error) {
	var cred Credential
	err := c.postJSON(
		c.cfg.IssuerURL+"/credentials/owner",
		OwnerCredentialRequest{
			Subject:      subject,
			Gateway:      c.cfg.GatewayID,
			DeviceScopes: []string{deviceID},
			ActionScopes: actions,
		},
		&cred,
		http.StatusOK,
	)
	return cred, err
}

func (c *Client) issueDelegationCredentialForDevice(delegatedBy, subject string, owner Credential, deviceID string, actions []string, ttlMinutes int) (Credential, error) {
	challenge, presentation, err := c.ownerPresentationForIssuer(delegatedBy, "delegation", owner)
	if err != nil {
		return Credential{}, err
	}

	var cred Credential
	err = c.postJSON(
		c.cfg.IssuerURL+"/credentials/delegation",
		DelegationCredentialRequest{
			DelegatedBy:       delegatedBy,
			Subject:           subject,
			Gateway:           c.cfg.GatewayID,
			DeviceScopes:      []string{deviceID},
			ActionScopes:      actions,
			TTLMinutes:        ttlMinutes,
			Challenge:         challenge.Challenge,
			OwnerPresentation: presentation,
		},
		&cred,
		http.StatusOK,
	)
	return cred, err
}

func (c *Client) revokeCredentialViaIssuer(credentialID, revokedBy string, ownerCredential Credential) error {
	challenge, presentation, err := c.ownerPresentationForIssuer(revokedBy, "revocation", ownerCredential)
	if err != nil {
		return err
	}

	var out map[string]any
	return c.postJSON(
		c.cfg.IssuerURL+"/credentials/revoke",
		RevokeCredentialRequest{
			CredentialID:      credentialID,
			RevokedBy:         revokedBy,
			Challenge:         challenge.Challenge,
			OwnerPresentation: presentation,
		},
		&out,
		http.StatusOK,
	)
}

func (c *Client) transferOwnershipForDevice(transferredBy, newSubject string, ownerCredential Credential, deviceScopes, actionScopes []string) (TransferOwnershipResponse, error) {
	challenge, presentation, err := c.ownerPresentationForIssuer(transferredBy, "transfer", ownerCredential)
	if err != nil {
		return TransferOwnershipResponse{}, err
	}

	var out TransferOwnershipResponse
	err = c.postJSON(
		c.cfg.IssuerURL+"/credentials/transfer",
		TransferOwnershipRequest{
			TransferredBy:     transferredBy,
			NewSubject:        newSubject,
			Gateway:           c.cfg.GatewayID,
			DeviceScopes:      deviceScopes,
			ActionScopes:      actionScopes,
			Challenge:         challenge.Challenge,
			OwnerPresentation: presentation,
		},
		&out,
		http.StatusOK,
	)
	return out, err
}

func (c *Client) ownerPresentationForIssuer(subject, operation string, cred Credential) (ChallengeResponse, VerifiablePresentation, error) {
	if cred.CredentialSubject.ID != subject {
		return ChallengeResponse{}, VerifiablePresentation{}, fmt.Errorf("credential subject %s does not match issuer subject %s", cred.CredentialSubject.ID, subject)
	}

	challenge, err := c.requestIssuerChallenge(subject, operation)
	if err != nil {
		return ChallengeResponse{}, VerifiablePresentation{}, err
	}

	presentation, err := createScenarioPresentation(subject, cred, challenge.Challenge, challenge.Domain)
	if err != nil {
		return ChallengeResponse{}, VerifiablePresentation{}, err
	}

	return challenge, presentation, nil
}

func (c *Client) accessDevice(subject, deviceID, action string, cred Credential, expectedStatus int) (GatewayAccessResponse, error) {
	if cred.CredentialSubject.ID != subject {
		return GatewayAccessResponse{}, fmt.Errorf("credential subject %s does not match access subject %s", cred.CredentialSubject.ID, subject)
	}

	challenge, err := c.requestChallenge(subject, deviceID, action)
	if err != nil {
		return GatewayAccessResponse{}, err
	}

	presentation, err := createScenarioPresentation(subject, cred, challenge.Challenge, challenge.Domain)
	if err != nil {
		return GatewayAccessResponse{}, err
	}

	return c.accessDeviceWithPresentation(subject, deviceID, action, challenge.Challenge, presentation, expectedStatus)
}

func (c *Client) accessDeviceWithPresentation(subject, deviceID, action, challenge string, presentation VerifiablePresentation, expectedStatus int) (GatewayAccessResponse, error) {
	var out GatewayAccessResponse
	err := c.postJSON(
		c.cfg.GatewayURL+"/access/request",
		AccessRequest{
			Subject:      subject,
			DeviceID:     deviceID,
			Action:       action,
			Challenge:    challenge,
			Presentation: &presentation,
		},
		&out,
		expectedStatus,
	)
	return out, err
}

func (c *Client) walletDID() (string, error) {
	var out WalletDIDResponse
	if err := c.getJSON(c.cfg.WalletURL+"/wallet/did", &out); err != nil {
		return "", err
	}
	return out.DID, nil
}

func (c *Client) storeCredentialInWallet(cred Credential) error {
	var out map[string]any
	return c.postJSON(
		c.cfg.WalletURL+"/wallet/credentials",
		StoreCredentialRequest{Credential: cred},
		&out,
		http.StatusOK,
	)
}

func (c *Client) requestChallenge(subject, deviceID, action string) (ChallengeResponse, error) {
	var out ChallengeResponse
	err := c.postJSON(
		c.cfg.GatewayURL+"/access/challenge",
		ChallengeRequest{Subject: subject, DeviceID: deviceID, Action: action},
		&out,
		http.StatusOK,
	)
	return out, err
}

func (c *Client) requestIssuerChallenge(subject, operation string) (ChallengeResponse, error) {
	var out ChallengeResponse
	err := c.postJSON(
		c.cfg.IssuerURL+"/credentials/challenge",
		IssuerChallengeRequest{Subject: subject, Operation: operation},
		&out,
		http.StatusOK,
	)
	return out, err
}

func (c *Client) createPresentation(credentialID, challenge, domain string) (VerifiablePresentation, error) {
	var out VerifiablePresentation
	err := c.postJSON(
		c.cfg.WalletURL+"/wallet/presentations",
		PresentationRequest{CredentialID: credentialID, Challenge: challenge, Domain: domain},
		&out,
		http.StatusOK,
	)
	return out, err
}

func (c *Client) getJSON(url string, out any) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status=%d body=%s", resp.StatusCode, string(body))
	}
	if out == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response failed: %w body=%s", err, string(body))
	}
	return nil
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

func IssueOwnerCredential(cfg Config, subject string, actions ...string) Credential {
	return IssueOwnerCredentialForDevice(cfg, cfg.DeviceID, subject, actions...)
}

func IssueOwnerCredentialForDevice(cfg Config, deviceID, subject string, actions ...string) Credential {
	c := New(cfg)
	cred, err := c.issueOwnerCredentialForDevice(subject, deviceID, actions)
	must(err)
	return cred
}

func IssueDelegationCredential(cfg Config, delegatedBy, subject string, owner Credential, ttlMinutes int, actions ...string) Credential {
	return IssueDelegationCredentialForDevice(cfg, cfg.DeviceID, delegatedBy, subject, owner, ttlMinutes, actions...)
}

func IssueDelegationCredentialForDevice(cfg Config, deviceID, delegatedBy, subject string, owner Credential, ttlMinutes int, actions ...string) Credential {
	c := New(cfg)
	cred, err := c.issueDelegationCredentialForDevice(delegatedBy, subject, owner, deviceID, actions, ttlMinutes)
	must(err)
	return cred
}

func RevokeCredentialViaIssuer(cfg Config, credentialID, revokedBy string, ownerCredential Credential) {
	c := New(cfg)
	must(c.revokeCredentialViaIssuer(credentialID, revokedBy, ownerCredential))
}

func TransferOwnership(cfg Config, transferredBy, newSubject string, ownerCredential Credential) TransferOwnershipResponse {
	c := New(cfg)
	out, err := c.transferOwnershipForDevice(
		transferredBy,
		newSubject,
		ownerCredential,
		[]string{cfg.DeviceID},
		[]string{"unlock", "lock"},
	)
	must(err)
	return out
}

func TransferOwnershipForDevice(cfg Config, transferredBy, newSubject string, ownerCredential Credential, deviceScopes, actionScopes []string) TransferOwnershipResponse {
	c := New(cfg)
	out, err := c.transferOwnershipForDevice(
		transferredBy,
		newSubject,
		ownerCredential,
		deviceScopes,
		actionScopes,
	)
	must(err)
	return out
}

func Access(cfg Config, subject, action string, cred Credential, expectedStatus int) GatewayAccessResponse {
	return AccessDevice(cfg, cfg.DeviceID, subject, action, cred, expectedStatus)
}

func AccessDevice(cfg Config, deviceID, subject, action string, cred Credential, expectedStatus int) GatewayAccessResponse {
	c := New(cfg)
	out, err := c.accessDevice(subject, deviceID, action, cred, expectedStatus)
	must(err)
	return out
}

func ExpectAllowed(resp GatewayAccessResponse, expectedReason string) {
	if !resp.Allowed || resp.Reason != expectedReason {
		panic(fmt.Sprintf("expected allowed reason=%s got allowed=%v reason=%s", expectedReason, resp.Allowed, resp.Reason))
	}
}

func ExpectDenied(resp GatewayAccessResponse, expectedReason string) {
	if resp.Allowed || resp.Reason != expectedReason {
		panic(fmt.Sprintf("expected denied reason=%s got allowed=%v reason=%s", expectedReason, resp.Allowed, resp.Reason))
	}
}

func ExpectPersisted(resp GatewayAccessResponse) {
	if resp.PersistedTo == "" {
		panic("expected persisted_to in gateway response, got empty value")
	}
}

func ActorDID(name string) string {
	return scenarioActor(name)
}

func loadRevocations(path string) (Revocations, error) {
	var out Revocations

	raw, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return Revocations{RevokedIDs: []string{}}, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, err
	}
	if out.RevokedIDs == nil {
		out.RevokedIDs = []string{}
	}
	return out, nil
}

func saveRevocations(path string, revocations Revocations) error {
	raw, err := json.MarshalIndent(revocations, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o644)
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func fail(result ScenarioResult, start time.Time, step string, err error) ScenarioResult {
	result.Passed = false
	result.Duration = time.Since(start)
	result.Error = step + ": " + err.Error()
	result.Steps = append(result.Steps, result.Error)
	return result
}

func uniqueDID(name string) string {
	return scenarioActor(name)
}

func scenarioActor(name string) string {
	seed := sha256.Sum256([]byte("blackwall-scenario-actor:" + name))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	did := didKeyFromPublicKey(publicKey)
	scenarioActorKeys[did] = privateKey
	return did
}

func createScenarioPresentation(subject string, cred Credential, challenge, domain string) (VerifiablePresentation, error) {
	privateKey, ok := scenarioActorKeys[subject]
	if !ok {
		return VerifiablePresentation{}, fmt.Errorf("no scenario signing key for subject %s", subject)
	}

	now := time.Now().UTC()
	vp := VerifiablePresentation{
		Context: []string{
			"https://www.w3.org/ns/credentials/v2",
			"https://blackwall.local/contexts/smart-home-presentation/v1",
		},
		ID:                   fmt.Sprintf("urn:uuid:vp-%d", now.UnixNano()),
		Type:                 []string{"VerifiablePresentation"},
		Holder:               subject,
		VerifiableCredential: []Credential{cred},
	}

	signature := ed25519.Sign(privateKey, presentationSigningInput(vp))
	vp.Proof = &VPProof{
		Type:               "DataIntegrityProof",
		Cryptosuite:        "eddsa-rdfc-2022",
		Created:            now.Format(time.RFC3339),
		VerificationMethod: subject + "#key-1",
		ProofPurpose:       "authentication",
		Challenge:          challenge,
		Domain:             domain,
		ProofValue:         hex.EncodeToString(signature),
	}

	return vp, nil
}

func presentationSigningInput(vp VerifiablePresentation) []byte {
	vp.Proof = nil
	raw, err := json.Marshal(vp)
	if err != nil {
		return nil
	}
	return raw
}

func didKeyFromPublicKey(publicKey ed25519.PublicKey) string {
	prefixed := append([]byte{0xed, 0x01}, publicKey...)
	return "did:key:z" + base58Encode(prefixed)
}

func base58Encode(raw []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	if len(raw) == 0 {
		return ""
	}

	digits := []byte{0}
	for _, b := range raw {
		carry := int(b)
		for j := len(digits) - 1; j >= 0; j-- {
			carry += int(digits[j]) << 8
			digits[j] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			digits = append([]byte{byte(carry % 58)}, digits...)
			carry /= 58
		}
	}

	for _, b := range raw {
		if b == 0 {
			digits = append([]byte{0}, digits...)
			continue
		}
		break
	}

	out := make([]byte, len(digits))
	for i, digit := range digits {
		out[i] = alphabet[digit]
	}
	return string(out)
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
