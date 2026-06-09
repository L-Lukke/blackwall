package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const challengeTTL = 5 * time.Minute

var challengeStore = newChallengeStore()

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

type ChallengeRecord struct {
	Subject   string
	DeviceID  string
	Action    string
	Domain    string
	ExpiresAt time.Time
}

type ChallengeStore struct {
	mu         sync.Mutex
	challenges map[string]ChallengeRecord
}

func newChallengeStore() *ChallengeStore {
	return &ChallengeStore{
		challenges: map[string]ChallengeRecord{},
	}
}

type AuthzResponse struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason"`
}

type DeviceCommand struct {
	DeviceID string `json:"device_id"`
}

type AuditRecord struct {
	EventID              string `json:"event_id"`
	RecordedAt           string `json:"recorded_at"`
	Subject              string `json:"subject,omitempty"`
	DeviceID             string `json:"device_id,omitempty"`
	Action               string `json:"action,omitempty"`
	CredentialID         string `json:"credential_id,omitempty"`
	CredentialType       string `json:"credential_type,omitempty"`
	CredentialIssuer     string `json:"credential_issuer,omitempty"`
	CredentialSubject    string `json:"credential_subject,omitempty"`
	DelegatedBy          string `json:"delegated_by,omitempty"`
	ParentCredentialID   string `json:"parent_credential_id,omitempty"`
	TransferredBy        string `json:"transferred_by,omitempty"`
	ReplacesCredentialID string `json:"replaces_credential_id,omitempty"`
	AuthzAllow           *bool  `json:"authz_allow,omitempty"`
	AuthzReason          string `json:"authz_reason,omitempty"`
	Outcome              string `json:"outcome"`
	HTTPStatus           int    `json:"http_status"`
	PersistedTo          string `json:"persisted_to,omitempty"`
	Error                string `json:"error,omitempty"`
}

func main() {
	requireEnv("SERVICE_AUTH_TOKEN")

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/access/challenge", challengeHandler)
	mux.HandleFunc("/access/request", accessRequestHandler)

	addr := getenv("GATEWAY_ADDR", "127.0.0.1:8080")
	log.Printf("go-api listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, serviceAuthMiddleware(mux)))
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func challengeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}

	var req ChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_json"})
		return
	}
	if req.Subject == "" || req.DeviceID == "" || req.Action == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "subject_device_id_and_action_required"})
		return
	}

	challenge, err := randomHex(32)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "challenge_generation_failed"})
		return
	}
	domain := getenv("GATEWAY_ID", "gateway-home-1")
	expiresAt := time.Now().UTC().Add(challengeTTL)
	challengeStore.Put(challenge, ChallengeRecord{
		Subject:   req.Subject,
		DeviceID:  req.DeviceID,
		Action:    req.Action,
		Domain:    domain,
		ExpiresAt: expiresAt,
	})

	writeJSON(w, http.StatusOK, ChallengeResponse{
		Challenge: challenge,
		Domain:    domain,
		ExpiresAt: expiresAt.Format(time.RFC3339),
	})
}

func accessRequestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		appendAuditLog(AccessRequest{}, nil, "method_not_allowed", http.StatusMethodNotAllowed, "method_not_allowed", "")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}

	var req AccessRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		appendAuditLog(AccessRequest{}, nil, "bad_json", http.StatusBadRequest, err.Error(), "")
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_json"})
		return
	}
	if req.Presentation == nil {
		appendAuditLog(req, nil, "presentation_required", http.StatusForbidden, "", "")
		writeJSON(w, http.StatusForbidden, map[string]any{
			"allowed": false,
			"reason":  "presentation_required",
		})
		return
	}
	if reason := challengeStore.Consume(req); reason != "" {
		appendAuditLog(req, nil, "challenge_rejected", http.StatusForbidden, reason, "")
		writeJSON(w, http.StatusForbidden, map[string]any{
			"allowed": false,
			"reason":  reason,
		})
		return
	}

	var authzResp AuthzResponse
	if err := postJSON(
		getenv("AUTHZ_URL", "http://127.0.0.1:8081/v1/authorize"),
		req,
		&authzResp,
	); err != nil {
		appendAuditLog(req, nil, "authz_unreachable", http.StatusBadGateway, err.Error(), "")
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error":   "authz_unreachable",
			"details": err.Error(),
		})
		return
	}

	if !authzResp.Allow {
		appendAuditLog(req, &authzResp, "denied_by_authz", http.StatusForbidden, "", "")
		writeJSON(w, http.StatusForbidden, map[string]any{
			"allowed": false,
			"reason":  authzResp.Reason,
		})
		return
	}

	switch req.Action {
	case "unlock", "lock":
		handleLockAction(w, req, authzResp)
	case "read_sensor":
		handleReadSensor(w, req, authzResp)
	case "turn_on", "turn_off":
		handleLightAction(w, req, authzResp)
	default:
		appendAuditLog(req, &authzResp, "unsupported_action", http.StatusBadRequest, "unsupported_action_for_v1", "")
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "unsupported_action_for_v1",
		})
	}
}

func handleLockAction(w http.ResponseWriter, req AccessRequest, authzResp AuthzResponse) {
	deviceURL := getenv("LOCK_URL", "http://127.0.0.1:8090") + "/" + req.Action

	var deviceResp map[string]any
	if err := postJSON(deviceURL, DeviceCommand{DeviceID: req.DeviceID}, &deviceResp); err != nil {
		appendAuditLog(req, &authzResp, "device_unreachable", http.StatusBadGateway, err.Error(), "")
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error":   "device_unreachable",
			"details": err.Error(),
		})
		return
	}

	appendAuditLog(req, &authzResp, "device_command_sent", http.StatusOK, "", "")

	writeJSON(w, http.StatusOK, map[string]any{
		"allowed":       true,
		"reason":        authzResp.Reason,
		"device_result": deviceResp,
	})
}

func handleLightAction(w http.ResponseWriter, req AccessRequest, authzResp AuthzResponse) {
	deviceURL := getenv("LIGHT_URL", "http://127.0.0.1:8092") + "/" + req.Action

	var deviceResp map[string]any
	if err := postJSON(deviceURL, DeviceCommand{DeviceID: req.DeviceID}, &deviceResp); err != nil {
		appendAuditLog(req, &authzResp, "light_unreachable", http.StatusBadGateway, err.Error(), "")
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error":   "light_unreachable",
			"details": err.Error(),
		})
		return
	}

	appendAuditLog(req, &authzResp, "device_command_sent", http.StatusOK, "", "")

	writeJSON(w, http.StatusOK, map[string]any{
		"allowed":       true,
		"reason":        authzResp.Reason,
		"device_result": deviceResp,
	})
}

func handleReadSensor(w http.ResponseWriter, req AccessRequest, authzResp AuthzResponse) {
	sensorURL := getenv("SENSOR_URL", "http://127.0.0.1:8091") + "/reading?device_id=" + url.QueryEscape(req.DeviceID)

	var reading map[string]any
	if err := getJSON(sensorURL, &reading); err != nil {
		appendAuditLog(req, &authzResp, "sensor_unreachable", http.StatusBadGateway, err.Error(), "")
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error":   "sensor_unreachable",
			"details": err.Error(),
		})
		return
	}

	record := map[string]any{
		"subject":      req.Subject,
		"device_id":    req.DeviceID,
		"action":       req.Action,
		"authz_reason": authzResp.Reason,
		"reading":      reading,
		"persisted_at": time.Now().UTC().Format(time.RFC3339),
	}

	sinkPath := getenv("LOCAL_SINK_FILE", "../../testdata/data/local-sink.ndjson")
	if err := appendNDJSON(sinkPath, record); err != nil {
		appendAuditLog(req, &authzResp, "local_sink_write_failed", http.StatusInternalServerError, err.Error(), sinkPath)
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error":   "local_sink_write_failed",
			"details": err.Error(),
		})
		return
	}

	appendAuditLog(req, &authzResp, "data_persisted", http.StatusOK, "", sinkPath)

	writeJSON(w, http.StatusOK, map[string]any{
		"allowed":       true,
		"reason":        authzResp.Reason,
		"device_result": reading,
		"persisted_to":  sinkPath,
	})
}

func postJSON(endpoint string, in any, out any) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	setServiceAuthHeader(req)

	resp, err := http.DefaultClient.Do(req)
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
		return fmt.Errorf("decode response: %w", err)
	}

	return nil
}

func getJSON(endpoint string, out any) error {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	setServiceAuthHeader(req)

	resp, err := http.DefaultClient.Do(req)
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
		return fmt.Errorf("decode response: %w", err)
	}

	return nil
}

func appendNDJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}

	if _, err := f.Write(raw); err != nil {
		return err
	}
	if _, err := f.Write([]byte("\n")); err != nil {
		return err
	}

	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func serviceAuthMiddleware(next http.Handler) http.Handler {
	token := os.Getenv("SERVICE_AUTH_TOKEN")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Blackwall-Service-Token") != token {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "service_auth_required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func setServiceAuthHeader(req *http.Request) {
	req.Header.Set("X-Blackwall-Service-Token", os.Getenv("SERVICE_AUTH_TOKEN"))
}

func requireEnv(key string) {
	if os.Getenv(key) == "" {
		log.Fatalf("%s must be set", key)
	}
}

func randomHex(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func (s *ChallengeStore) Put(challenge string, record ChallengeRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.deleteExpiredLocked(time.Now().UTC())
	s.challenges[challenge] = record
}

func (s *ChallengeStore) Consume(req AccessRequest) string {
	if req.Challenge == "" {
		return "presentation_challenge_required"
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	s.deleteExpiredLocked(now)

	record, ok := s.challenges[req.Challenge]
	if !ok {
		return "challenge_replayed_or_unknown"
	}
	delete(s.challenges, req.Challenge)

	if now.After(record.ExpiresAt) {
		return "challenge_expired"
	}
	if record.Subject != req.Subject {
		return "challenge_subject_mismatch"
	}
	if record.DeviceID != req.DeviceID {
		return "challenge_device_mismatch"
	}
	if record.Action != req.Action {
		return "challenge_action_mismatch"
	}
	if req.Presentation == nil || req.Presentation.Proof == nil {
		return "presentation_proof_missing"
	}
	if req.Presentation.Proof.Challenge != req.Challenge {
		return "presentation_challenge_mismatch"
	}
	if req.Presentation.Proof.Domain != record.Domain {
		return "presentation_domain_mismatch"
	}

	return ""
}

func (s *ChallengeStore) deleteExpiredLocked(now time.Time) {
	for challenge, record := range s.challenges {
		if now.After(record.ExpiresAt) {
			delete(s.challenges, challenge)
		}
	}
}

func appendAuditLog(req AccessRequest, authzResp *AuthzResponse, outcome string, status int, errText string, persistedTo string) {
	now := time.Now().UTC()

	record := AuditRecord{
		EventID:              fmt.Sprintf("audit-%d", now.UnixNano()),
		RecordedAt:           now.Format(time.RFC3339),
		Subject:              req.Subject,
		DeviceID:             req.DeviceID,
		Action:               req.Action,
		CredentialID:         credentialID(req),
		CredentialType:       credentialType(req),
		CredentialIssuer:     credentialIssuer(req),
		CredentialSubject:    credentialSubject(req),
		DelegatedBy:          credentialDelegatedBy(req),
		ParentCredentialID:   credentialParentID(req),
		TransferredBy:        credentialTransferredBy(req),
		ReplacesCredentialID: credentialReplacesID(req),
		Outcome:              outcome,
		HTTPStatus:           status,
		Error:                errText,
		PersistedTo:          persistedTo,
	}

	if authzResp != nil {
		allow := authzResp.Allow
		record.AuthzAllow = &allow
		record.AuthzReason = authzResp.Reason
	}

	path := getenv("AUDIT_LOG_FILE", "../../testdata/audit/audit.ndjson")
	if err := appendNDJSON(path, record); err != nil {
		log.Printf("audit log write failed: %v", err)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func credentialFromRequest(req AccessRequest) *Credential {
	if req.Presentation != nil && len(req.Presentation.VerifiableCredential) > 0 {
		return &req.Presentation.VerifiableCredential[0]
	}
	return nil
}

func credentialID(req AccessRequest) string {
	if cred := credentialFromRequest(req); cred != nil {
		return cred.ID
	}
	return ""
}

func credentialIssuer(req AccessRequest) string {
	if cred := credentialFromRequest(req); cred != nil {
		return cred.Issuer
	}
	return ""
}

func credentialSubject(req AccessRequest) string {
	if cred := credentialFromRequest(req); cred != nil {
		return cred.CredentialSubject.ID
	}
	return ""
}

func credentialDelegatedBy(req AccessRequest) string {
	if cred := credentialFromRequest(req); cred != nil {
		return cred.CredentialSubject.DelegatedBy
	}
	return ""
}

func credentialParentID(req AccessRequest) string {
	if cred := credentialFromRequest(req); cred != nil {
		return cred.CredentialSubject.ParentCredentialID
	}
	return ""
}

func credentialTransferredBy(req AccessRequest) string {
	if cred := credentialFromRequest(req); cred != nil {
		return cred.CredentialSubject.TransferredBy
	}
	return ""
}

func credentialReplacesID(req AccessRequest) string {
	if cred := credentialFromRequest(req); cred != nil {
		return cred.CredentialSubject.ReplacesCredentialID
	}
	return ""
}

func credentialType(req AccessRequest) string {
	cred := credentialFromRequest(req)
	if cred == nil {
		return ""
	}
	for _, t := range cred.Type {
		if t != "VerifiableCredential" {
			return t
		}
	}
	return ""
}
