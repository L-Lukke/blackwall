package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const challengeTTL = 5 * time.Minute

var gatewayDB *sql.DB

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

	var err error
	gatewayDB, err = openGatewayDB(gatewayDBPath())
	if err != nil {
		log.Fatalf("open gateway db: %v", err)
	}
	defer gatewayDB.Close()

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
	if err := saveAccessChallenge(challenge, ChallengeRecord{
		Subject:   req.Subject,
		DeviceID:  req.DeviceID,
		Action:    req.Action,
		Domain:    domain,
		ExpiresAt: expiresAt,
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "challenge_store_failed"})
		return
	}

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
	if reason := consumeAccessChallenge(req); reason != "" {
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

	eventID := appendAuditLog(req, &authzResp, "device_command_sent", http.StatusOK, "", "")
	if err := saveDeviceExecution(eventID, req, deviceResp, "ok"); err != nil {
		log.Printf("device execution write failed: %v", err)
	}

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

	eventID := appendAuditLog(req, &authzResp, "device_command_sent", http.StatusOK, "", "")
	if err := saveDeviceExecution(eventID, req, deviceResp, "ok"); err != nil {
		log.Printf("device execution write failed: %v", err)
	}

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

	eventID := appendAuditLog(req, &authzResp, "data_persisted", http.StatusOK, "", gatewayDBPath()+"#sensor_readings")
	if err := saveSensorReading(eventID, req, authzResp, reading); err != nil {
		appendAuditLog(req, &authzResp, "sensor_reading_write_failed", http.StatusInternalServerError, err.Error(), gatewayDBPath()+"#sensor_readings")
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error":   "sensor_reading_write_failed",
			"details": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"allowed":       true,
		"reason":        authzResp.Reason,
		"device_result": reading,
		"persisted_to":  gatewayDBPath() + "#sensor_readings",
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

func openGatewayDB(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", path+"?_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec(gatewaySchema); err != nil {
		_ = db.Close()
		return nil, err
	}

	return db, nil
}

const gatewaySchema = `
CREATE TABLE IF NOT EXISTS access_challenges (
	challenge TEXT PRIMARY KEY,
	subject TEXT NOT NULL,
	device_id TEXT NOT NULL,
	action TEXT NOT NULL,
	domain TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	created_at TEXT NOT NULL,
	consumed_at TEXT,
	consumption_result TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_access_challenges_unconsumed
ON access_challenges(challenge)
WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS audit_events (
	event_id TEXT PRIMARY KEY,
	recorded_at TEXT NOT NULL,
	subject TEXT,
	device_id TEXT,
	action TEXT,
	credential_id TEXT,
	outcome TEXT NOT NULL,
	http_status INTEGER NOT NULL,
	error TEXT,
	raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_attempts (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	event_id TEXT NOT NULL UNIQUE REFERENCES audit_events(event_id) ON DELETE CASCADE,
	recorded_at TEXT NOT NULL,
	subject TEXT,
	device_id TEXT,
	action TEXT,
	credential_id TEXT,
	authz_allow INTEGER,
	authz_reason TEXT,
	outcome TEXT NOT NULL,
	http_status INTEGER NOT NULL,
	error TEXT
);

CREATE TABLE IF NOT EXISTS device_executions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	event_id TEXT NOT NULL REFERENCES audit_events(event_id) ON DELETE CASCADE,
	recorded_at TEXT NOT NULL,
	device_id TEXT NOT NULL,
	action TEXT NOT NULL,
	request_json TEXT NOT NULL,
	response_json TEXT NOT NULL,
	outcome TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sensor_readings (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	event_id TEXT NOT NULL REFERENCES audit_events(event_id) ON DELETE CASCADE,
	recorded_at TEXT NOT NULL,
	subject TEXT NOT NULL,
	device_id TEXT NOT NULL,
	action TEXT NOT NULL,
	authz_reason TEXT NOT NULL,
	reading_json TEXT NOT NULL
);
`

func saveAccessChallenge(challenge string, record ChallengeRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := gatewayDB.Exec(`
		INSERT INTO access_challenges (
			challenge, subject, device_id, action, domain, expires_at, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`, challenge, record.Subject, record.DeviceID, record.Action, record.Domain, record.ExpiresAt.Format(time.RFC3339), now)
	return err
}

func consumeAccessChallenge(req AccessRequest) string {
	if req.Challenge == "" {
		return "presentation_challenge_required"
	}

	tx, err := gatewayDB.Begin()
	if err != nil {
		return "challenge_store_unavailable"
	}
	defer tx.Rollback()

	var record ChallengeRecord
	var consumedAt sql.NullString
	row := tx.QueryRow(`
		SELECT subject, device_id, action, domain, expires_at, consumed_at
		FROM access_challenges
		WHERE challenge = ?
	`, req.Challenge)
	var expiresAt string
	if err := row.Scan(&record.Subject, &record.DeviceID, &record.Action, &record.Domain, &expiresAt, &consumedAt); err != nil {
		if err == sql.ErrNoRows {
			return "challenge_replayed_or_unknown"
		}
		return "challenge_store_unavailable"
	}
	if consumedAt.Valid {
		return "challenge_replayed_or_unknown"
	}
	parsedExpiry, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return "challenge_bad_expiry"
	}
	record.ExpiresAt = parsedExpiry

	reason := validateConsumedChallenge(req, record)
	result := "accepted"
	if reason != "" {
		result = reason
	}

	res, err := tx.Exec(`
		UPDATE access_challenges
		SET consumed_at = ?, consumption_result = ?
		WHERE challenge = ? AND consumed_at IS NULL
	`, time.Now().UTC().Format(time.RFC3339), result, req.Challenge)
	if err != nil {
		return "challenge_store_unavailable"
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return "challenge_store_unavailable"
	}
	if rows != 1 {
		return "challenge_replayed_or_unknown"
	}
	if err := tx.Commit(); err != nil {
		return "challenge_store_unavailable"
	}

	return reason
}

func validateConsumedChallenge(req AccessRequest, record ChallengeRecord) string {
	now := time.Now().UTC()
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

func saveDeviceExecution(eventID string, req AccessRequest, response map[string]any, outcome string) error {
	requestJSON, err := json.Marshal(DeviceCommand{DeviceID: req.DeviceID})
	if err != nil {
		return err
	}
	responseJSON, err := json.Marshal(response)
	if err != nil {
		return err
	}
	_, err = gatewayDB.Exec(`
		INSERT INTO device_executions (
			event_id, recorded_at, device_id, action, request_json, response_json, outcome
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`, eventID, time.Now().UTC().Format(time.RFC3339), req.DeviceID, req.Action, string(requestJSON), string(responseJSON), outcome)
	return err
}

func saveSensorReading(eventID string, req AccessRequest, authzResp AuthzResponse, reading map[string]any) error {
	readingJSON, err := json.Marshal(reading)
	if err != nil {
		return err
	}
	_, err = gatewayDB.Exec(`
		INSERT INTO sensor_readings (
			event_id, recorded_at, subject, device_id, action, authz_reason, reading_json
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`, eventID, time.Now().UTC().Format(time.RFC3339), req.Subject, req.DeviceID, req.Action, authzResp.Reason, string(readingJSON))
	return err
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

func appendAuditLog(req AccessRequest, authzResp *AuthzResponse, outcome string, status int, errText string, persistedTo string) string {
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

	if err := saveAuditRecord(record); err != nil {
		log.Printf("audit log write failed: %v", err)
	}
	return record.EventID
}

func saveAuditRecord(record AuditRecord) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}

	tx, err := gatewayDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		INSERT INTO audit_events (
			event_id, recorded_at, subject, device_id, action, credential_id,
			outcome, http_status, error, raw_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, record.EventID, record.RecordedAt, record.Subject, record.DeviceID, record.Action, record.CredentialID, record.Outcome, record.HTTPStatus, record.Error, string(raw))
	if err != nil {
		return err
	}

	var authzAllow any
	if record.AuthzAllow != nil {
		if *record.AuthzAllow {
			authzAllow = 1
		} else {
			authzAllow = 0
		}
	}
	_, err = tx.Exec(`
		INSERT INTO access_attempts (
			event_id, recorded_at, subject, device_id, action, credential_id,
			authz_allow, authz_reason, outcome, http_status, error
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, record.EventID, record.RecordedAt, record.Subject, record.DeviceID, record.Action, record.CredentialID, authzAllow, record.AuthzReason, record.Outcome, record.HTTPStatus, record.Error)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func gatewayDBPath() string {
	return getenv("GATEWAY_DB_PATH", "../../runtime/gateway/gateway.db")
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
