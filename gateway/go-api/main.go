package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type Proof struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Credential struct {
	ID                   string   `json:"id"`
	Type                 string   `json:"type"`
	Issuer               string   `json:"issuer"`
	Subject              string   `json:"subject"`
	Gateway              string   `json:"gateway"`
	DeviceScopes         []string `json:"device_scopes"`
	ActionScopes         []string `json:"action_scopes"`
	DelegatedBy          string   `json:"delegated_by,omitempty"`
	ParentCredentialID   string   `json:"parent_credential_id,omitempty"`
	TransferredBy        string   `json:"transferred_by,omitempty"`
	ReplacesCredentialID string   `json:"replaces_credential_id,omitempty"`
	IssuedAt             string   `json:"issued_at"`
	ExpiresAt            string   `json:"expires_at"`
	Status               string   `json:"status"`
	Proof                Proof    `json:"proof"`
}

type AccessRequest struct {
	Subject    string     `json:"subject"`
	DeviceID   string     `json:"device_id"`
	Action     string     `json:"action"`
	Credential Credential `json:"credential"`
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
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/access/request", accessRequestHandler)

	addr := getenv("GATEWAY_ADDR", ":8080")
	log.Printf("go-api listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func accessRequestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		appendAuditLog(AccessRequest{}, nil, "method_not_allowed", http.StatusMethodNotAllowed, "method_not_allowed", "")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}

	var req AccessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		appendAuditLog(AccessRequest{}, nil, "bad_json", http.StatusBadRequest, err.Error(), "")
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_json"})
		return
	}

	var authzResp AuthzResponse
	if err := postJSON(
		getenv("AUTHZ_URL", "http://localhost:8081/v1/authorize"),
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
	deviceURL := getenv("LOCK_URL", "http://localhost:8090") + "/" + req.Action

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
	deviceURL := getenv("LIGHT_URL", "http://localhost:8092") + "/" + req.Action

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
	sensorURL := getenv("SENSOR_URL", "http://localhost:8091") + "/reading?device_id=" + url.QueryEscape(req.DeviceID)

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

func appendAuditLog(req AccessRequest, authzResp *AuthzResponse, outcome string, status int, errText string, persistedTo string) {
	now := time.Now().UTC()

	record := AuditRecord{
		EventID:              fmt.Sprintf("audit-%d", now.UnixNano()),
		RecordedAt:           now.Format(time.RFC3339),
		Subject:              req.Subject,
		DeviceID:             req.DeviceID,
		Action:               req.Action,
		CredentialID:         req.Credential.ID,
		CredentialType:       req.Credential.Type,
		CredentialIssuer:     req.Credential.Issuer,
		CredentialSubject:    req.Credential.Subject,
		DelegatedBy:          req.Credential.DelegatedBy,
		ParentCredentialID:   req.Credential.ParentCredentialID,
		TransferredBy:        req.Credential.TransferredBy,
		ReplacesCredentialID: req.Credential.ReplacesCredentialID,
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
