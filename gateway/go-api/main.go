package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
)

type Proof struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Credential struct {
	ID                 string   `json:"id"`
	Type               string   `json:"type"`
	Issuer             string   `json:"issuer"`
	Subject            string   `json:"subject"`
	Gateway            string   `json:"gateway"`
	DeviceScopes       []string `json:"device_scopes"`
	ActionScopes       []string `json:"action_scopes"`
	DelegatedBy        string   `json:"delegated_by,omitempty"`
	ParentCredentialID string   `json:"parent_credential_id,omitempty"`
	IssuedAt           string   `json:"issued_at"`
	ExpiresAt          string   `json:"expires_at"`
	Status             string   `json:"status"`
	Proof              Proof    `json:"proof"`
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
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}

	var req AccessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_json"})
		return
	}

	var authzResp AuthzResponse
	if err := postJSON(getenv("AUTHZ_URL", "http://localhost:8081/v1/authorize"), req, &authzResp); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "authz_unreachable", "details": err.Error()})
		return
	}

	if !authzResp.Allow {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"allowed": false,
			"reason":  authzResp.Reason,
		})
		return
	}

	switch req.Action {
	case "unlock", "lock":
		deviceURL := getenv("LOCK_URL", "http://localhost:8090") + "/" + req.Action
		var deviceResp map[string]any
		if err := postJSON(deviceURL, DeviceCommand{DeviceID: req.DeviceID}, &deviceResp); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": "device_unreachable", "details": err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"allowed":       true,
			"reason":        authzResp.Reason,
			"device_result": deviceResp,
		})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "unsupported_action_for_v1",
		})
	}
}

func postJSON(url string, in any, out any) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return json.NewDecoder(resp.Body).Decode(out)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}