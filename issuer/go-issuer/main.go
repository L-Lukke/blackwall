package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

type Proof struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Credential struct {
	ID           string   `json:"id"`
	Type         string   `json:"type"`
	Issuer       string   `json:"issuer"`
	Subject      string   `json:"subject"`
	Gateway      string   `json:"gateway"`
	DeviceScopes []string `json:"device_scopes"`
	ActionScopes []string `json:"action_scopes"`
	IssuedAt     string   `json:"issued_at"`
	ExpiresAt    string   `json:"expires_at"`
	Status       string   `json:"status"`
	Proof        Proof    `json:"proof"`
}

type OwnerCredentialRequest struct {
	Subject      string   `json:"subject"`
	Gateway      string   `json:"gateway"`
	DeviceScopes []string `json:"device_scopes"`
	ActionScopes []string `json:"action_scopes"`
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/credentials/owner", ownerCredentialHandler)

	addr := getenv("ISSUER_ADDR", ":8082")
	log.Printf("go-issuer listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func ownerCredentialHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}

	var req OwnerCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_json"})
		return
	}

	if req.Subject == "" || req.Gateway == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "subject_and_gateway_required"})
		return
	}

	now := time.Now().UTC()
	cred := Credential{
		ID:           fmt.Sprintf("cred-%d", now.UnixNano()),
		Type:         "OwnerCredential",
		Issuer:       getenv("ISSUER_DID", "did:example:issuer"),
		Subject:      req.Subject,
		Gateway:      req.Gateway,
		DeviceScopes: req.DeviceScopes,
		ActionScopes: req.ActionScopes,
		IssuedAt:     now.Format(time.RFC3339),
		ExpiresAt:    now.Add(365 * 24 * time.Hour).Format(time.RFC3339),
		Status:       "active",
	}

	cred.Proof = Proof{
		Type:  "HMAC-SHA256",
		Value: sign(getenv("ISSUER_SHARED_SECRET", "dev-secret"), signingInput(cred)),
	}

	if dir := os.Getenv("SAVE_CREDENTIALS_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err == nil {
			path := fmt.Sprintf("%s/%s.json", strings.TrimRight(dir, "/"), cred.ID)
			if raw, err := json.Marshal(cred); err == nil {
				_ = os.WriteFile(path, raw, 0o644)
			}
		}
	}

	writeJSON(w, http.StatusOK, cred)
}

func signingInput(c Credential) string {
	devices := append([]string(nil), c.DeviceScopes...)
	actions := append([]string(nil), c.ActionScopes...)
	sort.Strings(devices)
	sort.Strings(actions)

	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		c.ID,
		c.Type,
		c.Issuer,
		c.Subject,
		c.Gateway,
		strings.Join(devices, ","),
		strings.Join(actions, ","),
		c.IssuedAt,
		c.ExpiresAt,
		c.Status,
	)
}

func sign(secret, data string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
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