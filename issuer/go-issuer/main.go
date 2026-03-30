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
	"path/filepath"
	"sort"
	"strings"
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

type Revocations struct {
	RevokedIDs []string `json:"revoked_ids"`
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/credentials/owner", ownerCredentialHandler)
	mux.HandleFunc("/credentials/delegation", delegationCredentialHandler)
	mux.HandleFunc("/credentials/revoke", revokeCredentialHandler)
	mux.HandleFunc("/credentials/transfer", transferOwnershipHandler)

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
	if len(req.DeviceScopes) == 0 || len(req.ActionScopes) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "device_scopes_and_action_scopes_required"})
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

	saveCredential(cred)
	writeJSON(w, http.StatusOK, cred)
}

func delegationCredentialHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}

	var req DelegationCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_json"})
		return
	}

	if req.DelegatedBy == "" || req.Subject == "" || req.Gateway == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "delegated_by_subject_and_gateway_required"})
		return
	}
	if len(req.DeviceScopes) == 0 || len(req.ActionScopes) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "device_scopes_and_action_scopes_required"})
		return
	}

	owner := req.OwnerCredential
	secret := getenv("ISSUER_SHARED_SECRET", "dev-secret")

	if owner.Type != "OwnerCredential" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_required"})
		return
	}
	if owner.Subject != req.DelegatedBy {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_subject_mismatch"})
		return
	}
	if owner.Gateway != req.Gateway {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "gateway_mismatch"})
		return
	}
	if owner.Status != "active" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_not_active"})
		return
	}
	if !verifySignature(secret, owner) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_bad_signature"})
		return
	}
	if !isSubset(req.DeviceScopes, owner.DeviceScopes) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "device_scopes_not_subset_of_owner"})
		return
	}
	if !isSubset(req.ActionScopes, owner.ActionScopes) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "action_scopes_not_subset_of_owner"})
		return
	}

	ownerExpiry, err := time.Parse(time.RFC3339, owner.ExpiresAt)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_bad_expiry"})
		return
	}

	now := time.Now().UTC()
	if now.After(ownerExpiry) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_expired"})
		return
	}

	ttlMinutes := req.TTLMinutes
	if ttlMinutes <= 0 {
		ttlMinutes = 120
	}

	expiresAt := now.Add(time.Duration(ttlMinutes) * time.Minute)
	if expiresAt.After(ownerExpiry) {
		expiresAt = ownerExpiry
	}

	cred := Credential{
		ID:                 fmt.Sprintf("cred-%d", now.UnixNano()),
		Type:               "DelegationCredential",
		Issuer:             getenv("ISSUER_DID", "did:example:issuer"),
		Subject:            req.Subject,
		Gateway:            req.Gateway,
		DeviceScopes:       req.DeviceScopes,
		ActionScopes:       req.ActionScopes,
		DelegatedBy:        req.DelegatedBy,
		ParentCredentialID: owner.ID,
		IssuedAt:           now.Format(time.RFC3339),
		ExpiresAt:          expiresAt.Format(time.RFC3339),
		Status:             "active",
	}
	cred.Proof = Proof{
		Type:  "HMAC-SHA256",
		Value: sign(secret, signingInput(cred)),
	}

	saveCredential(cred)
	writeJSON(w, http.StatusOK, cred)
}

func revokeCredentialHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}

	var req RevokeCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_json"})
		return
	}

	if req.CredentialID == "" || req.RevokedBy == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "credential_id_and_revoked_by_required"})
		return
	}

	owner := req.OwnerCredential
	secret := getenv("ISSUER_SHARED_SECRET", "dev-secret")

	if owner.Type != "OwnerCredential" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_required"})
		return
	}
	if owner.Subject != req.RevokedBy {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_subject_mismatch"})
		return
	}
	if owner.Status != "active" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_not_active"})
		return
	}
	if !verifySignature(secret, owner) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_bad_signature"})
		return
	}

	ownerExpiry, err := time.Parse(time.RFC3339, owner.ExpiresAt)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_bad_expiry"})
		return
	}
	if time.Now().UTC().After(ownerExpiry) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_expired"})
		return
	}

	path := getenv("REVOCATION_FILE", "../../testdata/revocations/revoked_ids.json")
	revocations, err := loadRevocations(path)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "revocation_file_load_failed"})
		return
	}

	if !contains(revocations.RevokedIDs, req.CredentialID) {
		revocations.RevokedIDs = append(revocations.RevokedIDs, req.CredentialID)
		sort.Strings(revocations.RevokedIDs)
	}

	if err := saveRevocations(path, revocations); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "revocation_file_write_failed"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"credential_id": req.CredentialID,
		"revoked_by":    req.RevokedBy,
		"revoked_ids":   revocations.RevokedIDs,
	})
}

func transferOwnershipHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}

	var req TransferOwnershipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_json"})
		return
	}

	if req.TransferredBy == "" || req.NewSubject == "" || req.Gateway == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "transferred_by_new_subject_and_gateway_required"})
		return
	}
	if req.TransferredBy == req.NewSubject {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "self_transfer_not_allowed"})
		return
	}

	owner := req.OwnerCredential
	secret := getenv("ISSUER_SHARED_SECRET", "dev-secret")

	if owner.Type != "OwnerCredential" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_required"})
		return
	}
	if owner.Subject != req.TransferredBy {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_subject_mismatch"})
		return
	}
	if owner.Gateway != req.Gateway {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "gateway_mismatch"})
		return
	}
	if owner.Status != "active" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_not_active"})
		return
	}
	if !verifySignature(secret, owner) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_bad_signature"})
		return
	}

	ownerExpiry, err := time.Parse(time.RFC3339, owner.ExpiresAt)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_bad_expiry"})
		return
	}
	now := time.Now().UTC()
	if now.After(ownerExpiry) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_expired"})
		return
	}

	path := getenv("REVOCATION_FILE", "../../testdata/revocations/revoked_ids.json")
	revocations, err := loadRevocations(path)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "revocation_file_load_failed"})
		return
	}
	if contains(revocations.RevokedIDs, owner.ID) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_already_revoked"})
		return
	}

	deviceScopes := owner.DeviceScopes
	actionScopes := owner.ActionScopes

	if len(req.DeviceScopes) > 0 {
		if !isSubset(req.DeviceScopes, owner.DeviceScopes) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "device_scopes_not_subset_of_owner"})
			return
		}
		deviceScopes = req.DeviceScopes
	}
	if len(req.ActionScopes) > 0 {
		if !isSubset(req.ActionScopes, owner.ActionScopes) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "action_scopes_not_subset_of_owner"})
			return
		}
		actionScopes = req.ActionScopes
	}

	newCred := Credential{
		ID:                  fmt.Sprintf("cred-%d", now.UnixNano()),
		Type:                "OwnerCredential",
		Issuer:              getenv("ISSUER_DID", "did:example:issuer"),
		Subject:             req.NewSubject,
		Gateway:             req.Gateway,
		DeviceScopes:        deviceScopes,
		ActionScopes:        actionScopes,
		TransferredBy:       req.TransferredBy,
		ReplacesCredentialID: owner.ID,
		IssuedAt:            now.Format(time.RFC3339),
		ExpiresAt:           ownerExpiry.Format(time.RFC3339),
		Status:              "active",
	}
	newCred.Proof = Proof{
		Type:  "HMAC-SHA256",
		Value: sign(secret, signingInput(newCred)),
	}

	revocations.RevokedIDs = appendUnique(revocations.RevokedIDs, owner.ID)
	sort.Strings(revocations.RevokedIDs)

	if err := saveRevocations(path, revocations); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "revocation_file_write_failed"})
		return
	}

	saveCredential(newCred)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                   true,
		"revoked_credential_id": owner.ID,
		"new_owner_credential": newCred,
	})
}

func signingInput(c Credential) string {
	devices := append([]string(nil), c.DeviceScopes...)
	actions := append([]string(nil), c.ActionScopes...)
	sort.Strings(devices)
	sort.Strings(actions)

	return fmt.Sprintf(
		"%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		c.ID,
		c.Type,
		c.Issuer,
		c.Subject,
		c.Gateway,
		strings.Join(devices, ","),
		strings.Join(actions, ","),
		c.DelegatedBy,
		c.ParentCredentialID,
		c.TransferredBy,
		c.ReplacesCredentialID,
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

func verifySignature(secret string, cred Credential) bool {
	expected := sign(secret, signingInput(cred))
	return hmac.Equal([]byte(expected), []byte(cred.Proof.Value))
}

func isSubset(requested, allowed []string) bool {
	if contains(allowed, "*") {
		return true
	}

	allowedSet := make(map[string]struct{}, len(allowed))
	for _, v := range allowed {
		allowedSet[v] = struct{}{}
	}

	for _, v := range requested {
		if _, ok := allowedSet[v]; !ok {
			return false
		}
	}
	return true
}

func contains(values []string, wanted string) bool {
	for _, v := range values {
		if v == wanted {
			return true
		}
	}
	return false
}

func appendUnique(values []string, wanted string) []string {
	if contains(values, wanted) {
		return values
	}
	return append(values, wanted)
}

func saveCredential(cred Credential) {
	dir := os.Getenv("SAVE_CREDENTIALS_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	path := fmt.Sprintf("%s/%s.json", strings.TrimRight(dir, "/"), cred.ID)
	raw, err := json.Marshal(cred)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, raw, 0o644)
}

func loadRevocations(path string) (Revocations, error) {
	var revocations Revocations

	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Revocations{RevokedIDs: []string{}}, nil
		}
		return revocations, err
	}

	if len(strings.TrimSpace(string(raw))) == 0 {
		return Revocations{RevokedIDs: []string{}}, nil
	}

	if err := json.Unmarshal(raw, &revocations); err != nil {
		return revocations, err
	}

	if revocations.RevokedIDs == nil {
		revocations.RevokedIDs = []string{}
	}
	return revocations, nil
}

func saveRevocations(path string, revocations Revocations) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	raw, err := json.MarshalIndent(revocations, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, raw, 0o644)
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
