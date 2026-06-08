package main

import (
	"crypto/ed25519"
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
	cred := newCredential("OwnerCredential", req.Subject, req.Gateway, req.DeviceScopes, req.ActionScopes, now, now.Add(365*24*time.Hour))
	cred.Proof = signCredential(cred, now)

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
	if !hasType(owner, "OwnerCredential") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_required"})
		return
	}
	if owner.CredentialSubject.ID != req.DelegatedBy {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_subject_mismatch"})
		return
	}
	if owner.CredentialSubject.Gateway != req.Gateway {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "gateway_mismatch"})
		return
	}
	if owner.CredentialStatus.Status != "active" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_not_active"})
		return
	}
	if !verifySignature(owner) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_bad_signature"})
		return
	}
	if !isSubset(req.DeviceScopes, owner.CredentialSubject.DeviceScopes) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "device_scopes_not_subset_of_owner"})
		return
	}
	if !isSubset(req.ActionScopes, owner.CredentialSubject.ActionScopes) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "action_scopes_not_subset_of_owner"})
		return
	}

	ownerExpiry, err := time.Parse(time.RFC3339, owner.ValidUntil)
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

	cred := newCredential("DelegationCredential", req.Subject, req.Gateway, req.DeviceScopes, req.ActionScopes, now, expiresAt)
	cred.CredentialSubject.DelegatedBy = req.DelegatedBy
	cred.CredentialSubject.ParentCredentialID = owner.ID
	cred.Proof = signCredential(cred, now)

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
	if !hasType(owner, "OwnerCredential") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_required"})
		return
	}
	if owner.CredentialSubject.ID != req.RevokedBy {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_subject_mismatch"})
		return
	}
	if owner.CredentialStatus.Status != "active" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_not_active"})
		return
	}
	if !verifySignature(owner) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_bad_signature"})
		return
	}

	ownerExpiry, err := time.Parse(time.RFC3339, owner.ValidUntil)
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
	if !hasType(owner, "OwnerCredential") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_required"})
		return
	}
	if owner.CredentialSubject.ID != req.TransferredBy {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_subject_mismatch"})
		return
	}
	if owner.CredentialSubject.Gateway != req.Gateway {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "gateway_mismatch"})
		return
	}
	if owner.CredentialStatus.Status != "active" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_not_active"})
		return
	}
	if !verifySignature(owner) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_credential_bad_signature"})
		return
	}

	ownerExpiry, err := time.Parse(time.RFC3339, owner.ValidUntil)
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

	deviceScopes := owner.CredentialSubject.DeviceScopes
	actionScopes := owner.CredentialSubject.ActionScopes

	if len(req.DeviceScopes) > 0 {
		if !isSubset(req.DeviceScopes, owner.CredentialSubject.DeviceScopes) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "device_scopes_not_subset_of_owner"})
			return
		}
		deviceScopes = req.DeviceScopes
	}
	if len(req.ActionScopes) > 0 {
		if !isSubset(req.ActionScopes, owner.CredentialSubject.ActionScopes) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "action_scopes_not_subset_of_owner"})
			return
		}
		actionScopes = req.ActionScopes
	}

	newCred := newCredential("OwnerCredential", req.NewSubject, req.Gateway, deviceScopes, actionScopes, now, ownerExpiry)
	newCred.CredentialSubject.TransferredBy = req.TransferredBy
	newCred.CredentialSubject.ReplacesCredentialID = owner.ID
	newCred.Proof = signCredential(newCred, now)

	revocations.RevokedIDs = appendUnique(revocations.RevokedIDs, owner.ID)
	sort.Strings(revocations.RevokedIDs)

	if err := saveRevocations(path, revocations); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "revocation_file_write_failed"})
		return
	}

	saveCredential(newCred)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                    true,
		"revoked_credential_id": owner.ID,
		"new_owner_credential":  newCred,
	})
}

func newCredential(kind, subject, gateway string, deviceScopes, actionScopes []string, validFrom, validUntil time.Time) Credential {
	id := fmt.Sprintf("urn:uuid:cred-%d", validFrom.UnixNano())
	return Credential{
		Context: []string{
			"https://www.w3.org/ns/credentials/v2",
			"https://blackwall.local/contexts/smart-home-authorization/v1",
		},
		ID:         id,
		Type:       []string{"VerifiableCredential", kind},
		Issuer:     getenv("ISSUER_DID", defaultIssuerDID()),
		ValidFrom:  validFrom.Format(time.RFC3339),
		ValidUntil: validUntil.Format(time.RFC3339),
		CredentialSubject: CredentialSubject{
			ID:           subject,
			Gateway:      gateway,
			DeviceScopes: deviceScopes,
			ActionScopes: actionScopes,
		},
		CredentialStatus: CredentialStatus{
			ID:            id + "#status",
			Type:          "BlackwallRevocationStatus2026",
			StatusPurpose: "revocation",
			Status:        "active",
		},
	}
}

func signingInput(c Credential) []byte {
	c.Proof = nil
	raw, err := json.Marshal(c)
	if err != nil {
		return nil
	}
	return raw
}

func signCredential(cred Credential, now time.Time) *Proof {
	privateKey := issuerPrivateKey()
	signature := ed25519.Sign(privateKey, signingInput(cred))
	issuerDID := getenv("ISSUER_DID", defaultIssuerDID())
	return &Proof{
		Type:               "DataIntegrityProof",
		Cryptosuite:        "eddsa-rdfc-2022",
		Created:            now.Format(time.RFC3339),
		VerificationMethod: getenv("ISSUER_VERIFICATION_METHOD", issuerDID+"#key-1"),
		ProofPurpose:       "assertionMethod",
		ProofValue:         hex.EncodeToString(signature),
	}
}

func verifySignature(cred Credential) bool {
	if cred.Proof == nil {
		return false
	}
	signature, err := hex.DecodeString(cred.Proof.ProofValue)
	if err != nil {
		return false
	}
	return ed25519.Verify(issuerPublicKey(), signingInput(cred), signature)
}

func issuerPrivateKey() ed25519.PrivateKey {
	if rawHex := os.Getenv("ISSUER_ED25519_PRIVATE_KEY_HEX"); rawHex != "" {
		raw, err := hex.DecodeString(rawHex)
		if err == nil && len(raw) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(raw)
		}
		if err == nil && len(raw) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(raw)
		}
	}
	return ed25519.NewKeyFromSeed(defaultIssuerEd25519Seed())
}

func issuerPublicKey() ed25519.PublicKey {
	if rawHex := os.Getenv("ISSUER_ED25519_PUBLIC_KEY_HEX"); rawHex != "" {
		raw, err := hex.DecodeString(rawHex)
		if err == nil && len(raw) == ed25519.PublicKeySize {
			return ed25519.PublicKey(raw)
		}
	}
	return issuerPrivateKey().Public().(ed25519.PublicKey)
}

func defaultIssuerEd25519Seed() []byte {
	seed, _ := hex.DecodeString("298754db2dbab6ec62605ceb0379eb7ee376580359449efe0caa3aa06cd56736")
	return seed
}

func defaultIssuerDID() string {
	return didKeyFromPublicKey(issuerPublicKey())
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

func hasType(cred Credential, kind string) bool {
	for _, t := range cred.Type {
		if t == kind {
			return true
		}
	}
	return false
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
