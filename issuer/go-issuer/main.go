package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const challengeTTL = 5 * time.Minute

type Proof struct {
	Type               string `json:"type"`
	Cryptosuite        string `json:"cryptosuite"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	ProofValue         string `json:"proofValue"`
}

type PresentationProof struct {
	Type               string `json:"type"`
	Cryptosuite        string `json:"cryptosuite"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	Challenge          string `json:"challenge"`
	Domain             string `json:"domain"`
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

type VerifiablePresentation struct {
	Context              []string           `json:"@context"`
	ID                   string             `json:"id"`
	Type                 []string           `json:"type"`
	Holder               string             `json:"holder"`
	VerifiableCredential []Credential       `json:"verifiableCredential"`
	Proof                *PresentationProof `json:"proof,omitempty"`
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

type CredentialChallengeRequest struct {
	Subject   string `json:"subject"`
	Operation string `json:"operation"`
}

type CredentialChallengeResponse struct {
	Challenge string `json:"challenge"`
	Domain    string `json:"domain"`
	ExpiresAt string `json:"expires_at"`
}

type credentialChallengeRecord struct {
	Subject   string
	Operation string
	Domain    string
	ExpiresAt time.Time
}

type credentialChallengeStore struct {
	mu         sync.Mutex
	challenges map[string]credentialChallengeRecord
}

type Revocations struct {
	RevokedIDs []string `json:"revoked_ids"`
}

var issuerChallenges = &credentialChallengeStore{
	challenges: map[string]credentialChallengeRecord{},
}

var (
	issuerSigningKey         ed25519.PrivateKey
	configuredIssuerDID      string
	issuerVerificationMethod string
)

func main() {
	issuerSigningKey = mustLoadEd25519PrivateKey("ISSUER_ED25519_PRIVATE_KEY_HEX", "ISSUER_ED25519_SEED_HEX")
	configuredIssuerDID = getenv("ISSUER_DID", didKeyFromPublicKey(issuerSigningKey.Public().(ed25519.PublicKey)))
	issuerVerificationMethod = getenv("ISSUER_VERIFICATION_METHOD", configuredIssuerDID+"#key-1")
	requireEnv("SERVICE_AUTH_TOKEN")
	requireEnv("OWNER_ISSUANCE_TOKEN")

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/credentials/challenge", credentialChallengeHandler)
	mux.HandleFunc("/credentials/owner", ownerCredentialHandler)
	mux.HandleFunc("/credentials/delegation", delegationCredentialHandler)
	mux.HandleFunc("/credentials/revoke", revokeCredentialHandler)
	mux.HandleFunc("/credentials/transfer", transferOwnershipHandler)

	addr := getenv("ISSUER_ADDR", "127.0.0.1:8082")
	log.Printf("go-issuer listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, serviceAuthMiddleware(mux)))
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func credentialChallengeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}

	var req CredentialChallengeRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if req.Subject == "" || req.Operation == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "subject_and_operation_required"})
		return
	}
	if !validCredentialOperation(req.Operation) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_credential_operation"})
		return
	}

	challenge, err := newChallenge()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "challenge_generation_failed"})
		return
	}

	domain := configuredIssuerDID
	expiresAt := time.Now().UTC().Add(challengeTTL)
	issuerChallenges.Put(challenge, credentialChallengeRecord{
		Subject:   req.Subject,
		Operation: req.Operation,
		Domain:    domain,
		ExpiresAt: expiresAt,
	})

	writeJSON(w, http.StatusOK, CredentialChallengeResponse{
		Challenge: challenge,
		Domain:    domain,
		ExpiresAt: expiresAt.Format(time.RFC3339),
	})
}

func ownerCredentialHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	if !validOwnerIssuanceToken(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "owner_issuance_auth_required"})
		return
	}

	var req OwnerCredentialRequest
	if !decodeJSON(w, r, &req) {
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
	if !decodeJSON(w, r, &req) {
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

	owner, ok := verifiedOwnerPresentation(w, req.DelegatedBy, "delegation", req.Challenge, req.OwnerPresentation)
	if !ok {
		return
	}

	if owner.CredentialSubject.Gateway != req.Gateway {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "gateway_mismatch"})
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
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_presentation_credential_bad_expiry"})
		return
	}

	now := time.Now().UTC()
	if now.After(ownerExpiry) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_presentation_credential_expired"})
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
	if !decodeJSON(w, r, &req) {
		return
	}

	if req.CredentialID == "" || req.RevokedBy == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "credential_id_and_revoked_by_required"})
		return
	}

	owner, ok := verifiedOwnerPresentation(w, req.RevokedBy, "revocation", req.Challenge, req.OwnerPresentation)
	if !ok {
		return
	}

	ownerExpiry, err := time.Parse(time.RFC3339, owner.ValidUntil)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_presentation_credential_bad_expiry"})
		return
	}
	if time.Now().UTC().After(ownerExpiry) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_presentation_credential_expired"})
		return
	}

	target, err := loadCredential(req.CredentialID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "target_credential_not_found"})
		return
	}
	if !ownerAuthorizedOverTarget(owner, target) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "owner_not_authorized_for_target_credential"})
		return
	}
	if target.Issuer != configuredIssuerDID || !verifySignature(target) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "target_credential_bad_signature"})
		return
	}

	revocations, err := loadRevocations(revocationFile())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "revocation_file_load_failed"})
		return
	}

	if !contains(revocations.RevokedIDs, req.CredentialID) {
		revocations.RevokedIDs = append(revocations.RevokedIDs, req.CredentialID)
		sort.Strings(revocations.RevokedIDs)
	}

	if err := saveRevocations(revocationFile(), revocations); err != nil {
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
	if !decodeJSON(w, r, &req) {
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

	owner, ok := verifiedOwnerPresentation(w, req.TransferredBy, "transfer", req.Challenge, req.OwnerPresentation)
	if !ok {
		return
	}

	if owner.CredentialSubject.Gateway != req.Gateway {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "gateway_mismatch"})
		return
	}

	ownerExpiry, err := time.Parse(time.RFC3339, owner.ValidUntil)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_presentation_credential_bad_expiry"})
		return
	}
	now := time.Now().UTC()
	if now.After(ownerExpiry) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_presentation_credential_expired"})
		return
	}

	revocations, err := loadRevocations(revocationFile())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "revocation_file_load_failed"})
		return
	}
	if contains(revocations.RevokedIDs, owner.ID) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_presentation_credential_already_revoked"})
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

	if err := saveRevocations(revocationFile(), revocations); err != nil {
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

func verifiedOwnerPresentation(w http.ResponseWriter, subject, operation, challenge string, presentation VerifiablePresentation) (Credential, bool) {
	if challenge == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "presentation_challenge_required"})
		return Credential{}, false
	}

	record, ok := issuerChallenges.Consume(challenge)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "challenge_replayed_or_unknown"})
		return Credential{}, false
	}
	if time.Now().UTC().After(record.ExpiresAt) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "challenge_expired"})
		return Credential{}, false
	}
	if record.Subject != subject {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "challenge_subject_mismatch"})
		return Credential{}, false
	}
	if record.Operation != operation {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "challenge_operation_mismatch"})
		return Credential{}, false
	}

	if !contains(presentation.Type, "VerifiablePresentation") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "not_a_verifiable_presentation"})
		return Credential{}, false
	}
	if presentation.Holder != subject {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "presentation_holder_mismatch"})
		return Credential{}, false
	}
	if len(presentation.VerifiableCredential) != 1 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "presentation_must_contain_one_credential"})
		return Credential{}, false
	}
	if presentation.Proof == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "presentation_proof_missing"})
		return Credential{}, false
	}
	if presentation.Proof.Challenge != challenge {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "presentation_challenge_mismatch"})
		return Credential{}, false
	}
	if presentation.Proof.Domain != record.Domain {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "presentation_domain_mismatch"})
		return Credential{}, false
	}
	if !verifyPresentationSignature(presentation) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_presentation_signature"})
		return Credential{}, false
	}

	owner := presentation.VerifiableCredential[0]
	if !hasType(owner, "OwnerCredential") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_presentation_credential_required"})
		return Credential{}, false
	}
	if owner.CredentialSubject.ID != subject {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_subject_mismatch"})
		return Credential{}, false
	}
	if owner.CredentialStatus.Status != "active" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_presentation_credential_not_active"})
		return Credential{}, false
	}
	if owner.Issuer != configuredIssuerDID {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_presentation_credential_issuer_not_trusted"})
		return Credential{}, false
	}
	if !verifySignature(owner) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_presentation_credential_bad_signature"})
		return Credential{}, false
	}
	revocations, err := loadRevocations(revocationFile())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "revocation_file_load_failed"})
		return Credential{}, false
	}
	if contains(revocations.RevokedIDs, owner.ID) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_presentation_credential_revoked"})
		return Credential{}, false
	}

	return owner, true
}

func verifyPresentationSignature(presentation VerifiablePresentation) bool {
	proof := presentation.Proof
	if proof == nil {
		return false
	}
	if proof.Type != "DataIntegrityProof" ||
		proof.Cryptosuite != "eddsa-rdfc-2022" ||
		proof.ProofPurpose != "authentication" {
		return false
	}
	if !strings.HasPrefix(proof.VerificationMethod, presentation.Holder+"#") {
		return false
	}

	publicKey, err := didKeyVerificationKey(presentation.Holder, proof.VerificationMethod)
	if err != nil {
		return false
	}
	signature, err := hex.DecodeString(proof.ProofValue)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, presentationSigningInput(presentation), signature)
}

func presentationSigningInput(vp VerifiablePresentation) []byte {
	vp.Proof = nil
	raw, err := json.Marshal(vp)
	if err != nil {
		return nil
	}
	return raw
}

func didKeyVerificationKey(did, verificationMethod string) (ed25519.PublicKey, error) {
	if verificationMethod != did+"#key-1" {
		return nil, fmt.Errorf("verification_method_not_found")
	}

	encoded, ok := strings.CutPrefix(did, "did:key:z")
	if !ok {
		return nil, fmt.Errorf("unsupported_did_method")
	}
	decoded, err := base58Decode(encoded)
	if err != nil {
		return nil, err
	}
	if len(decoded) != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
		return nil, fmt.Errorf("unsupported_did_key_multicodec")
	}
	return ed25519.PublicKey(decoded[2:34]), nil
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
		Issuer:     configuredIssuerDID,
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
	signature := ed25519.Sign(issuerSigningKey, signingInput(cred))
	return &Proof{
		Type:               "DataIntegrityProof",
		Cryptosuite:        "eddsa-rdfc-2022",
		Created:            now.Format(time.RFC3339),
		VerificationMethod: issuerVerificationMethod,
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
	return ed25519.Verify(issuerSigningKey.Public().(ed25519.PublicKey), signingInput(cred), signature)
}

func mustLoadEd25519PrivateKey(privateKeyEnv, seedEnv string) ed25519.PrivateKey {
	if rawHex := os.Getenv(privateKeyEnv); rawHex != "" {
		raw, err := hex.DecodeString(rawHex)
		if err == nil && len(raw) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(raw)
		}
		if err == nil && len(raw) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(raw)
		}
	}
	if rawHex := os.Getenv(seedEnv); rawHex != "" {
		raw, err := hex.DecodeString(rawHex)
		if err == nil && len(raw) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(raw)
		}
	}
	log.Fatalf("%s or %s must be set to a valid Ed25519 key", privateKeyEnv, seedEnv)
	return nil
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
	dir := credentialStoreDir()
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

func loadCredential(id string) (Credential, error) {
	var cred Credential
	path := fmt.Sprintf("%s/%s.json", strings.TrimRight(credentialStoreDir(), "/"), id)
	raw, err := os.ReadFile(path)
	if err != nil {
		return cred, err
	}
	if err := json.Unmarshal(raw, &cred); err != nil {
		return cred, err
	}
	return cred, nil
}

func ownerAuthorizedOverTarget(owner, target Credential) bool {
	if owner.CredentialSubject.Gateway != target.CredentialSubject.Gateway {
		return false
	}
	if !isSubset(target.CredentialSubject.DeviceScopes, owner.CredentialSubject.DeviceScopes) {
		return false
	}
	if !isSubset(target.CredentialSubject.ActionScopes, owner.CredentialSubject.ActionScopes) {
		return false
	}
	if hasType(target, "OwnerCredential") {
		return target.ID == owner.ID
	}
	if hasType(target, "DelegationCredential") {
		return target.CredentialSubject.ParentCredentialID == owner.ID ||
			target.CredentialSubject.DelegatedBy == owner.CredentialSubject.ID
	}
	return false
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

func (s *credentialChallengeStore) Put(challenge string, record credentialChallengeRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.challenges[challenge] = record
}

func (s *credentialChallengeStore) Consume(challenge string) (credentialChallengeRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.challenges[challenge]
	if ok {
		delete(s.challenges, challenge)
	}
	return record, ok
}

func newChallenge() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func validCredentialOperation(operation string) bool {
	switch operation {
	case "delegation", "revocation", "transfer":
		return true
	default:
		return false
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_json"})
		return false
	}
	return true
}

func base58Decode(input string) ([]byte, error) {
	input = strings.TrimPrefix(input, "z")
	alphabet := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	bytes := []byte{0}

	for _, ch := range []byte(input) {
		index := strings.IndexByte(alphabet, ch)
		if index < 0 {
			return nil, fmt.Errorf("bad_base58_character")
		}

		carry := index
		for i := len(bytes) - 1; i >= 0; i-- {
			carry += int(bytes[i]) * 58
			bytes[i] = byte(carry & 0xff)
			carry >>= 8
		}

		for carry > 0 {
			bytes = append([]byte{byte(carry & 0xff)}, bytes...)
			carry >>= 8
		}
	}

	for _, ch := range []byte(input) {
		if ch != '1' {
			break
		}
		bytes = append([]byte{0}, bytes...)
	}

	return bytes, nil
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

func validOwnerIssuanceToken(r *http.Request) bool {
	return r.Header.Get("X-Blackwall-Owner-Issuance-Token") == os.Getenv("OWNER_ISSUANCE_TOKEN")
}

func revocationFile() string {
	return getenv("REVOCATION_FILE", "../../testdata/revocations/revoked_ids.json")
}

func credentialStoreDir() string {
	return getenv("SAVE_CREDENTIALS_DIR", "../../testdata/credentials")
}

func requireEnv(key string) {
	if os.Getenv(key) == "" {
		log.Fatalf("%s must be set", key)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
