package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestOwnerCredentialHandlerIssuesAndPersistsCredential(t *testing.T) {
	setupIssuerTest(t)

	body := OwnerCredentialRequest{
		Subject:      testActorDID("alice"),
		Gateway:      "gateway-home-1",
		DeviceScopes: []string{"lock-front-door"},
		ActionScopes: []string{"unlock"},
	}
	rec := postIssuerJSON(t, "/credentials/owner", body, ownerCredentialHandler, true)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var cred Credential
	if err := json.Unmarshal(rec.Body.Bytes(), &cred); err != nil {
		t.Fatalf("decode credential: %v", err)
	}
	if !hasType(cred, "OwnerCredential") {
		t.Fatalf("credential type = %v, want OwnerCredential", cred.Type)
	}
	if cred.Proof == nil || !verifySignature(cred) {
		t.Fatalf("issued credential proof did not verify")
	}
	if _, err := loadCredential(cred.ID); err != nil {
		t.Fatalf("credential was not persisted: %v", err)
	}
}

func TestDelegationHandlerRejectsBadOwnerPresentation(t *testing.T) {
	setupIssuerTest(t)

	holderDID, holderKey := testActor("alice")
	owner := testSignedOwnerCredential(holderDID)
	challenge := "issuer-challenge"
	if err := saveIssuerChallenge(challenge, credentialChallengeRecord{
		Subject:   holderDID,
		Operation: "delegation",
		Domain:    configuredIssuerDID,
		ExpiresAt: time.Now().UTC().Add(time.Minute),
	}); err != nil {
		t.Fatalf("save issuer challenge: %v", err)
	}

	presentation := testOwnerPresentation(holderDID, holderKey, owner, challenge, configuredIssuerDID)
	presentation.Proof.ProofValue = "00" + presentation.Proof.ProofValue[2:]

	body := DelegationCredentialRequest{
		DelegatedBy:       holderDID,
		Subject:           testActorDID("bob"),
		Gateway:           "gateway-home-1",
		DeviceScopes:      []string{"lock-front-door"},
		ActionScopes:      []string{"unlock"},
		TTLMinutes:        30,
		Challenge:         challenge,
		OwnerPresentation: presentation,
	}
	rec := postIssuerJSON(t, "/credentials/delegation", body, delegationCredentialHandler, false)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	assertIssuerError(t, rec.Body.Bytes(), "bad_presentation_signature")
}

func setupIssuerTest(t *testing.T) {
	t.Helper()

	t.Setenv("OWNER_ISSUANCE_TOKEN", "owner-token")
	issuerSigningKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	configuredIssuerDID = didKeyFromPublicKey(issuerSigningKey.Public().(ed25519.PublicKey))
	issuerVerificationMethod = configuredIssuerDID + "#key-1"

	oldDB := issuerDB
	db, err := openIssuerDB(filepath.Join(t.TempDir(), "issuer.db"))
	if err != nil {
		t.Fatalf("open issuer db: %v", err)
	}
	issuerDB = db

	t.Cleanup(func() {
		_ = issuerDB.Close()
		issuerDB = oldDB
	})
}

func postIssuerJSON(t *testing.T, path string, body any, handler http.HandlerFunc, ownerToken bool) *httptest.ResponseRecorder {
	t.Helper()

	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if ownerToken {
		req.Header.Set("X-Blackwall-Owner-Issuance-Token", "owner-token")
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func testSignedOwnerCredential(subject string) Credential {
	now := time.Now().UTC()
	cred := newCredential(
		"OwnerCredential",
		subject,
		"gateway-home-1",
		[]string{"lock-front-door"},
		[]string{"unlock"},
		now.Add(-time.Minute),
		now.Add(time.Hour),
	)
	cred.Proof = signCredential(cred, now)
	return cred
}

func testOwnerPresentation(subject string, key ed25519.PrivateKey, cred Credential, challenge, domain string) VerifiablePresentation {
	now := time.Now().UTC()
	vp := VerifiablePresentation{
		Context:              []string{"https://www.w3.org/ns/credentials/v2"},
		ID:                   "urn:uuid:test-vp",
		Type:                 []string{"VerifiablePresentation"},
		Holder:               subject,
		VerifiableCredential: []Credential{cred},
	}
	signature := ed25519.Sign(key, presentationSigningInput(vp))
	vp.Proof = &PresentationProof{
		Type:               "DataIntegrityProof",
		Cryptosuite:        "eddsa-rdfc-2022",
		Created:            now.Format(time.RFC3339),
		VerificationMethod: subject + "#key-1",
		ProofPurpose:       "authentication",
		Challenge:          challenge,
		Domain:             domain,
		ProofValue:         hex.EncodeToString(signature),
	}
	return vp
}

func testActorDID(name string) string {
	did, _ := testActor(name)
	return did
}

func testActor(name string) (string, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte("blackwall-issuer-test:" + name))
	key := ed25519.NewKeyFromSeed(seed[:])
	return didKeyFromPublicKey(key.Public().(ed25519.PublicKey)), key
}

func assertIssuerError(t *testing.T, raw []byte, want string) {
	t.Helper()

	var out struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode response: %v body=%s", err, string(raw))
	}
	if out.Error != want {
		t.Fatalf("error = %q, want %q; body=%s", out.Error, want, string(raw))
	}
}
