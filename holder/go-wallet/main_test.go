package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestWalletStoresCredentialAndSignsChallengeBoundPresentation(t *testing.T) {
	wlt := setupWalletTest(t)

	cred := testWalletCredential(wlt.did)
	if err := wlt.storeCredential(cred); err != nil {
		t.Fatalf("store credential: %v", err)
	}

	rec := postWalletJSON(t, wlt.presentationsHandler, PresentationRequest{
		CredentialID: cred.ID,
		Challenge:    "gateway-challenge",
		Domain:       "gateway-home-1",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var vp VerifiablePresentation
	if err := json.Unmarshal(rec.Body.Bytes(), &vp); err != nil {
		t.Fatalf("decode presentation: %v", err)
	}
	if vp.Holder != wlt.did {
		t.Fatalf("holder = %q, want %q", vp.Holder, wlt.did)
	}
	if vp.Proof == nil {
		t.Fatalf("presentation proof missing")
	}
	if vp.Proof.Challenge != "gateway-challenge" || vp.Proof.Domain != "gateway-home-1" {
		t.Fatalf("proof binding = challenge %q domain %q", vp.Proof.Challenge, vp.Proof.Domain)
	}
	signature, err := hexDecodeSignature(vp.Proof.ProofValue)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(wlt.privateKey.Public().(ed25519.PublicKey), presentationSigningInput(vp), signature) {
		t.Fatalf("presentation signature did not verify")
	}
}

func TestWalletRejectsCredentialForDifferentHolder(t *testing.T) {
	wlt := setupWalletTest(t)
	cred := testWalletCredential("did:key:someone-else")

	rec := postWalletJSON(t, wlt.credentialsHandler, StoreCredentialRequest{Credential: cred})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	var out struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Error != "credential_subject_not_wallet_holder" {
		t.Fatalf("error = %q", out.Error)
	}
}

func setupWalletTest(t *testing.T) *Wallet {
	t.Helper()

	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	db, err := openWalletDB(filepath.Join(t.TempDir(), "wallet.db"))
	if err != nil {
		t.Fatalf("open wallet db: %v", err)
	}
	wlt := &Wallet{
		privateKey: key,
		did:        didKeyFromPublicKey(key.Public().(ed25519.PublicKey)),
		db:         db,
	}
	if err := wlt.saveMetadata(); err != nil {
		t.Fatalf("save metadata: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	return wlt
}

func postWalletJSON(t *testing.T, handler http.HandlerFunc, body any) *httptest.ResponseRecorder {
	t.Helper()

	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func testWalletCredential(subject string) Credential {
	now := time.Now().UTC()
	return Credential{
		Context:    []string{"https://www.w3.org/ns/credentials/v2"},
		ID:         "urn:uuid:test-wallet-credential",
		Type:       []string{"VerifiableCredential", "OwnerCredential"},
		Issuer:     "did:key:test-issuer",
		ValidFrom:  now.Add(-time.Minute).Format(time.RFC3339),
		ValidUntil: now.Add(time.Hour).Format(time.RFC3339),
		CredentialSubject: CredentialSubject{
			ID:           subject,
			Gateway:      "gateway-home-1",
			DeviceScopes: []string{"lock-front-door"},
			ActionScopes: []string{"unlock"},
		},
		CredentialStatus: CredentialStatus{
			ID:            "urn:uuid:test-wallet-credential#status",
			Type:          "BlackwallRevocationStatus2026",
			StatusPurpose: "revocation",
			Status:        "active",
		},
	}
}

func hexDecodeSignature(value string) ([]byte, error) {
	return hex.DecodeString(value)
}
