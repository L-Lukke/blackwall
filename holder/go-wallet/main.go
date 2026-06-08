package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
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

type VerifiablePresentation struct {
	Context              []string           `json:"@context"`
	ID                   string             `json:"id"`
	Type                 []string           `json:"type"`
	Holder               string             `json:"holder"`
	VerifiableCredential []Credential       `json:"verifiableCredential"`
	Proof                *PresentationProof `json:"proof,omitempty"`
}

type StoreCredentialRequest struct {
	Credential Credential `json:"credential"`
}

type PresentationRequest struct {
	CredentialID string `json:"credential_id,omitempty"`
	Challenge    string `json:"challenge"`
	Domain       string `json:"domain"`
}

type Wallet struct {
	mu          sync.Mutex
	privateKey  ed25519.PrivateKey
	did         string
	credentials map[string]Credential
}

func main() {
	wallet := newWallet()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/wallet/did", wallet.didHandler)
	mux.HandleFunc("/wallet/credentials", wallet.credentialsHandler)
	mux.HandleFunc("/wallet/presentations", wallet.presentationsHandler)

	addr := getenv("WALLET_ADDR", ":8083")
	log.Printf("go-wallet listening on %s holder=%s", addr, wallet.did)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func newWallet() *Wallet {
	privateKey := walletPrivateKey()
	return &Wallet{
		privateKey:  privateKey,
		did:         didKeyFromPublicKey(privateKey.Public().(ed25519.PublicKey)),
		credentials: map[string]Credential{},
	}
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (wlt *Wallet) didHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"did":                wlt.did,
		"verificationMethod": wlt.did + "#key-1",
	})
}

func (wlt *Wallet) credentialsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}

	var req StoreCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_json"})
		return
	}
	if req.Credential.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "credential_required"})
		return
	}
	if req.Credential.CredentialSubject.ID != wlt.did {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "credential_subject_not_wallet_holder"})
		return
	}

	wlt.mu.Lock()
	wlt.credentials[req.Credential.ID] = req.Credential
	wlt.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "credential_id": req.Credential.ID})
}

func (wlt *Wallet) presentationsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}

	var req PresentationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_json"})
		return
	}
	if req.Challenge == "" || req.Domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "challenge_and_domain_required"})
		return
	}

	cred, ok := wlt.findCredential(req.CredentialID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "credential_not_found"})
		return
	}

	now := time.Now().UTC()
	vp := VerifiablePresentation{
		Context: []string{
			"https://www.w3.org/ns/credentials/v2",
			"https://blackwall.local/contexts/smart-home-presentation/v1",
		},
		ID:                   fmt.Sprintf("urn:uuid:vp-%d", now.UnixNano()),
		Type:                 []string{"VerifiablePresentation"},
		Holder:               wlt.did,
		VerifiableCredential: []Credential{cred},
	}
	signature := ed25519.Sign(wlt.privateKey, presentationSigningInput(vp))
	vp.Proof = &PresentationProof{
		Type:               "DataIntegrityProof",
		Cryptosuite:        "eddsa-rdfc-2022",
		Created:            now.Format(time.RFC3339),
		VerificationMethod: wlt.did + "#key-1",
		ProofPurpose:       "authentication",
		Challenge:          req.Challenge,
		Domain:             req.Domain,
		ProofValue:         hex.EncodeToString(signature),
	}

	writeJSON(w, http.StatusOK, vp)
}

func (wlt *Wallet) findCredential(id string) (Credential, bool) {
	wlt.mu.Lock()
	defer wlt.mu.Unlock()

	if id != "" {
		cred, ok := wlt.credentials[id]
		return cred, ok
	}
	for _, cred := range wlt.credentials {
		return cred, true
	}
	return Credential{}, false
}

func presentationSigningInput(vp VerifiablePresentation) []byte {
	vp.Proof = nil
	raw, err := json.Marshal(vp)
	if err != nil {
		return nil
	}
	return raw
}

func walletPrivateKey() ed25519.PrivateKey {
	if rawHex := os.Getenv("WALLET_ED25519_PRIVATE_KEY_HEX"); rawHex != "" {
		raw, err := hex.DecodeString(rawHex)
		if err == nil && len(raw) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(raw)
		}
		if err == nil && len(raw) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(raw)
		}
	}

	seed, _ := hex.DecodeString(getenv("WALLET_ED25519_SEED_HEX", "f6a36f36c806d12794d5c307809762fd1f95d32278c6ac2c742c7b6a9249fbd5"))
	return ed25519.NewKeyFromSeed(seed)
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
