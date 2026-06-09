package main

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
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
	privateKey ed25519.PrivateKey
	did        string
	db         *sql.DB
}

func main() {
	requireEnv("SERVICE_AUTH_TOKEN")
	wallet := newWallet()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/wallet/did", wallet.didHandler)
	mux.HandleFunc("/wallet/credentials", wallet.credentialsHandler)
	mux.HandleFunc("/wallet/presentations", wallet.presentationsHandler)

	addr := getenv("WALLET_ADDR", "127.0.0.1:8083")
	log.Printf("go-wallet listening on %s holder=%s", addr, wallet.did)
	log.Fatal(http.ListenAndServe(addr, serviceAuthMiddleware(mux)))
}

func newWallet() *Wallet {
	privateKey := walletPrivateKey()
	did := didKeyFromPublicKey(privateKey.Public().(ed25519.PublicKey))
	db, err := openWalletDB(walletDBPath())
	if err != nil {
		log.Fatalf("open wallet db: %v", err)
	}
	wallet := &Wallet{
		privateKey: privateKey,
		did:        did,
		db:         db,
	}
	if err := wallet.saveMetadata(); err != nil {
		log.Fatalf("save wallet metadata: %v", err)
	}
	return wallet
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

	if err := wlt.storeCredential(req.Credential); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "credential_store_failed"})
		return
	}

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
	var raw string
	var err error
	if id != "" {
		err = wlt.db.QueryRow(`SELECT raw_json FROM credentials WHERE id = ?`, id).Scan(&raw)
	} else {
		err = wlt.db.QueryRow(`SELECT raw_json FROM credentials ORDER BY stored_at DESC LIMIT 1`).Scan(&raw)
	}
	if err != nil {
		return Credential{}, false
	}
	var cred Credential
	if err := json.Unmarshal([]byte(raw), &cred); err != nil {
		return Credential{}, false
	}
	return cred, true
}

func (wlt *Wallet) storeCredential(cred Credential) error {
	raw, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	_, err = wlt.db.Exec(`
		INSERT INTO credentials (
			id, holder, issuer, raw_json, stored_at
		) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			holder = excluded.holder,
			issuer = excluded.issuer,
			raw_json = excluded.raw_json,
			stored_at = excluded.stored_at
	`, cred.ID, wlt.did, cred.Issuer, string(raw), time.Now().UTC().Format(time.RFC3339))
	return err
}

func (wlt *Wallet) saveMetadata() error {
	tx, err := wlt.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	metadata := map[string]string{
		"holder_did":          wlt.did,
		"verification_method": wlt.did + "#key-1",
	}
	for key, value := range metadata {
		if _, err := tx.Exec(`
			INSERT INTO wallet_metadata (key, value, updated_at)
			VALUES (?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
		`, key, value, time.Now().UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	keyMetadata := map[string]string{
		"key_type":            "Ed25519",
		"key_source":          walletKeySource(),
		"verification_method": wlt.did + "#key-1",
	}
	for key, value := range keyMetadata {
		if _, err := tx.Exec(`
			INSERT INTO key_metadata (key, value, updated_at)
			VALUES (?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
		`, key, value, time.Now().UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	return tx.Commit()
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

	if rawHex := os.Getenv("WALLET_ED25519_SEED_HEX"); rawHex != "" {
		seed, err := hex.DecodeString(rawHex)
		if err == nil && len(seed) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(seed)
		}
	}
	log.Fatal("WALLET_ED25519_PRIVATE_KEY_HEX or WALLET_ED25519_SEED_HEX must be set to a valid Ed25519 key")
	return nil
}

func walletKeySource() string {
	if os.Getenv("WALLET_ED25519_PRIVATE_KEY_HEX") != "" {
		return "WALLET_ED25519_PRIVATE_KEY_HEX"
	}
	return "WALLET_ED25519_SEED_HEX"
}

func openWalletDB(path string) (*sql.DB, error) {
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
	if _, err := db.Exec(walletSchema); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

const walletSchema = `
CREATE TABLE IF NOT EXISTS credentials (
	id TEXT PRIMARY KEY,
	holder TEXT NOT NULL,
	issuer TEXT NOT NULL,
	raw_json TEXT NOT NULL,
	stored_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS wallet_metadata (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS key_metadata (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
`

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

func requireEnv(key string) {
	if os.Getenv(key) == "" {
		log.Fatalf("%s must be set", key)
	}
}

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func walletDBPath() string {
	return getenv("WALLET_DB_PATH", "../../runtime/wallet/wallet.db")
}
