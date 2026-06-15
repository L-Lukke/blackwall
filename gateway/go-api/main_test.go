package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestAccessRequestRequiresPresentation(t *testing.T) {
	withTestGatewayDB(t)

	reqBody := AccessRequest{
		Subject:  "did:key:test-holder",
		DeviceID: "lock-front-door",
		Action:   "unlock",
	}
	rec := postAccessRequest(t, reqBody)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	assertJSONReason(t, rec.Body.Bytes(), "presentation_required")
}

func TestValidateConsumedChallengeRejectsBoundFieldMismatch(t *testing.T) {
	record := ChallengeRecord{
		Subject:   "did:key:test-holder",
		DeviceID:  "lock-front-door",
		Action:    "unlock",
		Domain:    "gateway-home-1",
		ExpiresAt: time.Now().UTC().Add(time.Minute),
	}
	req := AccessRequest{
		Subject:   record.Subject,
		DeviceID:  record.DeviceID,
		Action:    record.Action,
		Challenge: "challenge",
		Presentation: &VerifiablePresentation{
			Proof: &VPProof{
				Challenge: "challenge",
				Domain:    record.Domain,
			},
		},
	}

	req.DeviceID = "light-living-room"
	if reason := validateConsumedChallenge(req, record); reason != "challenge_device_mismatch" {
		t.Fatalf("device mismatch reason = %q", reason)
	}

	req = AccessRequest{
		Subject:   record.Subject,
		DeviceID:  record.DeviceID,
		Action:    record.Action,
		Challenge: "challenge",
		Presentation: &VerifiablePresentation{
			Proof: &VPProof{
				Challenge: "different-challenge",
				Domain:    record.Domain,
			},
		},
	}
	if reason := validateConsumedChallenge(req, record); reason != "presentation_challenge_mismatch" {
		t.Fatalf("presentation challenge mismatch reason = %q", reason)
	}
}

func TestConsumeAccessChallengeRejectsReplay(t *testing.T) {
	withTestGatewayDB(t)

	challenge := "test-challenge"
	record := ChallengeRecord{
		Subject:   "did:key:test-holder",
		DeviceID:  "lock-front-door",
		Action:    "unlock",
		Domain:    "gateway-home-1",
		ExpiresAt: time.Now().UTC().Add(time.Minute),
	}
	if err := saveAccessChallenge(challenge, record); err != nil {
		t.Fatalf("save challenge: %v", err)
	}

	req := AccessRequest{
		Subject:   record.Subject,
		DeviceID:  record.DeviceID,
		Action:    record.Action,
		Challenge: challenge,
		Presentation: &VerifiablePresentation{
			Proof: &VPProof{
				Challenge: challenge,
				Domain:    record.Domain,
			},
		},
	}

	if reason := consumeAccessChallenge(req); reason != "" {
		t.Fatalf("first consume reason = %q, want accepted", reason)
	}
	if reason := consumeAccessChallenge(req); reason != "challenge_replayed_or_unknown" {
		t.Fatalf("second consume reason = %q, want challenge_replayed_or_unknown", reason)
	}
}

func withTestGatewayDB(t *testing.T) {
	t.Helper()

	oldDB := gatewayDB
	db, err := openGatewayDB(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatalf("open test gateway db: %v", err)
	}
	gatewayDB = db

	t.Cleanup(func() {
		_ = gatewayDB.Close()
		gatewayDB = oldDB
	})
}

func postAccessRequest(t *testing.T, body AccessRequest) *httptest.ResponseRecorder {
	t.Helper()

	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/access/request", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	accessRequestHandler(rec, req)
	return rec
}

func assertJSONReason(t *testing.T, raw []byte, want string) {
	t.Helper()

	var out struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode response: %v body=%s", err, string(raw))
	}
	if out.Reason != want {
		t.Fatalf("reason = %q, want %q; body=%s", out.Reason, want, string(raw))
	}
}
