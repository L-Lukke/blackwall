package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
)

type commandRequest struct {
	DeviceID string `json:"device_id"`
}

type lockResponse struct {
	OK       bool   `json:"ok"`
	DeviceID string `json:"device_id"`
	State    string `json:"state"`
}

type lockState struct {
	mu    sync.Mutex
	state string
}

var current = &lockState{state: "locked"}

func main() {
	requireEnv("SERVICE_AUTH_TOKEN")

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/lock", lockHandler)
	mux.HandleFunc("/unlock", unlockHandler)
	mux.HandleFunc("/state", stateHandler)

	addr := getenv("LOCK_ADDR", "127.0.0.1:8090")
	log.Printf("lock-sim listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, serviceAuthMiddleware(mux)))
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func lockHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}

	var req commandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_json"})
		return
	}

	current.mu.Lock()
	current.state = "locked"
	current.mu.Unlock()

	writeJSON(w, http.StatusOK, lockResponse{
		OK:       true,
		DeviceID: req.DeviceID,
		State:    "locked",
	})
}

func unlockHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}

	var req commandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_json"})
		return
	}

	current.mu.Lock()
	current.state = "unlocked"
	current.mu.Unlock()

	writeJSON(w, http.StatusOK, lockResponse{
		OK:       true,
		DeviceID: req.DeviceID,
		State:    "unlocked",
	})
}

func stateHandler(w http.ResponseWriter, _ *http.Request) {
	current.mu.Lock()
	defer current.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"device_id": "lock-front-door",
		"state":     current.state,
	})
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
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
