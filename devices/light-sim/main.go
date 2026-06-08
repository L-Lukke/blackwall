package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type DeviceCommand struct {
	DeviceID string `json:"device_id"`
}

var (
	mu     sync.Mutex
	states = map[string]string{}
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/turn_on", lightHandler("on"))
	mux.HandleFunc("/turn_off", lightHandler("off"))
	mux.HandleFunc("/state", stateHandler)

	addr := getenv("LIGHT_ADDR", ":8092")
	log.Printf("light-sim listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func lightHandler(nextState string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
			return
		}

		var cmd DeviceCommand
		if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_json"})
			return
		}
		if cmd.DeviceID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "device_id_required"})
			return
		}

		mu.Lock()
		states[cmd.DeviceID] = nextState
		mu.Unlock()

		writeJSON(w, http.StatusOK, map[string]any{
			"device_id":  cmd.DeviceID,
			"state":      nextState,
			"updated_at": time.Now().UTC().Format(time.RFC3339),
		})
	}
}

func stateHandler(w http.ResponseWriter, r *http.Request) {
	deviceID := r.URL.Query().Get("device_id")
	if deviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "device_id_required"})
		return
	}

	mu.Lock()
	state := states[deviceID]
	mu.Unlock()

	if state == "" {
		state = "off"
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"device_id": deviceID,
		"state":     state,
	})
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