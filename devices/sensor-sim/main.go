package main

import (
	"encoding/json"
	"log"
	"math"
	"net/http"
	"os"
	"time"
)

type readingResponse struct {
	OK           bool    `json:"ok"`
	DeviceID     string  `json:"device_id"`
	Kind         string  `json:"kind"`
	TemperatureC float64 `json:"temperature_c"`
	HumidityPct  float64 `json:"humidity_pct"`
	CapturedAt   string  `json:"captured_at"`
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/reading", readingHandler)

	addr := getenv("SENSOR_ADDR", ":8091")
	log.Printf("sensor-sim listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func readingHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}

	deviceID := r.URL.Query().Get("device_id")
	if deviceID == "" {
		deviceID = "sensor-living-room"
	}

	now := time.Now().UTC()
	temp, hum := syntheticReading(now)

	writeJSON(w, http.StatusOK, readingResponse{
		OK:           true,
		DeviceID:     deviceID,
		Kind:         "environment",
		TemperatureC: temp,
		HumidityPct:  hum,
		CapturedAt:   now.Format(time.RFC3339),
	})
}

func syntheticReading(t time.Time) (float64, float64) {
	sec := float64(t.Unix())

	temperature := 22.0 + 2.4*math.Sin(sec/300.0)
	humidity := 48.0 + 7.5*math.Cos(sec/420.0)

	return round1(temperature), round1(humidity)
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
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