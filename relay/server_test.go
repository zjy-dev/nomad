package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDeviceRegisterAndFrameFlow exercises the full register->frame->deliver->ack HTTP flow.
func TestDeviceRegisterAndFrameFlow(t *testing.T) {
	db, err := NewMailboxDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	srv := NewServer(db, "127.0.0.1:0")
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/frame", srv.handleFrame)
	mux.HandleFunc("/v1/frames", srv.handleFramesList)
	mux.HandleFunc("/v1/ack", srv.handleAck)
	mux.HandleFunc("/v1/devices/register", srv.handleDeviceRegister)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Register device
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	deviceID := GenerateTestDeviceID()

	regBody := map[string]interface{}{
		"device_id":  fmt.Sprintf("%x", deviceID[:]),
		"pubkey_hex": fmt.Sprintf("%x", []byte(pub)),
	}
	regJSON, _ := json.Marshal(regBody)
	resp, err := http.Post(ts.URL+"/v1/devices/register", "application/json", bytes.NewReader(regJSON))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register: expected 200, got %d", resp.StatusCode)
	}

	// Create and sign a frame
	payload := []byte(`{"secret":"opaque","data":[1,2,3]}`)
	env := NewEnvelope(deviceID, FlagRequest, payload)
	if err := env.Sign(priv); err != nil {
		t.Fatal(err)
	}
	raw := env.Marshal()

	// Submit frame
	resp, err = http.Post(ts.URL+"/v1/frame", "application/octet-stream", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("frame: expected 202, got %d: %s", resp.StatusCode, string(body))
	}

	// Parse response to get frame_id
	var frameResp struct {
		FrameID string `json:"frame_id"`
		New     bool   `json:"new"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&frameResp); err != nil {
		t.Fatal(err)
	}
	if !frameResp.New {
		t.Error("frame should be new")
	}

	// List frames
	resp, err = http.Get(ts.URL + "/v1/frames?device=" + fmt.Sprintf("%x", deviceID[:]))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("frames list: expected 200, got %d", resp.StatusCode)
	}

	var frames []struct {
		FrameID string `json:"frame_id"`
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&frames); err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
	if frames[0].FrameID != frameResp.FrameID {
		t.Errorf("frame_id mismatch")
	}

	// Decode payload hex and verify it matches the original
	decoded, err := hex.DecodeString(frames[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Errorf("payload changed through HTTP pipeline: got %s, want %s", decoded, payload)
	}

	// ACK the frame
	ackBody := map[string]interface{}{
		"device":    fmt.Sprintf("%x", deviceID[:]),
		"frame_ids": []string{frameResp.FrameID},
	}
	ackJSON, _ := json.Marshal(ackBody)
	resp, err = http.Post(ts.URL+"/v1/ack", "application/json", bytes.NewReader(ackJSON))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ack: expected 200, got %d", resp.StatusCode)
	}

	var ackResp struct {
		Acked    int  `json:"acked"`
		Verified bool `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ackResp); err != nil {
		t.Fatal(err)
	}
	if ackResp.Acked != 1 {
		t.Errorf("acked count: expected 1, got %d", ackResp.Acked)
	}
	if !ackResp.Verified {
		t.Error("ACK verification failed")
	}

	// After ACK, frame should not be deliverable
	resp, err = http.Get(ts.URL + "/v1/frames?device=" + fmt.Sprintf("%x", deviceID[:]))
	if err != nil {
		t.Fatal(err)
	}
	var frames2 []struct {
		FrameID string `json:"frame_id"`
	}
	json.NewDecoder(resp.Body).Decode(&frames2)
	if len(frames2) != 0 {
		t.Errorf("expected 0 frames after ACK, got %d", len(frames2))
	}
}

// TestPayloadNeverParsedOverHTTP verifies the relay does not interpret payload
// content at any point in the HTTP pipeline.
func TestPayloadNeverParsedOverHTTP(t *testing.T) {
	db, err := NewMailboxDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	srv := NewServer(db, "127.0.0.1:0")
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/frame", srv.handleFrame)
	mux.HandleFunc("/v1/frames", srv.handleFramesList)
	mux.HandleFunc("/v1/devices/register", srv.handleDeviceRegister)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Register
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	deviceID := GenerateTestDeviceID()
	regBody := map[string]interface{}{
		"device_id":  fmt.Sprintf("%x", deviceID[:]),
		"pubkey_hex": fmt.Sprintf("%x", []byte(pub)),
	}
	regJSON, _ := json.Marshal(regBody)
	http.Post(ts.URL+"/v1/devices/register", "application/json", bytes.NewReader(regJSON))

	// Test with malicious payload content that SHOULD NOT be parsed
	maliciousPayloads := []struct {
		name    string
		payload []byte
	}{
		{"sql-injection", []byte("'); DROP TABLE frames; --")},
		{"xss-attempt", []byte("<script>alert('xss')</script>")},
		{"shell-command", []byte("; rm -rf /")},
		{"path-traversal", []byte("../../etc/passwd")},
		{"json-command", []byte(`{"command":"cat /etc/shadow"}`)},
		{"binary-null", append([]byte{0x00}, []byte("binary\x00data")...)},
		{"large-binary", bytes.Repeat([]byte{0xDE, 0xAD}, 100)},
	}

	for _, tc := range maliciousPayloads {
		t.Run(tc.name, func(t *testing.T) {
			env := NewEnvelope(deviceID, FlagRequest, tc.payload)
			if err := env.Sign(priv); err != nil {
				t.Fatal(err)
			}
			raw := env.Marshal()

			resp, err := http.Post(ts.URL+"/v1/frame", "application/octet-stream", bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusAccepted {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("frame submit failed: %d: %s", resp.StatusCode, string(body))
			}

			var frameResp struct {
				FrameID string `json:"frame_id"`
			}
			json.NewDecoder(resp.Body).Decode(&frameResp)

			// Retrieve and verify payload is intact
			resp, err = http.Get(ts.URL + "/v1/frames?device=" + fmt.Sprintf("%x", deviceID[:]))
			if err != nil {
				t.Fatal(err)
			}

			var frames []struct {
				FrameID string `json:"frame_id"`
				Payload string `json:"payload"`
			}
			json.NewDecoder(resp.Body).Decode(&frames)

			for _, f := range frames {
				if f.FrameID == frameResp.FrameID {
					decoded, err := hex.DecodeString(f.Payload)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(decoded, tc.payload) {
						t.Errorf("payload corrupted: got %x, want %x", decoded, tc.payload)
					}
					return
				}
			}
			t.Error("frame not found in deliverable list")
		})
	}
}

// TestHealthEndpoint verifies health is available.
func TestHealthEndpoint(t *testing.T) {
	db, err := NewMailboxDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	srv := NewServer(db, "127.0.0.1:0")
	mux := http.NewServeMux()
	mux.HandleFunc("/health", srv.handleHealth)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health: expected 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result["status"] != "ok" {
		t.Error("health status not ok")
	}
	if result["protocol"] != "TEST-ONLY/1" {
		t.Errorf("protocol: got %v, want TEST-ONLY/1", result["protocol"])
	}
}

// TestWorkerCleanup verifies the retention worker properly cleans up TTL-expired frames.
func TestWorkerCleanup(t *testing.T) {
	db, err := NewMailboxDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	deviceID := GenerateTestDeviceID()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	db.RegisterDevice(deviceID, pub)

	// Store with expired TTL
	env := NewEnvelope(deviceID, FlagRequest, []byte("will-expire"))
	env.Sign(priv)
	db.StoreFrame(env, 0) // zero TTL

	// Run cleanup manually
	w := NewWorker(db, 100*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	go w.Run(ctx)

	// Wait for at least one cleanup tick
	time.Sleep(200 * time.Millisecond)
	w.Stop()

	// Verify frame is gone
	_, unacked, err := db.DeviceFrameCount(deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if unacked != 0 {
		t.Errorf("expired frames should be cleaned up, unacked=%d", unacked)
	}
}

// TestFrameRateLimitOverHTTP verifies rate limit enforcement through HTTP.
func TestFrameRateLimitOverHTTP(t *testing.T) {
	db, err := NewMailboxDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	srv := NewServer(db, "127.0.0.1:0")
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/frame", srv.handleFrame)
	mux.HandleFunc("/v1/devices/register", srv.handleDeviceRegister)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	deviceID := GenerateTestDeviceID()
	regBody := map[string]interface{}{
		"device_id":  fmt.Sprintf("%x", deviceID[:]),
		"pubkey_hex": fmt.Sprintf("%x", []byte(pub)),
	}
	regJSON, _ := json.Marshal(regBody)
	http.Post(ts.URL+"/v1/devices/register", "application/json", bytes.NewReader(regJSON))

	// Send MaxFramesPerSecond frames
	for i := 0; i < MaxFramesPerSecond; i++ {
		env := NewEnvelope(deviceID, FlagRequest, []byte{byte(i)})
		env.Sign(priv)
		raw := env.Marshal()
		resp, _ := http.Post(ts.URL+"/v1/frame", "application/octet-stream", bytes.NewReader(raw))
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("frame %d: expected 202, got %d", i, resp.StatusCode)
		}
		resp.Body.Close()
	}

	// Next frame should be rate-limited
	env := NewEnvelope(deviceID, FlagRequest, []byte("over"))
	env.Sign(priv)
	resp, _ := http.Post(ts.URL+"/v1/frame", "application/octet-stream", bytes.NewReader(env.Marshal()))
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected 429 rate limited, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}
