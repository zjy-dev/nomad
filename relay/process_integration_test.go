package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

const (
	alphaEnvFlag       = "NOMAD_RELAY_ALPHA_LOCAL"
	alphaTokenEnvName  = "NOMAD_ALPHA_RELAY_TOKEN"
	alphaTokenValue    = "local-alpha-capability-token"
	alphaDeviceIDHex   = "00112233445566778899aabbccddeeff"
	alphaPublicKeyHex  = "91e2a79a68c193280833693cd118d53d7e9cf571eb3bc8b3ade7a398b4068864"
	alphaPrivateKeyHex = "8cd8ac5b730d8f625d9631bb0a6cd7e7d66f6bde56d356b8af602534fe7fc54b91e2a79a68c193280833693cd118d53d7e9cf571eb3bc8b3ade7a398b4068864"
)

type runningRelay struct {
	cmd    *exec.Cmd
	base   string
	cancel context.CancelFunc
	waited bool
}

type frameAccepted struct {
	FrameID string `json:"frame_id"`
	New     bool   `json:"new"`
	Device  string `json:"device"`
	Hash    string `json:"hash"`
}

type listedFrame struct {
	FrameID string `json:"frame_id"`
	Payload string `json:"payload"`
	Flags   uint16 `json:"flags"`
}

type ackResponse struct {
	Acked    int  `json:"acked"`
	Verified bool `json:"verified"`
}

func TestAlphaLocalRealProcessRestartFlow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "relay.db")
	deviceID, _, priv := alphaFixtureKeys(t)
	addr := reserveLoopbackAddr(t)

	relayOne := startAlphaRelay(t, addr, dbPath)

	payload := []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x41, 0x42}
	raw := signedFrame(t, deviceID, priv, payload)
	accepted := postRawFrame(t, relayOne.base, raw)
	if !accepted.New {
		t.Fatalf("first post should be new: %+v", accepted)
	}

	duplicate := postRawFrame(t, relayOne.base, raw)
	if duplicate.FrameID != accepted.FrameID || duplicate.New {
		t.Fatalf("duplicate post should be idempotent: first=%+v dup=%+v", accepted, duplicate)
	}

	frames := listFrames(t, relayOne.base, deviceID)
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame before restart, got %d", len(frames))
	}
	if got := mustHexDecode(t, frames[0].Payload); !bytes.Equal(got, payload) {
		t.Fatalf("payload changed before restart: got=%x want=%x", got, payload)
	}

	stopRelay(t, relayOne)

	relayTwo := startAlphaRelay(t, addr, dbPath)
	defer stopRelay(t, relayTwo)

	frames = listFrames(t, relayTwo.base, deviceID)
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame after restart, got %d", len(frames))
	}
	if frames[0].FrameID != accepted.FrameID {
		t.Fatalf("frame id changed across restart: got=%s want=%s", frames[0].FrameID, accepted.FrameID)
	}
	if got := mustHexDecode(t, frames[0].Payload); !bytes.Equal(got, payload) {
		t.Fatalf("payload changed after restart: got=%x want=%x", got, payload)
	}

	acked := ackFrames(t, relayTwo.base, deviceID, []string{accepted.FrameID})
	if acked.Acked != 1 || !acked.Verified {
		t.Fatalf("ack failed: %+v", acked)
	}
	if remaining := listFrames(t, relayTwo.base, deviceID); len(remaining) != 0 {
		t.Fatalf("expected 0 frames after ack, got %d", len(remaining))
	}

	stopRelay(t, relayTwo)
	relayThree := startAlphaRelay(t, addr, dbPath)
	defer stopRelay(t, relayThree)
	if remaining := listFrames(t, relayThree.base, deviceID); len(remaining) != 0 {
		t.Fatalf("acked state did not persist across restart: %d frames", len(remaining))
	}
}

func TestAlphaLocalNegativeMatrix(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "relay-negative.db")
	deviceID, _, priv := alphaFixtureKeys(t)
	relay := startAlphaRelay(t, reserveLoopbackAddr(t), dbPath)
	defer stopRelay(t, relay)

	testRouteResp, err := http.Get(relay.base + "/v1/test/messages")
	if err != nil {
		t.Fatal(err)
	}
	defer testRouteResp.Body.Close()
	if testRouteResp.StatusCode != http.StatusNotFound {
		t.Fatalf("/v1/test/messages should be 404, got %d", testRouteResp.StatusCode)
	}

	assertStatus(t, listFramesRequest(t, relay.base, deviceID, ""), http.StatusUnauthorized)
	assertStatus(t, listFramesRequest(t, relay.base, deviceID, "wrong-token"), http.StatusUnauthorized)
	assertStatus(t, ackFramesRequest(t, relay.base, deviceID, []string{"missing"}, ""), http.StatusUnauthorized)
	assertStatus(t, ackFramesRequest(t, relay.base, deviceID, []string{"missing"}, "wrong-token"), http.StatusUnauthorized)

	assertStatus(t, postJSONRequest(t, relay.base+"/v1/devices/register", map[string]string{
		"device_id":  fmt.Sprintf("%x", deviceID[:]),
		"pubkey_hex": alphaPublicKeyHex,
	}), http.StatusForbidden)
	assertStatus(t, postJSONRequest(t, relay.base+"/v1/devices/deregister", map[string]string{
		"device_id": fmt.Sprintf("%x", deviceID[:]),
	}), http.StatusForbidden)

	badSig := signedFrame(t, deviceID, priv, []byte("bad-signature"))
	badSig[len(badSig)-1] ^= 0x01
	assertStatus(t, postFrameRequest(t, relay.base, badSig), http.StatusUnauthorized)

	unknownID := deviceID
	unknownID[0] ^= 0xff
	assertStatus(t, postFrameRequest(t, relay.base, signedFrame(t, unknownID, priv, []byte("unknown"))), http.StatusUnauthorized)

	oversized := signedFrame(t, deviceID, priv, bytes.Repeat([]byte{0x42}, MaxFrameSize))
	oversized = append(oversized, 0x99)
	assertStatus(t, postFrameRequest(t, relay.base, oversized), http.StatusRequestEntityTooLarge)
}

func TestAlphaLocalRealProcessRejectsRegisteredNonFixedDeviceFrame(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "relay-fixed-device.db")
	otherDeviceID := GenerateTestDeviceID()
	otherPublicKey, otherPrivateKey := GenerateTestKeys()

	db, err := NewMailboxDB(dbPath)
	if err != nil {
		t.Fatalf("open relay db to register other device: %v", err)
	}
	if err := db.RegisterDevice(otherDeviceID, otherPublicKey); err != nil {
		db.Close()
		t.Fatalf("register other device: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close relay db after registering other device: %v", err)
	}

	relay := startAlphaRelay(t, reserveLoopbackAddr(t), dbPath)
	raw := signedFrame(t, otherDeviceID, otherPrivateKey, []byte("opaque-other-device-payload"))
	resp := postFrameRequest(t, relay.base, raw)
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		stopRelay(t, relay)
		t.Fatalf("read rejected frame response: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized || string(body) != "unauthorized\n" {
		stopRelay(t, relay)
		t.Fatalf("registered non-fixed device status=%d body=%q, want 401 unauthorized", resp.StatusCode, body)
	}
	stopRelay(t, relay)

	db, err = NewMailboxDB(dbPath)
	if err != nil {
		t.Fatalf("reopen relay db after rejected frame: %v", err)
	}
	defer db.Close()
	total, unacked, err := db.DeviceFrameCount(otherDeviceID)
	if err != nil {
		t.Fatalf("count other device frames: %v", err)
	}
	if total != 0 || unacked != 0 {
		t.Fatalf("registered non-fixed device frame was stored: total=%d unacked=%d", total, unacked)
	}
}

func TestAlphaLocalRejectsNonLoopbackAddr(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "relay-non-loopback.db")
	bin := buildRelayBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-db", dbPath, "-addr", "0.0.0.0:0", "-alpha-local")
	cmd.Env = append(os.Environ(), alphaEnvFlag+"=1", alphaTokenEnvName+"="+alphaTokenValue)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-loopback alpha start to fail, output=%s", output)
	}
	if !bytes.Contains(output, []byte("loopback")) {
		t.Fatalf("expected loopback failure, got output=%s", output)
	}
}

func TestAlphaLocalRejectsMemoryDBAndMissingToken(t *testing.T) {
	bin := buildRelayBinary(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-db", ":memory:", "-addr", "127.0.0.1:18089", "-alpha-local")
	cmd.Env = append(os.Environ(), alphaEnvFlag+"=1", alphaTokenEnvName+"="+alphaTokenValue)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected :memory: alpha-local start to fail, output=%s", output)
	}
	if !bytes.Contains(output, []byte(":memory:")) {
		t.Fatalf("expected file-backed sqlite failure, got output=%s", output)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	dbPath := filepath.Join(t.TempDir(), "relay-missing-token.db")
	cmd = exec.CommandContext(ctx2, bin, "-db", dbPath, "-addr", "127.0.0.1:18090", "-alpha-local")
	cmd.Env = append(os.Environ(), alphaEnvFlag+"=1")
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected missing token alpha-local start to fail, output=%s", output)
	}
	if !bytes.Contains(output, []byte(alphaTokenEnvName)) {
		t.Fatalf("expected missing token failure, got output=%s", output)
	}
}

func buildRelayBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "relay-bin")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/relay")
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build relay: %v\n%s", err, output)
	}
	return bin
}

func startAlphaRelay(t *testing.T, addr, dbPath string) *runningRelay {
	t.Helper()
	bin := buildRelayBinary(t)
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, "-db", dbPath, "-addr", addr, "-alpha-local", "-alpha-token-env", alphaTokenEnvName)
	cmd.Env = append(os.Environ(), alphaEnvFlag+"=1", alphaTokenEnvName+"="+alphaTokenValue)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start relay: %v", err)
	}
	base := "http://" + addr
	waitForRelay(t, base, 5*time.Second)
	return &runningRelay{cmd: cmd, base: base, cancel: cancel}
}

func stopRelay(t *testing.T, relay *runningRelay) {
	t.Helper()
	if relay == nil || relay.waited || relay.cmd == nil || relay.cmd.Process == nil {
		return
	}
	relay.cancel()
	_ = relay.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- relay.cmd.Wait() }()
	select {
	case err := <-done:
		relay.waited = true
		if err != nil {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("relay wait failed: %v", err)
			}
		}
	case <-time.After(5 * time.Second):
		relay.waited = true
		_ = relay.cmd.Process.Kill()
		t.Fatalf("relay did not stop in time")
	}
}

func waitForRelay(t *testing.T, base string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/health")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && bytes.Contains(body, []byte("TEST-ONLY/1")) {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("relay did not become healthy on loopback within %s", timeout)
}

func reserveLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback addr: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close reserved listener: %v", err)
	}
	return addr
}

func alphaFixtureKeys(t *testing.T) (DeviceID, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	deviceID, pub, err := AlphaLocalFixture()
	if err != nil {
		t.Fatalf("alpha fixture: %v", err)
	}
	priv := ed25519.PrivateKey(mustHexDecode(t, alphaPrivateKeyHex))
	return deviceID, pub, priv
}

func signedFrame(t *testing.T, id DeviceID, priv ed25519.PrivateKey, payload []byte) []byte {
	t.Helper()
	env := NewEnvelope(id, FlagRequest, payload)
	if err := env.Sign(priv); err != nil {
		t.Fatalf("sign frame: %v", err)
	}
	return env.Marshal()
}

func postSignedFrame(t *testing.T, base string, id DeviceID, priv ed25519.PrivateKey, payload []byte) frameAccepted {
	t.Helper()
	return postRawFrame(t, base, signedFrame(t, id, priv, payload))
}

func postRawFrame(t *testing.T, base string, raw []byte) frameAccepted {
	t.Helper()
	resp := postFrameRequest(t, base, raw)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("post frame status=%d body=%s", resp.StatusCode, body)
	}
	var accepted frameAccepted
	if err := json.NewDecoder(resp.Body).Decode(&accepted); err != nil {
		t.Fatalf("decode frame accepted: %v", err)
	}
	return accepted
}

func postFrameRequest(t *testing.T, base string, raw []byte) *http.Response {
	t.Helper()
	resp, err := http.Post(base+"/v1/frame", "application/octet-stream", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("post frame request: %v", err)
	}
	return resp
}

func listFrames(t *testing.T, base string, id DeviceID) []listedFrame {
	t.Helper()
	resp := listFramesRequest(t, base, id, alphaTokenValue)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("list frames status=%d body=%s", resp.StatusCode, body)
	}
	var frames []listedFrame
	if err := json.NewDecoder(resp.Body).Decode(&frames); err != nil {
		t.Fatalf("decode frames: %v", err)
	}
	return frames
}

func ackFrames(t *testing.T, base string, id DeviceID, frameIDs []string) ackResponse {
	t.Helper()
	resp := ackFramesRequest(t, base, id, frameIDs, alphaTokenValue)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("ack status=%d body=%s", resp.StatusCode, raw)
	}
	var acked ackResponse
	if err := json.NewDecoder(resp.Body).Decode(&acked); err != nil {
		t.Fatalf("decode ack response: %v", err)
	}
	return acked
}

func listFramesRequest(t *testing.T, base string, id DeviceID, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+"/v1/frames?device="+fmt.Sprintf("%x", id[:]), nil)
	if err != nil {
		t.Fatalf("build list frames request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list frames request: %v", err)
	}
	return resp
}

func ackFramesRequest(t *testing.T, base string, id DeviceID, frameIDs []string, token string) *http.Response {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{
		"device":    fmt.Sprintf("%x", id[:]),
		"frame_ids": frameIDs,
	})
	req, err := http.NewRequest(http.MethodPost, base+"/v1/ack", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build ack request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("ack request: %v", err)
	}
	return resp
}

func postJSONRequest(t *testing.T, url string, payload any) *http.Response {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal json request: %v", err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post json request: %v", err)
	}
	return resp
}

func assertStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != want {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want=%d body=%s", resp.StatusCode, want, body)
	}
}

func mustHexDecode(t *testing.T, value string) []byte {
	t.Helper()
	output, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex %q: %v", value, err)
	}
	return output
}
