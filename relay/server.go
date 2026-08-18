package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Server is the relay HTTP/WebSocket server.
type Server struct {
	db      *mailboxDB
	httpSrv *http.Server
	wsHub   *wsHub
	addr    string

	testBridge        TestBridgeStorage
	testBridgeToken   string
	testBridgeEnabled bool
}

// NewServer creates a new relay server backed by the given mailbox DB.
func NewServer(db *mailboxDB, addr string) *Server {
	return &Server{
		db:    db,
		wsHub: newWSHub(),
		addr:  addr,
	}
}

// SetTestBridge enables the TEST-ONLY bridge endpoints.
// The server validates the bearer token and requires loopback binding.
// Enablement is rejected if the server address is not loopback (127.* or ::1).
func (s *Server) SetTestBridge(store TestBridgeStorage, token string) error {
	if store == nil {
		return fmt.Errorf("relay: test bridge store is nil")
	}
	if token == "" {
		return fmt.Errorf("relay: test bridge token is empty")
	}
	if !isLoopbackAddr(s.addr) {
		return fmt.Errorf("relay: test bridge requires loopback address, got %s", s.addr)
	}
	s.testBridge = store
	s.testBridgeToken = token
	s.testBridgeEnabled = true
	return nil
}

// isLoopbackAddr checks whether the given address string binds to a loopback interface.
func isLoopbackAddr(addr string) bool {
	if addr == "" || addr == ":0" {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Maybe no port specified; treat as host-only
		host = addr
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if host == "127.0.0.1" || host == "::1" {
		return true
	}
	// Handle wildcard binds
	if host == "0.0.0.0" || host == "*" {
		return false
	}
	// Check for 127.x.x.x range
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// Start begins listening. Blocks until the server is shut down.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/v1/frame", s.handleFrame)
	mux.HandleFunc("/v1/frames", s.handleFramesList)
	mux.HandleFunc("/v1/ack", s.handleAck)
	mux.HandleFunc("/v1/devices/register", s.handleDeviceRegister)
	mux.HandleFunc("/v1/devices/deregister", s.handleDeviceDeregister)
	mux.HandleFunc("/v1/ws", s.handleWebSocket)

	if s.testBridgeEnabled {
		s.registerTestBridgeRoutes(mux)
		log.Printf("[relay] TEST-ONLY bridge enabled on loopback")
	} else {
		s.registerTestBridgeRoutes(mux)
	}

	s.httpSrv = &http.Server{
		Addr:         s.addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("relay: listen: %w", err)
	}

	log.Printf("[relay] listening on %s", ln.Addr().String())
	return s.httpSrv.Serve(ln)
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

// --- Handlers ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"protocol":  fmt.Sprintf("TEST-ONLY/%d", ProtocolVersion),
		"timestamp": time.Now().Unix(),
	})
}

// handleFrame accepts a frame from a device (request) and stores it in the mailbox.
func (s *Server) handleFrame(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()

	maxBody := make([]byte, MaxFrameSize+MinEnvelopeSize+1)
	n, _ := r.Body.Read(maxBody)
	if n == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}
	if n > MaxFrameSize+MinEnvelopeSize {
		http.Error(w, ErrFrameTooLarge.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	raw := maxBody[:n]

	env, err := Unmarshal(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := env.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	pubKey, err := s.db.GetDevice(env.DeviceID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := env.Verify(pubKey); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	fid, isNew, err := s.db.StoreFrame(env, DefaultFrameTTL)
	if err != nil {
		status := http.StatusInternalServerError
		if err == ErrCapacityExceeded {
			status = http.StatusServiceUnavailable
		} else if err == ErrFrameRateLimited {
			status = http.StatusTooManyRequests
		} else if err == ErrFrameTooLarge {
			status = http.StatusRequestEntityTooLarge
		} else if err == ErrNoContent {
			status = http.StatusBadRequest
		}
		http.Error(w, err.Error(), status)
		return
	}

	s.wsHub.broadcastFrame(env.DeviceID, fid)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"frame_id": fid,
		"new":      isNew,
		"device":   fmt.Sprintf("%x", env.DeviceID[:]),
		"hash":     fmt.Sprintf("%x", env.PayloadHash()[:8]),
	})
}

// handleFramesList returns undelivered frames for a device.
func (s *Server) handleFramesList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	deviceHex := r.URL.Query().Get("device")
	if deviceHex == "" {
		http.Error(w, "device query required", http.StatusBadRequest)
		return
	}
	var deviceID DeviceID
	decoded, err := hex.DecodeString(deviceHex)
	if err != nil || len(decoded) != len(deviceID) {
		http.Error(w, "invalid device id", http.StatusBadRequest)
		return
	}
	copy(deviceID[:], decoded)

	if _, err := s.db.GetDevice(deviceID); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	frames, err := s.db.DeliverableFrames(deviceID, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result := make([]map[string]interface{}, 0, len(frames))
	for _, f := range frames {
		result = append(result, map[string]interface{}{
			"frame_id": f.FrameID,
			"payload":  fmt.Sprintf("%x", f.Payload),
			"flags":    f.Flags,
			"expires":  f.TTL.Unix(),
			"created":  f.CreatedAt.Unix(),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleAck marks frames as delivered (per-device ACK).
func (s *Server) handleAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Device   string   `json:"device"`
		FrameIDs []string `json:"frame_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var deviceID DeviceID
	decoded, err := hex.DecodeString(req.Device)
	if err != nil || len(decoded) != len(deviceID) {
		http.Error(w, "invalid device id", http.StatusBadRequest)
		return
	}
	copy(deviceID[:], decoded)

	if _, err := s.db.GetDevice(deviceID); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if err := s.db.AckFrames(deviceID, req.FrameIDs); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var allAcked bool = true
	for _, fid := range req.FrameIDs {
		acked, err := s.db.IsFrameAcked(deviceID, fid)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !acked {
			allAcked = false
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"acked":    len(req.FrameIDs),
		"verified": allAcked,
	})
}

// handleDeviceRegister registers a device with its public key.
func (s *Server) handleDeviceRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		DeviceID string `json:"device_id"`
		PubKey   string `json:"pubkey_hex"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var deviceID DeviceID
	decoded, err := hex.DecodeString(req.DeviceID)
	if err != nil || len(decoded) != len(deviceID) {
		http.Error(w, "invalid device id", http.StatusBadRequest)
		return
	}
	copy(deviceID[:], decoded)

	pubKeyBytes, err := hex.DecodeString(req.PubKey)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		http.Error(w, "invalid pubkey hex", http.StatusBadRequest)
		return
	}

	if err := s.db.RegisterDevice(deviceID, ed25519.PublicKey(pubKeyBytes)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "registered",
		"device": fmt.Sprintf("%x", deviceID[:]),
	})
}

// handleDeviceDeregister removes a device and all its data.
func (s *Server) handleDeviceDeregister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var deviceID DeviceID
	decoded, err := hex.DecodeString(req.DeviceID)
	if err != nil || len(decoded) != len(deviceID) {
		http.Error(w, "invalid device id", http.StatusBadRequest)
		return
	}
	copy(deviceID[:], decoded)

	if err := s.db.PurgeDevice(deviceID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "deregistered",
		"device": fmt.Sprintf("%x", deviceID[:]),
	})
}

// handleWebSocket upgrades to WebSocket for live frame notifications.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	s.wsHub.serveHTTP(w, r)
}

// --- TEST-ONLY Bridge Handlers ---

func (s *Server) registerTestBridgeRoutes(mux *http.ServeMux) {
	if s.testBridgeEnabled {
		mux.HandleFunc("/v1/test/messages", s.testBridgeHandleMessages)
		mux.HandleFunc("/v1/test/ack", s.testBridgeHandleAck)
		mux.HandleFunc("/v1/test/pairing/challenges", s.testPilotPairingCreate)
		mux.HandleFunc("/v1/test/pairing/confirm", s.testPilotPairingConfirm)
		mux.HandleFunc("/v1/test/pairing/consume", s.testPilotPairingConsume)
		mux.HandleFunc("/v1/test/cleanup", s.testPilotCleanupChannel)
		return
	}
	mux.HandleFunc("/v1/test/messages", s.testBridgeDisabled)
	mux.HandleFunc("/v1/test/ack", s.testBridgeDisabled)
	mux.HandleFunc("/v1/test/pairing/challenges", s.testBridgeDisabled)
	mux.HandleFunc("/v1/test/pairing/confirm", s.testBridgeDisabled)
	mux.HandleFunc("/v1/test/pairing/consume", s.testBridgeDisabled)
	mux.HandleFunc("/v1/test/cleanup", s.testBridgeDisabled)
}

// testBridgeDisabled returns 404 when the test bridge is not enabled.
func (s *Server) testBridgeDisabled(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "test bridge is disabled", http.StatusNotFound)
}

// testBridgeAuthenticate checks the Bearer token header.
func (s *Server) testBridgeAuthenticate(r *http.Request) bool {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return false
	}
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	provided := strings.TrimPrefix(auth, prefix)
	return subtle.ConstantTimeCompare([]byte(provided), []byte(s.testBridgeToken)) == 1
}

func (s *Server) testPilotStore(w http.ResponseWriter) (testPilotBridgeStorage, bool) {
	store, ok := s.testBridge.(testPilotBridgeStorage)
	if !ok {
		http.Error(w, "pilot bridge storage is unavailable", http.StatusNotImplemented)
	}
	return store, ok
}

func decodeTestBridgeJSON(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, TestOnlyMaxJSONBody)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(dst); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "invalid JSON request", http.StatusBadRequest)
		}
		return false
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "request must contain one JSON object", http.StatusBadRequest)
		return false
	}
	return true
}

func validTestBridgeID(value string, maxLength int) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= maxLength
}

// testBridgeHandleMessages handles POST /v1/test/messages and GET /v1/test/messages.
func (s *Server) testBridgeHandleMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.testBridgeListMessages(w, r)
		return
	}
	if r.Method == http.MethodPost {
		s.testBridgeCreateMessage(w, r)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// testBridgeListMessages returns unacked messages in insertion order.
func (s *Server) testBridgeListMessages(w http.ResponseWriter, r *http.Request) {
	if !s.testBridgeAuthenticate(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	channel := r.URL.Query().Get("channel")
	target := r.URL.Query().Get("target")
	if !validTestBridgeID(channel, testOnlyMaxChannelLength) {
		http.Error(w, "channel query required", http.StatusBadRequest)
		return
	}
	if target != "host" && target != "mobile" {
		http.Error(w, "target must be 'host' or 'mobile'", http.StatusBadRequest)
		return
	}

	msgs, err := s.testBridge.ListUnacked(channel, target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result := make([]map[string]interface{}, 0, len(msgs))
	for _, msg := range msgs {
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(msg.Payload), &payload); err != nil {
			http.Error(w, "stored test payload is invalid JSON", http.StatusInternalServerError)
			return
		}
		result = append(result, map[string]interface{}{
			"id":         msg.ID,
			"channel":    msg.Channel,
			"target":     msg.Target,
			"message_id": msg.MessageID,
			"payload":    payload,
			"acked":      msg.Acked,
			"created_at": msg.CreatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// testBridgeCreateMessage creates (or idempotently re-creates) a test message.
func (s *Server) testBridgeCreateMessage(w http.ResponseWriter, r *http.Request) {
	if !s.testBridgeAuthenticate(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Channel   string                 `json:"channel"`
		Target    string                 `json:"target"`
		MessageID string                 `json:"message_id"`
		Payload   map[string]interface{} `json:"payload"`
	}
	if !decodeTestBridgeJSON(w, r, &req) {
		return
	}

	if !validTestBridgeID(req.Channel, testOnlyMaxChannelLength) {
		http.Error(w, "channel is required", http.StatusBadRequest)
		return
	}
	if req.Target != "host" && req.Target != "mobile" {
		http.Error(w, "target must be 'host' or 'mobile'", http.StatusBadRequest)
		return
	}
	if !validTestBridgeID(req.MessageID, testOnlyMaxMessageIDLength) {
		http.Error(w, "message_id is required", http.StatusBadRequest)
		return
	}

	payloadBytes, err := json.Marshal(req.Payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	id, isNew, err := s.testBridge.Store(req.Channel, req.Target, req.MessageID, string(payloadBytes))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":         id,
		"new":        isNew,
		"channel":    req.Channel,
		"target":     req.Target,
		"message_id": req.MessageID,
	})
}

// testBridgeHandleAck handles POST /v1/test/ack.
func (s *Server) testBridgeHandleAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.testBridgeAuthenticate(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Channel    string   `json:"channel"`
		Target     string   `json:"target"`
		MessageIDs []string `json:"message_ids"`
	}
	if !decodeTestBridgeJSON(w, r, &req) {
		return
	}

	if !validTestBridgeID(req.Channel, testOnlyMaxChannelLength) {
		http.Error(w, "channel is required", http.StatusBadRequest)
		return
	}
	if req.Target != "host" && req.Target != "mobile" {
		http.Error(w, "target must be 'host' or 'mobile'", http.StatusBadRequest)
		return
	}
	for _, messageID := range req.MessageIDs {
		if !validTestBridgeID(messageID, testOnlyMaxMessageIDLength) {
			http.Error(w, "message_ids contains an invalid value", http.StatusBadRequest)
			return
		}
	}

	if err := s.testBridge.Ack(req.Channel, req.Target, req.MessageIDs); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"channel":     req.Channel,
		"target":      req.Target,
		"acked":       len(req.MessageIDs),
		"message_ids": req.MessageIDs,
	})
}

// testPilotPairingCreate creates a TEST-ONLY two-minute comparison challenge.
func (s *Server) testPilotPairingCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.testBridgeAuthenticate(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	store, ok := s.testPilotStore(w)
	if !ok {
		return
	}
	var req struct {
		Channel string `json:"channel"`
	}
	if !decodeTestBridgeJSON(w, r, &req) {
		return
	}
	if !validTestBridgeID(req.Channel, testOnlyMaxChannelLength) {
		http.Error(w, "invalid channel", http.StatusBadRequest)
		return
	}

	challenge, err := store.CreatePairingChallenge(req.Channel, TestOnlyPairingTTL)
	if err != nil {
		http.Error(w, "could not create pairing challenge", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"challenge_id":    challenge.ChallengeID,
		"comparison_code": challenge.Code,
		"expires_at":      challenge.ExpiresAt,
		"test_only":       true,
	})
}

// testPilotPairingConfirm records one host/mobile comparison-code confirmation.
func (s *Server) testPilotPairingConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.testBridgeAuthenticate(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	store, ok := s.testPilotStore(w)
	if !ok {
		return
	}
	var req struct {
		Channel        string `json:"channel"`
		ChallengeID    string `json:"challenge_id"`
		Side           string `json:"side"`
		ComparisonCode string `json:"comparison_code"`
	}
	if !decodeTestBridgeJSON(w, r, &req) {
		return
	}
	if !validPairingRequest(req.Channel, req.ChallengeID, req.Side, req.ComparisonCode) {
		http.Error(w, "invalid pairing confirmation", http.StatusBadRequest)
		return
	}
	state, err := store.ConfirmPairingChallenge(req.Channel, req.ChallengeID, req.Side, req.ComparisonCode)
	if err != nil {
		writeTestPairingError(w, err)
		return
	}
	writeTestPairingState(w, state)
}

// testPilotPairingConsume consumes a fully confirmed challenge exactly once.
func (s *Server) testPilotPairingConsume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.testBridgeAuthenticate(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	store, ok := s.testPilotStore(w)
	if !ok {
		return
	}
	var req struct {
		Channel     string `json:"channel"`
		ChallengeID string `json:"challenge_id"`
	}
	if !decodeTestBridgeJSON(w, r, &req) {
		return
	}
	if !validTestBridgeID(req.Channel, testOnlyMaxChannelLength) || !validTestBridgeID(req.ChallengeID, 64) {
		http.Error(w, "invalid pairing consume request", http.StatusBadRequest)
		return
	}
	state, err := store.ConsumePairingChallenge(req.Channel, req.ChallengeID)
	if err != nil {
		writeTestPairingError(w, err)
		return
	}
	writeTestPairingState(w, state)
}

// testPilotCleanupChannel removes all bridge messages and pairing state for a
// Pilot channel. Only aggregate deletion counts are returned.
func (s *Server) testPilotCleanupChannel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.testBridgeAuthenticate(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	store, ok := s.testPilotStore(w)
	if !ok {
		return
	}
	var req struct {
		Channel string `json:"channel"`
	}
	if !decodeTestBridgeJSON(w, r, &req) {
		return
	}
	if !validTestBridgeID(req.Channel, testOnlyMaxChannelLength) {
		http.Error(w, "invalid channel", http.StatusBadRequest)
		return
	}
	result, err := store.CleanupChannel(req.Channel)
	if err != nil {
		http.Error(w, "could not clean up channel", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"deleted_unacked_messages":   result.UnackedMessages,
		"deleted_acked_messages":     result.AckedMessages,
		"deleted_pairing_challenges": result.PairingChallenges,
	})
}

func validPairingRequest(channel, challengeID, side, code string) bool {
	if !validTestBridgeID(channel, testOnlyMaxChannelLength) || !validTestBridgeID(challengeID, 64) {
		return false
	}
	if side != "host" && side != "mobile" {
		return false
	}
	if len(code) != testOnlyPairingCodeDigits {
		return false
	}
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

func writeTestPairingState(w http.ResponseWriter, state testPairingChallengeState) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"challenge_id":     state.ChallengeID,
		"channel":          state.Channel,
		"expires_at":       state.ExpiresAt,
		"host_confirmed":   state.HostConfirmed,
		"mobile_confirmed": state.MobileConfirmed,
		"consumed":         state.Consumed,
		"test_only":        true,
	})
}

func writeTestPairingError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	code := "PAIRING_INTERNAL"
	switch {
	case errors.Is(err, ErrTestPairingNotFound):
		status, code = http.StatusNotFound, "PAIRING_NOT_FOUND"
	case errors.Is(err, ErrTestPairingExpired):
		status, code = http.StatusGone, "PAIRING_EXPIRED"
	case errors.Is(err, ErrTestPairingConsumed):
		status, code = http.StatusConflict, "PAIRING_CONSUMED"
	case errors.Is(err, ErrTestPairingCodeMismatch):
		status, code = http.StatusForbidden, "PAIRING_CODE_MISMATCH"
	case errors.Is(err, ErrTestPairingAlreadyConfirmed):
		status, code = http.StatusConflict, "PAIRING_CONFIRMATION_REPLAY"
	case errors.Is(err, ErrTestPairingConfirmationRequired):
		status, code = http.StatusConflict, "PAIRING_CONFIRMATION_REQUIRED"
	case errors.Is(err, ErrTestPairingInvalidSide):
		status, code = http.StatusBadRequest, "PAIRING_INVALID_SIDE"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error_code": code})
}

// --- WebSocket Hub ---

type wsHub struct {
	mu      sync.RWMutex
	clients map[string]map[*wsClient]bool
}

type wsClient struct {
	send chan []byte
	done chan struct{}
}

func newWSHub() *wsHub {
	return &wsHub{
		clients: make(map[string]map[*wsClient]bool),
	}
}

func (h *wsHub) subscribe(deviceHex string, c *wsClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	set, ok := h.clients[deviceHex]
	if !ok {
		set = make(map[*wsClient]bool)
		h.clients[deviceHex] = set
	}
	set[c] = true
}

func (h *wsHub) unsubscribe(deviceHex string, c *wsClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if set, ok := h.clients[deviceHex]; ok {
		delete(set, c)
		if len(set) == 0 {
			delete(h.clients, deviceHex)
		}
	}
	close(c.send)
	close(c.done)
}

func (h *wsHub) broadcastFrame(deviceID DeviceID, frameID string) {
	deviceHex := fmt.Sprintf("%x", deviceID[:])
	h.mu.RLock()
	defer h.mu.RUnlock()

	msg, _ := json.Marshal(map[string]interface{}{
		"type":     "frame_available",
		"device":   deviceHex,
		"frame_id": frameID,
	})
	for c := range h.clients[deviceHex] {
		select {
		case c.send <- msg:
		default:
		}
	}
}

// serveHTTP handles a WebSocket connection using stdlib only.
func (h *wsHub) serveHTTP(w http.ResponseWriter, r *http.Request) {
	deviceHex := r.URL.Query().Get("device")
	if deviceHex == "" {
		http.Error(w, "device query required", http.StatusBadRequest)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	secret := r.Header.Get("Sec-WebSocket-Key")
	accept := computeWSAccept(secret)
	bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	bufrw.WriteString("Upgrade: websocket\r\n")
	bufrw.WriteString("Connection: Upgrade\r\n")
	bufrw.WriteString(fmt.Sprintf("Sec-WebSocket-Accept: %s\r\n\r\n", accept))
	bufrw.Flush()

	client := &wsClient{
		send: make(chan []byte, 256),
		done: make(chan struct{}),
	}
	h.subscribe(deviceHex, client)
	defer h.unsubscribe(deviceHex, client)

	log.Printf("[relay][ws] device %s connected", deviceHex)

	go func() {
		defer close(client.done)
		for {
			f, err := readWSFrame(bufrw.Reader)
			if err != nil {
				return
			}
			switch f.opcode {
			case 0x9: // ping
				writeWSFrame(bufrw.Writer, 0xA, f.payload)
				bufrw.Flush()
			case 0x8: // close
				return
			}
		}
	}()

	for {
		select {
		case msg, ok := <-client.send:
			if !ok {
				return
			}
			writeWSFrame(bufrw.Writer, 0x1, msg)
			bufrw.Flush()
		case <-r.Context().Done():
			return
		case <-client.done:
			return
		}
	}
}

// --- Minimal WebSocket frame implementation (stdlib only) ---

func computeWSAccept(key string) string {
	const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	combined := key + magic
	s := sha1.New()
	s.Write([]byte(combined))
	return base64.StdEncoding.EncodeToString(s.Sum(nil))
}

type wsFrame struct {
	fin     bool
	opcode  byte
	payload []byte
}

func readWSFrame(r frameReader) (wsFrame, error) {
	b1, err := readByte(r)
	if err != nil {
		return wsFrame{}, err
	}
	b2, err := readByte(r)
	if err != nil {
		return wsFrame{}, err
	}

	fin := b1&0x80 != 0
	opcode := b1 & 0x0F
	masked := b2&0x80 != 0
	payloadLen := uint64(b2 & 0x7F)

	if payloadLen == 126 {
		b3, err := readByte(r)
		if err != nil {
			return wsFrame{}, err
		}
		b4, err := readByte(r)
		if err != nil {
			return wsFrame{}, err
		}
		payloadLen = uint64(b3)<<8 | uint64(b4)
	} else if payloadLen == 127 {
		var buf [8]byte
		for i := 7; i >= 0; i-- {
			b, err := readByte(r)
			if err != nil {
				return wsFrame{}, err
			}
			buf[i] = b
		}
		for i := 0; i < 8; i++ {
			payloadLen = payloadLen<<8 | uint64(buf[i])
		}
	}

	var mask [4]byte
	if masked {
		for i := 0; i < 4; i++ {
			b, err := readByte(r)
			if err != nil {
				return wsFrame{}, err
			}
			mask[i] = b
		}
	}

	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		buf := make([]byte, payloadLen)
		if _, err := readFull(r, buf); err != nil {
			return wsFrame{}, err
		}
		if masked {
			for i := range buf {
				payload[i] = buf[i] ^ mask[i%4]
			}
		} else {
			copy(payload, buf)
		}
	}

	return wsFrame{fin: fin, opcode: opcode, payload: payload}, nil
}

func writeWSFrame(w frameWriter, opcode byte, payload []byte) {
	frame := make([]byte, 0, 2+len(payload)+8)
	frame = append(frame, 0x80|(opcode&0x0F))
	payloadLen := len(payload)
	switch {
	case payloadLen < 126:
		frame = append(frame, byte(payloadLen))
	case payloadLen < 65536:
		frame = append(frame, 126, byte(payloadLen>>8), byte(payloadLen))
	default:
		frame = append(frame, 127)
		for i := 7; i >= 0; i-- {
			frame = append(frame, byte(payloadLen>>(i*8)))
		}
	}
	frame = append(frame, payload...)
	w.Write(frame)
}

type frameReader interface {
	Read([]byte) (int, error)
}

type frameWriter interface {
	Write([]byte) (int, error)
}

func readByte(r frameReader) (byte, error) {
	var buf [1]byte
	_, err := r.Read(buf[:])
	return buf[0], err
}

func readFull(r frameReader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
