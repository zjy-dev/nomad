package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- helpers ---

func newTestServerWithBridge(addr string, store TestBridgeStorage, token string) (*Server, *httptest.Server) {
	db, _ := NewMailboxDB(":memory:")
	srv := NewServer(db, addr)
	if err := srv.SetTestBridge(store, token); err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	srv.registerTestBridgeRoutes(mux)
	ts := httptest.NewServer(mux)
	return srv, ts
}

func newTestServerWithoutBridge(addr string) (*Server, *httptest.Server) {
	db, _ := NewMailboxDB(":memory:")
	srv := NewServer(db, addr)
	mux := http.NewServeMux()
	srv.registerTestBridgeRoutes(mux)
	ts := httptest.NewServer(mux)
	return srv, ts
}

func authHeader(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func testCreateMessage(t *testing.T, ts *httptest.Server, token, channel, target, messageID string, payload map[string]interface{}) (int, int64, bool) {
	t.Helper()
	body := map[string]interface{}{
		"channel":    channel,
		"target":     target,
		"message_id": messageID,
		"payload":    payload,
	}
	bodyJSON, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/test/messages", bytes.NewReader(bodyJSON))
	for k, v := range authHeader(token) {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		ID  int64 `json:"id"`
		New bool  `json:"new"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return resp.StatusCode, result.ID, result.New
}

func testListMessages(t *testing.T, ts *httptest.Server, token, channel, target string) (int, []testMessage) {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+"/v1/test/messages?channel="+channel+"&target="+target, nil)
	for k, v := range authHeader(token) {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var msgs []testMessage
	json.NewDecoder(resp.Body).Decode(&msgs)
	return resp.StatusCode, msgs
}

func testAckMessages(t *testing.T, ts *httptest.Server, token, channel, target string, messageIDs []string) int {
	t.Helper()
	body := map[string]interface{}{
		"channel":     channel,
		"target":      target,
		"message_ids": messageIDs,
	}
	bodyJSON, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/test/ack", bytes.NewReader(bodyJSON))
	for k, v := range authHeader(token) {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode
}

// --- Tests ---

// TestTestBridgeOffByDefault verifies the test bridge returns 404 when not enabled.
func TestTestBridgeOffByDefault(t *testing.T) {
	_, ts := newTestServerWithoutBridge("127.0.0.1:0")
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/test/messages?channel=ch1&target=host")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /v1/test/messages: expected 404, got %d", resp.StatusCode)
	}

	resp2, err := http.Post(ts.URL+"/v1/test/messages", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("POST /v1/test/messages: expected 404, got %d", resp2.StatusCode)
	}

	resp3, err := http.Post(ts.URL+"/v1/test/ack", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp3.StatusCode != http.StatusNotFound {
		t.Errorf("POST /v1/test/ack: expected 404, got %d", resp3.StatusCode)
	}
}

// TestTestBridgeAuth verifies the Bearer token requirement.
func TestTestBridgeAuth(t *testing.T) {
	store := NewInMemoryTestBridgeStore()
	token := "test-secret-token"
	_, ts := newTestServerWithBridge("127.0.0.1:0", store, token)
	defer ts.Close()

	payload := map[string]interface{}{"key": "value"}

	// No auth header
	body, _ := json.Marshal(map[string]interface{}{
		"channel": "ch1", "target": "host", "message_id": "m1", "payload": payload,
	})
	resp, err := http.Post(ts.URL+"/v1/test/messages", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no auth: expected 401, got %d", resp.StatusCode)
	}

	// Wrong token
	req, _ := http.NewRequest("POST", ts.URL+"/v1/test/messages", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong token: expected 401, got %d", resp.StatusCode)
	}

	// Wrong scheme (no "Bearer " prefix)
	req, _ = http.NewRequest("POST", ts.URL+"/v1/test/messages", bytes.NewReader(body))
	req.Header.Set("Authorization", token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong scheme: expected 401, got %d", resp.StatusCode)
	}

	// Correct token succeeds
	status, _, _ := testCreateMessage(t, ts, token, "ch1", "host", "m1", payload)
	if status != http.StatusAccepted {
		t.Errorf("correct token: expected 202, got %d", status)
	}

	// GET also requires auth
	req, _ = http.NewRequest("GET", ts.URL+"/v1/test/messages?channel=ch1&target=host", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET no auth: expected 401, got %d", resp.StatusCode)
	}

	// ACK also requires auth
	ackBody, _ := json.Marshal(map[string]interface{}{
		"channel": "ch1", "target": "host", "message_ids": []string{"m1"},
	})
	req, _ = http.NewRequest("POST", ts.URL+"/v1/test/ack", bytes.NewReader(ackBody))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("ACK no auth: expected 401, got %d", resp.StatusCode)
	}
}

// TestTestBridgeIdempotency verifies that repeated messages with the same
// (channel, target, message_id) are idempotent.
func TestTestBridgeIdempotency(t *testing.T) {
	store := NewInMemoryTestBridgeStore()
	token := "tok1"
	_, ts := newTestServerWithBridge("127.0.0.1:0", store, token)
	defer ts.Close()

	payload := map[string]interface{}{"key": "value"}

	// First POST — should be new
	status1, id1, isNew1 := testCreateMessage(t, ts, token, "ch1", "host", "mid-1", payload)
	if status1 != http.StatusAccepted {
		t.Fatalf("first post: expected 202, got %d", status1)
	}
	if !isNew1 {
		t.Error("first post should be new")
	}

	// Second POST with same id — should NOT be new, but still return 202
	status2, id2, isNew2 := testCreateMessage(t, ts, token, "ch1", "host", "mid-1", payload)
	if status2 != http.StatusAccepted {
		t.Fatalf("second post: expected 202, got %d", status2)
	}
	if isNew2 {
		t.Error("second post should not be new (idempotent)")
	}
	if id1 != id2 {
		t.Errorf("id mismatch: first=%d, second=%d", id1, id2)
	}

	// Third POST — same behavior
	status3, id3, isNew3 := testCreateMessage(t, ts, token, "ch1", "host", "mid-1", payload)
	if status3 != http.StatusAccepted {
		t.Fatalf("third post: expected 202, got %d", status3)
	}
	if isNew3 {
		t.Error("third post should not be new")
	}
	if id1 != id3 {
		t.Errorf("id mismatch: first=%d, third=%d", id1, id3)
	}

	// Verify only one message appears in the list
	status, msgs := testListMessages(t, ts, token, "ch1", "host")
	if status != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", status)
	}
	if len(msgs) != 1 {
		t.Errorf("expected 1 message after idempotent re-posts, got %d", len(msgs))
	}
}

// TestTestBridgeACK verifies ACK removes messages from the list and is idempotent.
func TestTestBridgeACK(t *testing.T) {
	store := NewInMemoryTestBridgeStore()
	token := "tok1"
	_, ts := newTestServerWithBridge("127.0.0.1:0", store, token)
	defer ts.Close()

	p1 := map[string]interface{}{"type": "pair.request", "code": "123456"}
	p2 := map[string]interface{}{"type": "session.checkpoint", "needs_permission": true}
	p3 := map[string]interface{}{"type": "command", "action": "deny"}

	// Create three messages
	testCreateMessage(t, ts, token, "ch1", "host", "m1", p1)
	testCreateMessage(t, ts, token, "ch1", "host", "m2", p2)
	testCreateMessage(t, ts, token, "ch1", "host", "m3", p3)

	// Verify all three are visible
	status, msgs := testListMessages(t, ts, token, "ch1", "host")
	if status != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", status)
	}
	if len(msgs) != 3 {
		t.Fatalf("expected 3 unacked messages, got %d", len(msgs))
	}

	// ACK only m2
	status = testAckMessages(t, ts, token, "ch1", "host", []string{"m2"})
	if status != http.StatusOK {
		t.Fatalf("ack m2: expected 200, got %d", status)
	}

	// Verify m1 and m3 remain, m2 is gone
	_, msgs = testListMessages(t, ts, token, "ch1", "host")
	if len(msgs) != 2 {
		t.Fatalf("expected 2 unacked messages after ack, got %d", len(msgs))
	}
	for _, m := range msgs {
		if m.MessageID == "m2" {
			t.Error("m2 should have been acked and removed")
		}
	}

	// ACK all remaining
	status = testAckMessages(t, ts, token, "ch1", "host", []string{"m1", "m3"})
	if status != http.StatusOK {
		t.Fatalf("ack all: expected 200, got %d", status)
	}

	// List should be empty
	_, msgs = testListMessages(t, ts, token, "ch1", "host")
	if len(msgs) != 0 {
		t.Errorf("expected 0 unacked messages, got %d", len(msgs))
	}

	// Idempotent ACK — re-ACKing already-acked message
	status = testAckMessages(t, ts, token, "ch1", "host", []string{"m2", "m1", "m3"})
	if status != http.StatusOK {
		t.Fatalf("idempotent ack: expected 200, got %d", status)
	}

	// List still empty
	_, msgs = testListMessages(t, ts, token, "ch1", "host")
	if len(msgs) != 0 {
		t.Errorf("expected 0 after idempotent ack, got %d", len(msgs))
	}

	// Cross-target ACK: mobile target messages are independent
	testCreateMessage(t, ts, token, "ch1", "mobile", "m1", p1)
	_, msgs = testListMessages(t, ts, token, "ch1", "mobile")
	if len(msgs) != 1 {
		t.Errorf("mobile should have 1 message, got %d", len(msgs))
	}

	// ACK host m1 should not affect mobile m1
	status = testAckMessages(t, ts, token, "ch1", "host", []string{"m1"})
	_, msgs = testListMessages(t, ts, token, "ch1", "mobile")
	if len(msgs) != 1 {
		t.Errorf("mobile should still have 1 message, got %d", len(msgs))
	}
}

// TestTestBridgeLoopback verifies the server rejects test bridge enablement
// on non-loopback addresses.
func TestTestBridgeLoopback(t *testing.T) {
	store := NewInMemoryTestBridgeStore()

	// Loopback address should succeed
	db, _ := NewMailboxDB(":memory:")
	srv1 := NewServer(db, "127.0.0.1:8089")
	if err := srv1.SetTestBridge(store, "tok"); err != nil {
		t.Errorf("127.0.0.1 should succeed, got: %v", err)
	}
	if !srv1.testBridgeEnabled {
		t.Error("test bridge should be enabled")
	}

	// ::1 should succeed
	srv2 := NewServer(db, "[::1]:8089")
	if err := srv2.SetTestBridge(store, "tok"); err != nil {
		t.Errorf("::1 should succeed, got: %v", err)
	}

	// Non-loopback should fail
	srv3 := NewServer(db, "0.0.0.0:8089")
	if err := srv3.SetTestBridge(store, "tok"); err == nil {
		t.Error("0.0.0.0 should be rejected")
	}

	// Wildcard should fail
	srv4 := NewServer(db, ":8089")
	if err := srv4.SetTestBridge(store, "tok"); err == nil {
		t.Error("wildcard addr should be rejected")
	}

	// Empty store should fail
	srv5 := NewServer(db, "127.0.0.1:8089")
	if err := srv5.SetTestBridge(nil, "tok"); err == nil {
		t.Error("nil store should be rejected")
	}

	// Empty token should fail
	srv6 := NewServer(db, "127.0.0.1:8089")
	if err := srv6.SetTestBridge(store, ""); err == nil {
		t.Error("empty token should be rejected")
	}
}

// TestTestBridgeOrderedList verifies messages are returned in insertion order.
func TestTestBridgeOrderedList(t *testing.T) {
	store := NewInMemoryTestBridgeStore()
	token := "tok1"
	_, ts := newTestServerWithBridge("127.0.0.1:0", store, token)
	defer ts.Close()

	for i := 0; i < 5; i++ {
		testCreateMessage(t, ts, token, "ch1", "host", fmt.Sprintf("m%d", i),
			map[string]interface{}{"order": i})
	}

	_, msgs := testListMessages(t, ts, token, "ch1", "host")
	if len(msgs) != 5 {
		t.Fatalf("expected 5 messages, got %d", len(msgs))
	}
	for i, m := range msgs {
		expectedID := fmt.Sprintf("m%d", i)
		if m.MessageID != expectedID {
			t.Errorf("order mismatch at index %d: got %s, want %s", i, m.MessageID, expectedID)
		}
	}
}

// TestTestBridgeInvalidInput verifies validation of input fields.
func TestTestBridgeInvalidInput(t *testing.T) {
	store := NewInMemoryTestBridgeStore()
	token := "tok1"
	_, ts := newTestServerWithBridge("127.0.0.1:0", store, token)
	defer ts.Close()

	tests := []struct {
		name   string
		body   map[string]interface{}
		method string
		url    string
	}{
		{"empty channel", map[string]interface{}{"channel": "", "target": "host", "message_id": "m1", "payload": map[string]interface{}{}}, "POST", "/v1/test/messages"},
		{"invalid target", map[string]interface{}{"channel": "ch1", "target": "server", "message_id": "m1", "payload": map[string]interface{}{}}, "POST", "/v1/test/messages"},
		{"empty message_id", map[string]interface{}{"channel": "ch1", "target": "host", "message_id": "", "payload": map[string]interface{}{}}, "POST", "/v1/test/messages"},
		{"empty channel list", nil, "GET", "/v1/test/messages?target=host"},
		{"invalid target list", nil, "GET", "/v1/test/messages?channel=ch1&target=server"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var req *http.Request
			if tc.method == "GET" {
				req, _ = http.NewRequest("GET", ts.URL+tc.url, nil)
			} else {
				bodyJSON, _ := json.Marshal(tc.body)
				req, _ = http.NewRequest("POST", ts.URL+tc.url, bytes.NewReader(bodyJSON))
			}
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusBadRequest {
				body := new(bytes.Buffer)
				body.ReadFrom(resp.Body)
				t.Errorf("expected 400, got %d: %s", resp.StatusCode, body.String())
			}
		})
	}
}

// TestTestBridgeSQLiteStore verifies the SQLite-backed store works identically.
func TestTestBridgeSQLiteStore(t *testing.T) {
	db, _ := NewMailboxDB(":memory:")
	store, err := NewTestBridgeStore(db.DB())
	if err != nil {
		t.Fatal(err)
	}

	token := "sql-token"
	_, ts := newTestServerWithBridge("127.0.0.1:0", store, token)
	defer ts.Close()

	payload := map[string]interface{}{"type": "pair.request", "code": "999999"}

	// Create
	status, _, isNew := testCreateMessage(t, ts, token, "pair", "host", "code-1", payload)
	if status != http.StatusAccepted || !isNew {
		t.Fatalf("create: status=%d isNew=%v", status, isNew)
	}

	// Idempotent re-create
	status, _, isNew = testCreateMessage(t, ts, token, "pair", "host", "code-1", payload)
	if status != http.StatusAccepted || isNew {
		t.Fatalf("idempotent: status=%d isNew=%v", status, isNew)
	}

	// List
	status, msgs := testListMessages(t, ts, token, "pair", "host")
	if status != http.StatusOK || len(msgs) != 1 {
		t.Fatalf("list: status=%d count=%d", status, len(msgs))
	}

	// ACK
	status = testAckMessages(t, ts, token, "pair", "host", []string{"code-1"})
	if status != http.StatusOK {
		t.Fatalf("ack: status=%d", status)
	}

	// Empty after ACK
	status, msgs = testListMessages(t, ts, token, "pair", "host")
	if status != http.StatusOK || len(msgs) != 0 {
		t.Fatalf("after ack: status=%d count=%d", status, len(msgs))
	}
}

// TestTestBridgePerTargetIsolation verifies that host and mobile targets are independent.
func TestTestBridgePerTargetIsolation(t *testing.T) {
	store := NewInMemoryTestBridgeStore()
	token := "tok1"
	_, ts := newTestServerWithBridge("127.0.0.1:0", store, token)
	defer ts.Close()

	payload := map[string]interface{}{"text": "hello"}

	// Same channel+message_id but different targets
	testCreateMessage(t, ts, token, "ch1", "host", "m1", payload)
	testCreateMessage(t, ts, token, "ch1", "mobile", "m1", payload)

	// Both should exist independently
	_, hostMsgs := testListMessages(t, ts, token, "ch1", "host")
	if len(hostMsgs) != 1 || hostMsgs[0].MessageID != "m1" {
		t.Errorf("host: expected 1 message m1, got %d", len(hostMsgs))
	}

	_, mobileMsgs := testListMessages(t, ts, token, "ch1", "mobile")
	if len(mobileMsgs) != 1 || mobileMsgs[0].MessageID != "m1" {
		t.Errorf("mobile: expected 1 message m1, got %d", len(mobileMsgs))
	}

	// ACK host m1, mobile m1 should remain
	testAckMessages(t, ts, token, "ch1", "host", []string{"m1"})

	_, hostMsgs = testListMessages(t, ts, token, "ch1", "host")
	if len(hostMsgs) != 0 {
		t.Errorf("host should be empty after ACK, got %d", len(hostMsgs))
	}

	_, mobileMsgs = testListMessages(t, ts, token, "ch1", "mobile")
	if len(mobileMsgs) != 1 {
		t.Errorf("mobile should still have m1, got %d", len(mobileMsgs))
	}
}

// TestTestBridgeWebSocketRegistration verifies that test bridge enablement
// does NOT register a websocket connection (it is HTTP-only).
func TestTestBridgeWebSocketRegistration(t *testing.T) {
	store := NewInMemoryTestBridgeStore()
	token := "tok1"
	srv, _ := newTestServerWithBridge("127.0.0.1:0", store, token)

	// Verify the wsHub remains empty (no ws connections)
	srv.wsHub.mu.RLock()
	count := 0
	for _, clients := range srv.wsHub.clients {
		count += len(clients)
	}
	srv.wsHub.mu.RUnlock()

	if count != 0 {
		t.Errorf("expected 0 websocket connections, got %d", count)
	}
}

// TestTestBridgeInvalidMethodOnList verifies that POST on list endpoint and GET
// on create endpoint return proper method-not-allowed.
func TestTestBridgeInvalidMethodOnList(t *testing.T) {
	store := NewInMemoryTestBridgeStore()
	token := "tok1"
	_, ts := newTestServerWithBridge("127.0.0.1:0", store, token)
	defer ts.Close()

	// GET on /v1/test/messages without query params should fail validation,
	// not return 405. But POST without body should return 400.
	// The key test: GET on /v1/test/ack should be 405.
	req, _ := http.NewRequest("GET", ts.URL+"/v1/test/ack?channel=ch1&target=host", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /v1/test/ack: expected 405, got %d", resp.StatusCode)
	}

	// Ensure body reads were consumed properly
	body := new(bytes.Buffer)
	body.ReadFrom(resp.Body)
	if !strings.Contains(body.String(), "method not allowed") {
		t.Errorf("unexpected body: %s", body.String())
	}
}
