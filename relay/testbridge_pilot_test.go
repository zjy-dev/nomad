package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestPilotPairingChallengeLifecycle(t *testing.T) {
	db, err := NewMailboxDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewTestBridgeStore(db.DB())
	if err != nil {
		t.Fatal(err)
	}

	base := time.Unix(2_000_000_000, 0)
	store.now = func() time.Time { return base }
	created, err := store.CreatePairingChallenge("pilot-pairing", TestOnlyPairingTTL)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9]{6}$`).MatchString(created.Code) {
		t.Fatalf("comparison code must be six digits, got %q", created.Code)
	}
	if created.ExpiresAt != base.Add(2*time.Minute).Unix() {
		t.Fatalf("unexpected expiry: %d", created.ExpiresAt)
	}

	wrongCode := "000000"
	if created.Code == wrongCode {
		wrongCode = "000001"
	}
	if _, err := store.ConfirmPairingChallenge("pilot-pairing", created.ChallengeID, "host", wrongCode); !errors.Is(err, ErrTestPairingCodeMismatch) {
		t.Fatalf("wrong code error = %v", err)
	}
	if _, err := store.ConsumePairingChallenge("pilot-pairing", created.ChallengeID); !errors.Is(err, ErrTestPairingConfirmationRequired) {
		t.Fatalf("early consume error = %v", err)
	}

	hostState, err := store.ConfirmPairingChallenge("pilot-pairing", created.ChallengeID, "host", created.Code)
	if err != nil {
		t.Fatal(err)
	}
	if !hostState.HostConfirmed || hostState.MobileConfirmed || hostState.Consumed {
		t.Fatalf("unexpected host confirmation state: %+v", hostState)
	}
	if _, err := store.ConfirmPairingChallenge("pilot-pairing", created.ChallengeID, "host", created.Code); !errors.Is(err, ErrTestPairingAlreadyConfirmed) {
		t.Fatalf("confirmation replay error = %v", err)
	}

	mobileState, err := store.ConfirmPairingChallenge("pilot-pairing", created.ChallengeID, "mobile", created.Code)
	if err != nil {
		t.Fatal(err)
	}
	if !mobileState.HostConfirmed || !mobileState.MobileConfirmed || mobileState.Consumed {
		t.Fatalf("unexpected two-sided confirmation state: %+v", mobileState)
	}
	consumed, err := store.ConsumePairingChallenge("pilot-pairing", created.ChallengeID)
	if err != nil {
		t.Fatal(err)
	}
	if !consumed.Consumed {
		t.Fatal("challenge was not consumed")
	}
	if _, err := store.ConsumePairingChallenge("pilot-pairing", created.ChallengeID); !errors.Is(err, ErrTestPairingConsumed) {
		t.Fatalf("consume replay error = %v", err)
	}
	if _, err := store.ConfirmPairingChallenge("pilot-pairing", created.ChallengeID, "mobile", created.Code); !errors.Is(err, ErrTestPairingConsumed) {
		t.Fatalf("consumed confirmation error = %v", err)
	}
}

func TestPilotPairingChallengeExpires(t *testing.T) {
	db, err := NewMailboxDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewTestBridgeStore(db.DB())
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(2_000_000_000, 0)
	store.now = func() time.Time { return now }
	created, err := store.CreatePairingChallenge("expiring", TestOnlyPairingTTL)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(TestOnlyPairingTTL)
	if _, err := store.ConfirmPairingChallenge("expiring", created.ChallengeID, "host", created.Code); !errors.Is(err, ErrTestPairingExpired) {
		t.Fatalf("expired confirmation error = %v", err)
	}
	if _, err := store.ConsumePairingChallenge("expiring", created.ChallengeID); !errors.Is(err, ErrTestPairingExpired) {
		t.Fatalf("expired consume error = %v", err)
	}
}

func TestPilotCleanupChannelIsScopedAndIdempotent(t *testing.T) {
	db, err := NewMailboxDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewTestBridgeStore(db.DB())
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := store.Store("cleanup-me", "host", "acked", `{"type":"session.checkpoint"}`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Store("cleanup-me", "mobile", "unacked", `{"type":"command.result"}`); err != nil {
		t.Fatal(err)
	}
	if err := store.Ack("cleanup-me", "host", []string{"acked"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreatePairingChallenge("cleanup-me", TestOnlyPairingTTL); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Store("keep-me", "host", "keep", `{"type":"session.checkpoint"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreatePairingChallenge("keep-me", TestOnlyPairingTTL); err != nil {
		t.Fatal(err)
	}

	result, err := store.CleanupChannel("cleanup-me")
	if err != nil {
		t.Fatal(err)
	}
	if result != (testBridgeCleanupResult{UnackedMessages: 1, AckedMessages: 1, PairingChallenges: 1}) {
		t.Fatalf("unexpected cleanup counts: %+v", result)
	}
	result, err = store.CleanupChannel("cleanup-me")
	if err != nil {
		t.Fatal(err)
	}
	if result != (testBridgeCleanupResult{}) {
		t.Fatalf("idempotent cleanup counts: %+v", result)
	}
	kept, err := store.ListUnacked("keep-me", "host")
	if err != nil || len(kept) != 1 {
		t.Fatalf("other channel was affected: count=%d err=%v", len(kept), err)
	}
}

func TestPilotSQLiteRecoveryAcrossRealReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pilot-relay.sqlite")
	payload := `{"type":"session.checkpoint","freshness":"live"}`

	db1, err := NewMailboxDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	store1, err := NewTestBridgeStore(db1.DB())
	if err != nil {
		t.Fatal(err)
	}
	id1, isNew, err := store1.Store("recovery", "mobile", "checkpoint-1", payload)
	if err != nil || !isNew {
		t.Fatalf("first store: id=%d new=%v err=%v", id1, isNew, err)
	}
	pairing, err := store1.CreatePairingChallenge("recovery", TestOnlyPairingTTL)
	if err != nil {
		t.Fatal(err)
	}
	for _, side := range []string{"host", "mobile"} {
		if _, err := store1.ConfirmPairingChallenge("recovery", pairing.ChallengeID, side, pairing.Code); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store1.ConsumePairingChallenge("recovery", pairing.ChallengeID); err != nil {
		t.Fatal(err)
	}
	if err := db1.Close(); err != nil {
		t.Fatal(err)
	}

	db2, err := NewMailboxDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	store2, err := NewTestBridgeStore(db2.DB())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store2.ConsumePairingChallenge("recovery", pairing.ChallengeID); !errors.Is(err, ErrTestPairingConsumed) {
		t.Fatalf("consumed pairing replay after restart error = %v", err)
	}
	messages, err := store2.ListUnacked("recovery", "mobile")
	if err != nil || len(messages) != 1 || messages[0].Payload != payload {
		t.Fatalf("unacked message did not recover: messages=%+v err=%v", messages, err)
	}
	id2, isNew, err := store2.Store("recovery", "mobile", "checkpoint-1", payload)
	if err != nil || isNew || id2 != id1 {
		t.Fatalf("replay after restart: id=%d new=%v err=%v", id2, isNew, err)
	}
	if err := store2.Ack("recovery", "mobile", []string{"checkpoint-1"}); err != nil {
		t.Fatal(err)
	}
	if err := db2.Close(); err != nil {
		t.Fatal(err)
	}

	db3, err := NewMailboxDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db3.Close()
	store3, err := NewTestBridgeStore(db3.DB())
	if err != nil {
		t.Fatal(err)
	}
	messages, err = store3.ListUnacked("recovery", "mobile")
	if err != nil || len(messages) != 0 {
		t.Fatalf("acked message reappeared: count=%d err=%v", len(messages), err)
	}
	id3, isNew, err := store3.Store("recovery", "mobile", "checkpoint-1", `{"type":"changed"}`)
	if err != nil || isNew || id3 != id1 {
		t.Fatalf("acked replay created a row: id=%d new=%v err=%v", id3, isNew, err)
	}
	var count int
	if err := db3.DB().QueryRow(
		`SELECT COUNT(*) FROM test_messages WHERE channel = ? AND target = ? AND message_id = ?`,
		"recovery", "mobile", "checkpoint-1",
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("message_id replay produced %d records", count)
	}
}

func TestPilotPairingHTTPAndPrivacySafeErrors(t *testing.T) {
	db, err := NewMailboxDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewTestBridgeStore(db.DB())
	if err != nil {
		t.Fatal(err)
	}
	_, ts := newTestServerWithBridge("127.0.0.1:0", store, "pilot-token")
	defer ts.Close()

	status, created := pilotJSONRequest(t, ts, "", "/v1/test/pairing/challenges", map[string]interface{}{"channel": "http-pair"})
	if status != http.StatusUnauthorized || created["comparison_code"] != nil {
		t.Fatalf("unauthorized creation leaked data: status=%d body=%v", status, created)
	}
	status, created = pilotJSONRequest(t, ts, "pilot-token", "/v1/test/pairing/challenges", map[string]interface{}{"channel": "http-pair"})
	if status != http.StatusCreated {
		t.Fatalf("create status=%d body=%v", status, created)
	}
	challengeID, _ := created["challenge_id"].(string)
	code, _ := created["comparison_code"].(string)
	if !regexp.MustCompile(`^[0-9]{6}$`).MatchString(code) {
		t.Fatalf("HTTP comparison code = %q", code)
	}

	wrongCode := "999999"
	if code == wrongCode {
		wrongCode = "999998"
	}
	confirm := map[string]interface{}{"channel": "http-pair", "challenge_id": challengeID, "side": "host", "comparison_code": wrongCode}
	status, response := pilotJSONRequest(t, ts, "pilot-token", "/v1/test/pairing/confirm", confirm)
	if status != http.StatusForbidden || response["error_code"] != "PAIRING_CODE_MISMATCH" {
		t.Fatalf("mismatch status=%d body=%v", status, response)
	}
	if response["comparison_code"] != nil || response["channel"] != nil {
		t.Fatalf("pairing error leaked request data: %v", response)
	}
	confirm["comparison_code"] = code
	for _, side := range []string{"host", "mobile"} {
		confirm["side"] = side
		status, response = pilotJSONRequest(t, ts, "pilot-token", "/v1/test/pairing/confirm", confirm)
		if status != http.StatusOK {
			t.Fatalf("confirm %s status=%d body=%v", side, status, response)
		}
	}
	consume := map[string]interface{}{"channel": "http-pair", "challenge_id": challengeID}
	status, response = pilotJSONRequest(t, ts, "pilot-token", "/v1/test/pairing/consume", consume)
	if status != http.StatusOK || response["consumed"] != true {
		t.Fatalf("consume status=%d body=%v", status, response)
	}
	status, response = pilotJSONRequest(t, ts, "pilot-token", "/v1/test/pairing/consume", consume)
	if status != http.StatusConflict || response["error_code"] != "PAIRING_CONSUMED" {
		t.Fatalf("consume replay status=%d body=%v", status, response)
	}
}

func TestPilotCleanupHTTPReturnsCountsOnly(t *testing.T) {
	db, err := NewMailboxDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewTestBridgeStore(db.DB())
	if err != nil {
		t.Fatal(err)
	}
	store.Store("cleanup-http", "mobile", "private-message-id", `{"secret":"do-not-return"}`)
	_, ts := newTestServerWithBridge("127.0.0.1:0", store, "pilot-token")
	defer ts.Close()

	status, response := pilotJSONRequest(t, ts, "pilot-token", "/v1/test/cleanup", map[string]interface{}{"channel": "cleanup-http"})
	if status != http.StatusOK || response["deleted_unacked_messages"] != float64(1) {
		t.Fatalf("cleanup status=%d body=%v", status, response)
	}
	encoded, _ := json.Marshal(response)
	if bytes.Contains(encoded, []byte("private-message-id")) || bytes.Contains(encoded, []byte("do-not-return")) {
		t.Fatalf("cleanup response leaked content: %s", encoded)
	}
}

func TestPilotHTTPRejectsOversizedBody(t *testing.T) {
	db, err := NewMailboxDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewTestBridgeStore(db.DB())
	if err != nil {
		t.Fatal(err)
	}
	_, ts := newTestServerWithBridge("127.0.0.1:0", store, "pilot-token")
	defer ts.Close()

	body := "{\"channel\":\"" + strings.Repeat("x", TestOnlyMaxJSONBody) + "\"}"
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/test/pairing/challenges", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer pilot-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d", resp.StatusCode)
	}
}

func pilotJSONRequest(t *testing.T, ts *httptest.Server, token, path string, body map[string]interface{}) (int, map[string]interface{}) {
	t.Helper()
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(bodyJSON))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	response := make(map[string]interface{})
	_ = json.NewDecoder(resp.Body).Decode(&response)
	return resp.StatusCode, response
}
