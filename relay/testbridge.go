package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

const (
	// TestOnlyPairingTTL is intentionally fixed for the Controlled Pilot bridge.
	// The TEST-ONLY bridge is not a production identity or E2EE mechanism.
	TestOnlyPairingTTL = 2 * time.Minute

	testOnlyPairingCodeDigits  = 6
	testOnlyMaxChannelLength   = 128
	testOnlyMaxMessageIDLength = 256
	TestOnlyMaxJSONBody        = 64 * 1024
)

var (
	ErrTestPairingNotFound             = errors.New("relay/testbridge: pairing challenge not found")
	ErrTestPairingExpired              = errors.New("relay/testbridge: pairing challenge expired")
	ErrTestPairingConsumed             = errors.New("relay/testbridge: pairing challenge consumed")
	ErrTestPairingCodeMismatch         = errors.New("relay/testbridge: pairing code mismatch")
	ErrTestPairingAlreadyConfirmed     = errors.New("relay/testbridge: pairing side already confirmed")
	ErrTestPairingConfirmationRequired = errors.New("relay/testbridge: both pairing confirmations required")
	ErrTestPairingInvalidSide          = errors.New("relay/testbridge: pairing side must be host or mobile")
)

// testMessage is a single test-bridge message stored in the SQLite test_messages table.
type testMessage struct {
	ID        int64  `json:"id"`
	Channel   string `json:"channel"`
	Target    string `json:"target"`
	MessageID string `json:"message_id"`
	Payload   string `json:"payload"`
	Acked     bool   `json:"acked"`
	CreatedAt int64  `json:"created_at"`
}

// testPairingChallenge is TEST-ONLY Pilot pairing state. The six-digit code is
// returned once at creation and is never stored; only its salted hash persists.
type testPairingChallenge struct {
	ChallengeID       string
	Channel           string
	CodeSalt          []byte
	CodeHash          []byte
	ExpiresAt         int64
	HostConfirmedAt   sql.NullInt64
	MobileConfirmedAt sql.NullInt64
	ConsumedAt        sql.NullInt64
	CreatedAt         int64
}

type testPairingChallengeCreated struct {
	ChallengeID string
	Code        string
	ExpiresAt   int64
}

type testPairingChallengeState struct {
	ChallengeID     string
	Channel         string
	ExpiresAt       int64
	HostConfirmed   bool
	MobileConfirmed bool
	Consumed        bool
}

type testBridgeCleanupResult struct {
	UnackedMessages   int64
	AckedMessages     int64
	PairingChallenges int64
}

// TestBridgeStore provides the persistence layer for TEST-ONLY bridge messages.
type TestBridgeStore struct {
	db  *sql.DB
	now func() time.Time
}

// NewTestBridgeStore opens (or creates) a test-bridge message store.
// Pass the same *mailboxDB to share the underlying SQLite connection, or
// a standalone SQLite path (including :memory:) for independent use.
func NewTestBridgeStore(db *sql.DB) (*TestBridgeStore, error) {
	if db == nil {
		return nil, fmt.Errorf("relay/testbridge: nil db")
	}
	s := &TestBridgeStore{db: db, now: time.Now}
	if err := s.initSchema(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *TestBridgeStore) initSchema() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS test_messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			channel TEXT NOT NULL,
			target TEXT NOT NULL,
			message_id TEXT NOT NULL,
			payload TEXT NOT NULL,
			acked INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			UNIQUE(channel, target, message_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_test_messages_channel_target
			ON test_messages(channel, target, acked, id)`,
		`CREATE TABLE IF NOT EXISTS test_pairing_challenges (
			challenge_id TEXT PRIMARY KEY,
			channel TEXT NOT NULL,
			code_salt BLOB NOT NULL,
			code_hash BLOB NOT NULL,
			expires_at INTEGER NOT NULL,
			host_confirmed_at INTEGER,
			mobile_confirmed_at INTEGER,
			consumed_at INTEGER,
			created_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_test_pairing_channel
			ON test_pairing_challenges(channel, challenge_id)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("relay/testbridge: init schema: %w", err)
		}
	}
	return nil
}

// Store inserts a message or returns existing if idempotent on (channel, target, message_id).
// Returns (id, isNew, error).
func (s *TestBridgeStore) Store(channel, target, messageID string, payload string) (int64, bool, error) {
	now := time.Now().Unix()

	res, err := s.db.Exec(
		`INSERT INTO test_messages (channel, target, message_id, payload, acked, created_at)
		 VALUES (?, ?, ?, ?, 0, ?)
		 ON CONFLICT(channel, target, message_id) DO NOTHING`,
		channel, target, messageID, payload, now,
	)
	if err != nil {
		return 0, false, err
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected > 0 {
		id, _ := res.LastInsertId()
		return id, true, nil
	}

	// Conflict — existing. Look up its id.
	var id int64
	err = s.db.QueryRow(
		`SELECT id FROM test_messages WHERE channel = ? AND target = ? AND message_id = ?`,
		channel, target, messageID,
	).Scan(&id)
	if err != nil {
		return 0, false, err
	}
	return id, false, nil
}

// ListUnacked returns unacked messages for the given channel/target in insertion order.
func (s *TestBridgeStore) ListUnacked(channel, target string) ([]testMessage, error) {
	rows, err := s.db.Query(
		`SELECT id, channel, target, message_id, payload, acked, created_at
		 FROM test_messages
		 WHERE channel = ? AND target = ? AND acked = 0
		 ORDER BY id ASC`,
		channel, target,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var msgs []testMessage
	for rows.Next() {
		var m testMessage
		if err := rows.Scan(&m.ID, &m.Channel, &m.Target, &m.MessageID, &m.Payload, &m.Acked, &m.CreatedAt); err != nil {
			return nil, err
		}
		msgs = append(msgs, m)
	}
	return msgs, rows.Err()
}

// Ack marks one or more message_ids as delivered. Idempotent.
func (s *TestBridgeStore) Ack(channel, target string, messageIDs []string) error {
	if len(messageIDs) == 0 {
		return nil
	}

	placeholders := make([]string, len(messageIDs))
	args := make([]interface{}, 0, len(messageIDs)+2)
	args = append(args, channel, target)
	for i, mid := range messageIDs {
		placeholders[i] = "?"
		args = append(args, mid)
	}

	query := fmt.Sprintf(
		`UPDATE test_messages SET acked = 1
		 WHERE channel = ? AND target = ? AND message_id IN (%s)`,
		strings.Join(placeholders, ","),
	)
	_, err := s.db.Exec(query, args...)
	return err
}

// CreatePairingChallenge creates a TEST-ONLY one-time six-digit challenge.
// The plaintext code is returned to the caller but never persisted.
func (s *TestBridgeStore) CreatePairingChallenge(channel string, ttl time.Duration) (testPairingChallengeCreated, error) {
	challengeID, err := randomHex(16)
	if err != nil {
		return testPairingChallengeCreated{}, err
	}
	salt, err := randomBytes(16)
	if err != nil {
		return testPairingChallengeCreated{}, err
	}
	code, err := randomPairingCode()
	if err != nil {
		return testPairingChallengeCreated{}, err
	}

	now := s.now()
	expiresAt := now.Add(ttl).Unix()
	codeHash := pairingCodeHash(salt, code)
	_, err = s.db.Exec(
		`INSERT INTO test_pairing_challenges
		 (challenge_id, channel, code_salt, code_hash, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		challengeID, channel, salt, codeHash, expiresAt, now.Unix(),
	)
	if err != nil {
		return testPairingChallengeCreated{}, err
	}
	return testPairingChallengeCreated{ChallengeID: challengeID, Code: code, ExpiresAt: expiresAt}, nil
}

// ConfirmPairingChallenge records one side's comparison-code confirmation. A
// side can confirm only once; expired, consumed, mismatched, and replayed
// confirmations are rejected.
func (s *TestBridgeStore) ConfirmPairingChallenge(channel, challengeID, side, code string) (testPairingChallengeState, error) {
	if side != "host" && side != "mobile" {
		return testPairingChallengeState{}, ErrTestPairingInvalidSide
	}

	tx, err := s.db.Begin()
	if err != nil {
		return testPairingChallengeState{}, err
	}
	defer tx.Rollback()

	challenge, err := getPairingChallenge(tx, channel, challengeID)
	if err != nil {
		return testPairingChallengeState{}, err
	}
	if err := validatePairingChallenge(challenge, code, s.now()); err != nil {
		return testPairingChallengeState{}, err
	}

	confirmedAt := s.now().Unix()
	var res sql.Result
	if side == "host" {
		if challenge.HostConfirmedAt.Valid {
			return testPairingChallengeState{}, ErrTestPairingAlreadyConfirmed
		}
		challenge.HostConfirmedAt = sql.NullInt64{Int64: confirmedAt, Valid: true}
		res, err = tx.Exec(
			`UPDATE test_pairing_challenges SET host_confirmed_at = ?
			 WHERE challenge_id = ? AND channel = ? AND host_confirmed_at IS NULL`,
			confirmedAt, challengeID, channel,
		)
	} else {
		if challenge.MobileConfirmedAt.Valid {
			return testPairingChallengeState{}, ErrTestPairingAlreadyConfirmed
		}
		challenge.MobileConfirmedAt = sql.NullInt64{Int64: confirmedAt, Valid: true}
		res, err = tx.Exec(
			`UPDATE test_pairing_challenges SET mobile_confirmed_at = ?
			 WHERE challenge_id = ? AND channel = ? AND mobile_confirmed_at IS NULL`,
			confirmedAt, challengeID, channel,
		)
	}
	if err != nil {
		return testPairingChallengeState{}, err
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return testPairingChallengeState{}, err
	}
	if rowsAffected != 1 {
		return testPairingChallengeState{}, ErrTestPairingAlreadyConfirmed
	}
	if err := tx.Commit(); err != nil {
		return testPairingChallengeState{}, err
	}
	return pairingChallengeState(challenge), nil
}

// ConsumePairingChallenge completes a challenge only after both sides have
// confirmed. Consumption is one-time and persisted across relay restarts.
func (s *TestBridgeStore) ConsumePairingChallenge(channel, challengeID string) (testPairingChallengeState, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return testPairingChallengeState{}, err
	}
	defer tx.Rollback()

	challenge, err := getPairingChallenge(tx, channel, challengeID)
	if err != nil {
		return testPairingChallengeState{}, err
	}
	if challenge.ConsumedAt.Valid {
		return testPairingChallengeState{}, ErrTestPairingConsumed
	}
	if s.now().Unix() >= challenge.ExpiresAt {
		return testPairingChallengeState{}, ErrTestPairingExpired
	}
	if !challenge.HostConfirmedAt.Valid || !challenge.MobileConfirmedAt.Valid {
		return testPairingChallengeState{}, ErrTestPairingConfirmationRequired
	}

	consumedAt := s.now().Unix()
	res, err := tx.Exec(
		`UPDATE test_pairing_challenges SET consumed_at = ?
		 WHERE challenge_id = ? AND channel = ? AND consumed_at IS NULL`,
		consumedAt, challengeID, channel,
	)
	if err != nil {
		return testPairingChallengeState{}, err
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return testPairingChallengeState{}, err
	}
	if rowsAffected != 1 {
		return testPairingChallengeState{}, ErrTestPairingConsumed
	}
	challenge.ConsumedAt = sql.NullInt64{Int64: consumedAt, Valid: true}
	if err := tx.Commit(); err != nil {
		return testPairingChallengeState{}, err
	}
	return pairingChallengeState(challenge), nil
}

// CleanupChannel deletes all acknowledged and unacknowledged TEST-ONLY
// messages plus pairing state for one channel. It returns counts only.
func (s *TestBridgeStore) CleanupChannel(channel string) (testBridgeCleanupResult, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return testBridgeCleanupResult{}, err
	}
	defer tx.Rollback()

	var result testBridgeCleanupResult
	if err := tx.QueryRow(
		`SELECT COALESCE(SUM(CASE WHEN acked = 0 THEN 1 ELSE 0 END), 0),
		        COALESCE(SUM(CASE WHEN acked = 1 THEN 1 ELSE 0 END), 0)
		 FROM test_messages WHERE channel = ?`,
		channel,
	).Scan(&result.UnackedMessages, &result.AckedMessages); err != nil {
		return testBridgeCleanupResult{}, err
	}
	if err := tx.QueryRow(
		`SELECT COUNT(*) FROM test_pairing_challenges WHERE channel = ?`,
		channel,
	).Scan(&result.PairingChallenges); err != nil {
		return testBridgeCleanupResult{}, err
	}
	if _, err := tx.Exec(`DELETE FROM test_messages WHERE channel = ?`, channel); err != nil {
		return testBridgeCleanupResult{}, err
	}
	if _, err := tx.Exec(`DELETE FROM test_pairing_challenges WHERE channel = ?`, channel); err != nil {
		return testBridgeCleanupResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return testBridgeCleanupResult{}, err
	}
	return result, nil
}

type pairingChallengeQuerier interface {
	QueryRow(query string, args ...interface{}) *sql.Row
}

func getPairingChallenge(q pairingChallengeQuerier, channel, challengeID string) (testPairingChallenge, error) {
	var challenge testPairingChallenge
	err := q.QueryRow(
		`SELECT challenge_id, channel, code_salt, code_hash, expires_at,
		        host_confirmed_at, mobile_confirmed_at, consumed_at, created_at
		 FROM test_pairing_challenges WHERE challenge_id = ? AND channel = ?`,
		challengeID, channel,
	).Scan(
		&challenge.ChallengeID, &challenge.Channel, &challenge.CodeSalt, &challenge.CodeHash,
		&challenge.ExpiresAt, &challenge.HostConfirmedAt, &challenge.MobileConfirmedAt,
		&challenge.ConsumedAt, &challenge.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return testPairingChallenge{}, ErrTestPairingNotFound
	}
	return challenge, err
}

func validatePairingChallenge(challenge testPairingChallenge, code string, now time.Time) error {
	if challenge.ConsumedAt.Valid {
		return ErrTestPairingConsumed
	}
	if now.Unix() >= challenge.ExpiresAt {
		return ErrTestPairingExpired
	}
	want := pairingCodeHash(challenge.CodeSalt, code)
	if subtle.ConstantTimeCompare(want, challenge.CodeHash) != 1 {
		return ErrTestPairingCodeMismatch
	}
	return nil
}

func pairingChallengeState(challenge testPairingChallenge) testPairingChallengeState {
	return testPairingChallengeState{
		ChallengeID:     challenge.ChallengeID,
		Channel:         challenge.Channel,
		ExpiresAt:       challenge.ExpiresAt,
		HostConfirmed:   challenge.HostConfirmedAt.Valid,
		MobileConfirmed: challenge.MobileConfirmedAt.Valid,
		Consumed:        challenge.ConsumedAt.Valid,
	}
}

func pairingCodeHash(salt []byte, code string) []byte {
	data := make([]byte, 0, len(salt)+len(code))
	data = append(data, salt...)
	data = append(data, code...)
	sum := sha256.Sum256(data)
	return sum[:]
}

func randomPairingCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", fmt.Errorf("relay/testbridge: generate pairing code: %w", err)
	}
	return fmt.Sprintf("%0*d", testOnlyPairingCodeDigits, n.Int64()), nil
}

func randomHex(size int) (string, error) {
	b, err := randomBytes(size)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("relay/testbridge: generate random value: %w", err)
	}
	return b, nil
}

// --- In-memory fallback store (for tests that want no SQLite) ---

// InMemoryTestBridgeStore is a non-persistent store backed by a slice and map.
// It is safe for concurrent use.
type InMemoryTestBridgeStore struct {
	mu     sync.Mutex
	items  []testMessage
	byKey  map[string]int64 // "channel|target|message_id" -> id counter
	nextID int64
}

// NewInMemoryTestBridgeStore creates a new in-memory test bridge store.
func NewInMemoryTestBridgeStore() *InMemoryTestBridgeStore {
	return &InMemoryTestBridgeStore{
		byKey: make(map[string]int64),
	}
}

func memKey(channel, target, messageID string) string {
	return channel + "|" + target + "|" + messageID
}

// Store inserts a message or returns existing if idempotent on (channel, target, message_id).
func (m *InMemoryTestBridgeStore) Store(channel, target, messageID string, payload string) (int64, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := memKey(channel, target, messageID)
	if id, exists := m.byKey[key]; exists {
		return id, false, nil
	}

	m.nextID++
	now := time.Now().Unix()
	msg := testMessage{
		ID:        m.nextID,
		Channel:   channel,
		Target:    target,
		MessageID: messageID,
		Payload:   payload,
		Acked:     false,
		CreatedAt: now,
	}
	m.items = append(m.items, msg)
	m.byKey[key] = m.nextID
	return m.nextID, true, nil
}

// ListUnacked returns unacked messages for the given channel/target in insertion order.
func (m *InMemoryTestBridgeStore) ListUnacked(channel, target string) ([]testMessage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []testMessage
	for _, msg := range m.items {
		if msg.Channel == channel && msg.Target == target && !msg.Acked {
			result = append(result, msg)
		}
	}
	return result, nil
}

// Ack marks messages as delivered. Idempotent.
func (m *InMemoryTestBridgeStore) Ack(channel, target string, messageIDs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(messageIDs) == 0 {
		return nil
	}

	set := make(map[string]bool, len(messageIDs))
	for _, mid := range messageIDs {
		set[mid] = true
	}

	for i := range m.items {
		if m.items[i].Channel == channel && m.items[i].Target == target && set[m.items[i].MessageID] {
			m.items[i].Acked = true
		}
	}
	return nil
}

// TestBridgeStore is the interface for the TEST-ONLY bridge message store.
type TestBridgeStorage interface {
	Store(channel, target, messageID string, payload string) (int64, bool, error)
	ListUnacked(channel, target string) ([]testMessage, error)
	Ack(channel, target string, messageIDs []string) error
}

// testPilotBridgeStorage extends the legacy message bridge with Controlled
// Pilot pairing and cleanup. It remains explicitly TEST-ONLY.
type testPilotBridgeStorage interface {
	TestBridgeStorage
	CreatePairingChallenge(channel string, ttl time.Duration) (testPairingChallengeCreated, error)
	ConfirmPairingChallenge(channel, challengeID, side, code string) (testPairingChallengeState, error)
	ConsumePairingChallenge(channel, challengeID string) (testPairingChallengeState, error)
	CleanupChannel(channel string) (testBridgeCleanupResult, error)
}

// --- Helpers ---

// TestBridgeEnvelopeJSON returns a test message as JSON bytes (useful for tests).
func TestBridgeEnvelopeJSON(m testMessage) []byte {
	b, _ := json.Marshal(m)
	return b
}
