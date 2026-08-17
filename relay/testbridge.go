package relay

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
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

// TestBridgeStore provides the persistence layer for TEST-ONLY bridge messages.
type TestBridgeStore struct {
	db *sql.DB
}

// NewTestBridgeStore opens (or creates) a test-bridge message store.
// Pass the same *mailboxDB to share the underlying SQLite connection, or
// a standalone SQLite path (including :memory:) for independent use.
func NewTestBridgeStore(db *sql.DB) (*TestBridgeStore, error) {
	if db == nil {
		return nil, fmt.Errorf("relay/testbridge: nil db")
	}
	s := &TestBridgeStore{db: db}
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

// --- Helpers ---

// TestBridgeEnvelopeJSON returns a test message as JSON bytes (useful for tests).
func TestBridgeEnvelopeJSON(m testMessage) []byte {
	b, _ := json.Marshal(m)
	return b
}
