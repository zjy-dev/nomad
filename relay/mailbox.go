package relay

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type mailboxDB struct {
	db *sql.DB

	mu      sync.Mutex
	rate    map[DeviceID]*rateWindow // per-device rate limiting
	devices map[DeviceID]*deviceInfo
}

type deviceInfo struct {
	PubKey   ed25519.PublicKey
	LastSeen time.Time
}

type rateWindow struct {
	frames []time.Time // timestamps of recent frames
}

// frame is an opaque mailbox entry.
type frame struct {
	ID        int64
	DeviceID  DeviceID
	FrameID   string // content-hash-derived idempotency key
	Payload   []byte // opaque — never parsed
	Flags     uint16
	TTL       time.Time
	CreatedAt time.Time
	Acked     bool
}

// NewMailboxDB creates a new SQLite-backed mailbox at the given path.
// Use ":memory:" for ephemeral in-memory operation.
func NewMailboxDB(path string) (*mailboxDB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("relay: open db: %w", err)
	}
	db.SetMaxOpenConns(1)

	m := &mailboxDB{
		db:      db,
		rate:    make(map[DeviceID]*rateWindow),
		devices: make(map[DeviceID]*deviceInfo),
	}
	if err := m.initSchema(); err != nil {
		db.Close()
		return nil, err
	}
	return m, nil
}

func (m *mailboxDB) initSchema() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS devices (
			device_id BLOB PRIMARY KEY,
			pubkey BLOB NOT NULL,
			last_seen INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS frames (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id BLOB NOT NULL,
			frame_id TEXT NOT NULL,
			payload BLOB NOT NULL,
			flags INTEGER NOT NULL,
			ttl INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			acked INTEGER NOT NULL DEFAULT 0,
			FOREIGN KEY (device_id) REFERENCES devices(device_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_frames_device ON frames(device_id)`,
		`CREATE INDEX IF NOT EXISTS idx_frames_ttl ON frames(ttl)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_frames_idempotent ON frames(device_id, frame_id)`,
		`CREATE TABLE IF NOT EXISTS acks (
			device_id BLOB NOT NULL,
			frame_id TEXT NOT NULL,
			ack_at INTEGER NOT NULL,
			PRIMARY KEY (device_id, frame_id)
		)`,
	}
	for _, s := range stmts {
		if _, err := m.db.Exec(s); err != nil {
			return fmt.Errorf("relay: init schema: %w", err)
		}
	}
	return nil
}

// Close closes the underlying database.
func (m *mailboxDB) Close() error { return m.db.Close() }

// DB returns the underlying *sql.DB for use by sub-stores (e.g. TestBridgeStore).
func (m *mailboxDB) DB() *sql.DB { return m.db }

// RegisterDevice registers a device with its public key.
func (m *mailboxDB) RegisterDevice(id DeviceID, pubKey ed25519.PublicKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	m.devices[id] = &deviceInfo{PubKey: pubKey, LastSeen: now}

	_, err := m.db.Exec(
		`INSERT OR REPLACE INTO devices (device_id, pubkey, last_seen) VALUES (?, ?, ?)`,
		id[:], []byte(pubKey), now.Unix(),
	)
	return err
}

// GetDevice returns the public key for a registered device.
func (m *mailboxDB) GetDevice(id DeviceID) (ed25519.PublicKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if d, ok := m.devices[id]; ok {
		return d.PubKey, nil
	}
	// Fallback to DB
	var pubKey []byte
	err := m.db.QueryRow(`SELECT pubkey FROM devices WHERE device_id = ?`, id[:]).Scan(&pubKey)
	if err == sql.ErrNoRows {
		return nil, ErrDeviceNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("relay: invalid pubkey in db: %d bytes", len(pubKey))
	}
	pk := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pk, pubKey)
	m.devices[id] = &deviceInfo{PubKey: pk, LastSeen: time.Now()}
	return pk, nil
}

// rateLimit checks and updates per-device rate limit.
// Returns nil if allowed, ErrFrameRateLimited if exceeded.
func (m *mailboxDB) rateLimit(id DeviceID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	w, ok := m.rate[id]
	if !ok {
		w = &rateWindow{}
		m.rate[id] = w
	}

	// Prune entries older than 1 second
	cutoff := now.Add(-1 * time.Second)
	filtered := w.frames[:0]
	for _, t := range w.frames {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	w.frames = filtered

	if len(w.frames) >= MaxFramesPerSecond {
		return ErrFrameRateLimited
	}
	w.frames = append(w.frames, now)
	return nil
}

// frameID computes a content-hash-derived idempotency key for a payload.
// Uses the first 16 hex chars of SHA-256(deviceID + payload + nonce + timestamp).
func frameIDFrom(envelope *Envelope) string {
	nonceBytes := encodeUint64(envelope.Nonce)
	tsBytes := encodeUint64(uint64(envelope.Timestamp))
	parts := make([]byte, 0, len(envelope.DeviceID)+len(envelope.Payload)+len(nonceBytes)+len(tsBytes))
	parts = append(parts, envelope.DeviceID[:]...)
	parts = append(parts, envelope.Payload...)
	parts = append(parts, nonceBytes...)
	parts = append(parts, tsBytes...)
	h := sha256Sum(parts)
	return hex.EncodeToString(h[:8])
}

func sha256Sum(data []byte) [32]byte {
	sum := [32]byte{}
	c := crypto.SHA256.New()
	c.Write(data)
	copy(sum[:], c.Sum(nil))
	return sum
}

func encodeUint64(v uint64) []byte {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return b
}

// StoreFrame stores an opaque frame for the given device.
// Returns the frame's idempotency key and whether it was new (not a duplicate).
func (m *mailboxDB) StoreFrame(envelope *Envelope, ttl time.Duration) (frameID string, isNew bool, err error) {
	if len(envelope.Payload) == 0 {
		return "", false, ErrNoContent
	}
	if len(envelope.Payload) > MaxFrameSize {
		return "", false, ErrFrameTooLarge
	}

	deviceID := envelope.DeviceID
	if _, err := m.GetDevice(deviceID); err != nil {
		return "", false, err
	}

	if err := m.rateLimit(deviceID); err != nil {
		return "", false, err
	}

	// Check capacity (count unacked frames for this device)
	var count int
	err = m.db.QueryRow(
		`SELECT COUNT(*) FROM frames WHERE device_id = ? AND acked = 0`,
		deviceID[:],
	).Scan(&count)
	if err != nil {
		return "", false, err
	}
	if count >= MaxMailboxFrames {
		return "", false, ErrCapacityExceeded
	}

	fid := frameIDFrom(envelope)
	ttlExpiry := time.Now().Add(ttl).Unix()
	createdAt := time.Now().Unix()

	res, err := m.db.Exec(
		`INSERT INTO frames (device_id, frame_id, payload, flags, ttl, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(device_id, frame_id) DO NOTHING`,
		deviceID[:], fid, envelope.Payload, envelope.Flags, ttlExpiry, createdAt,
	)
	if err != nil {
		return "", false, err
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return fid, false, nil
	}
	return fid, true, nil
}

// DeliverableFrames returns up to limit undelivered (acked=0, ttl>now) frames for a device.
func (m *mailboxDB) DeliverableFrames(deviceID DeviceID, limit int) ([]*frame, error) {
	rows, err := m.db.Query(
		`SELECT id, device_id, frame_id, payload, flags, ttl, created_at
		 FROM frames
		 WHERE device_id = ? AND acked = 0 AND ttl > ?
		 ORDER BY id ASC
		 LIMIT ?`,
		deviceID[:], time.Now().Unix(), limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var frames []*frame
	for rows.Next() {
		var (
			id       int64
			devID    []byte
			fid      string
			payload  []byte
			flags    uint16
			ttl      int64
			created  int64
			devIDArr DeviceID
		)
		if err := rows.Scan(&id, &devID, &fid, &payload, &flags, &ttl, &created); err != nil {
			return nil, err
		}
		copy(devIDArr[:], devID)
		f := &frame{
			ID:        id,
			DeviceID:  devIDArr,
			FrameID:   fid,
			Payload:   payload,
			Flags:     flags,
			TTL:       time.Unix(ttl, 0),
			CreatedAt: time.Unix(created, 0),
			Acked:     false,
		}
		frames = append(frames, f)
	}
	return frames, rows.Err()
}

// AckFrames marks frames as delivered for the given device.
// frameIDs are the idempotency keys from the deliverable frames.
// This is idempotent — re-ACKing the same frames is safe.
func (m *mailboxDB) AckFrames(deviceID DeviceID, frameIDs []string) error {
	if len(frameIDs) == 0 {
		return nil
	}
	placeholders := make([]string, len(frameIDs))
	args := make([]interface{}, 0, len(frameIDs)+1)
	args = append(args, deviceID[:])
	for i, fid := range frameIDs {
		placeholders[i] = "?"
		args = append(args, fid)
	}
	query := fmt.Sprintf(
		`UPDATE frames SET acked = 1 WHERE device_id = ? AND frame_id IN (%s)`,
		strings.Join(placeholders, ","),
	)
	if _, err := m.db.Exec(query, args...); err != nil {
		return err
	}

	// Record ACK for idempotent replay protection
	now := time.Now().Unix()
	for _, fid := range frameIDs {
		if _, err := m.db.Exec(
			`INSERT OR IGNORE INTO acks (device_id, frame_id, ack_at) VALUES (?, ?, ?)`,
			deviceID[:], fid, now,
		); err != nil {
			return err
		}
	}
	return nil
}

// IsFrameAcked checks whether a frame has already been acked by the device.
func (m *mailboxDB) IsFrameAcked(deviceID DeviceID, frameID string) (bool, error) {
	var count int
	err := m.db.QueryRow(
		`SELECT COUNT(*) FROM acks WHERE device_id = ? AND frame_id = ?`,
		deviceID[:], frameID,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// CleanupTTL removes frames that have expired their TTL.
// Returns the number of frames removed.
func (m *mailboxDB) CleanupTTL() (int64, error) {
	res, err := m.db.Exec(
		`DELETE FROM frames WHERE ttl <= ?`,
		time.Now().Unix(),
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CleanupAcked removes frames that have been acked and are older than the ACK window.
func (m *mailboxDB) CleanupAcked() (int64, error) {
	cutoff := time.Now().Add(-ACKWindow).Unix()
	res, err := m.db.Exec(
		`DELETE FROM frames WHERE acked = 1 AND created_at <= ?`,
		cutoff,
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PurgeDevice removes all frames and ACK records for a device (account deletion).
func (m *mailboxDB) PurgeDevice(deviceID DeviceID) error {
	if _, err := m.db.Exec(`DELETE FROM frames WHERE device_id = ?`, deviceID[:]); err != nil {
		return err
	}
	if _, err := m.db.Exec(`DELETE FROM acks WHERE device_id = ?`, deviceID[:]); err != nil {
		return err
	}
	_, err := m.db.Exec(`DELETE FROM devices WHERE device_id = ?`, deviceID[:])
	m.mu.Lock()
	delete(m.devices, deviceID)
	m.mu.Unlock()
	return err
}

// DeviceFrameCount returns total and unacked frame counts for a device.
func (m *mailboxDB) DeviceFrameCount(deviceID DeviceID) (total int, unacked int, err error) {
	err = m.db.QueryRow(
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN acked=0 THEN 1 ELSE 0 END),0)
		 FROM frames WHERE device_id = ?`,
		deviceID[:],
	).Scan(&total, &unacked)
	return
}

// --- Test helpers ---

// GenerateTestKeys creates an Ed25519 keypair for testing.
func GenerateTestKeys() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return pub, priv
}

// GenerateTestDeviceID creates a random device ID for testing.
func GenerateTestDeviceID() DeviceID {
	var id DeviceID
	rand.Read(id[:])
	return id
}

// Ensure unused import for crypto
var _ crypto.PublicKey = ed25519.PublicKey{}
