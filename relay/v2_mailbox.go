package relay

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	_ "modernc.org/sqlite"
)

const (
	V2MaxUnackedFrames = 100
	V2MaxPublishBurst  = 5
	V2TombstoneWindow  = 30 * 24 * time.Hour
)

type V2Digest [32]byte

type ProvisionedMailbox struct {
	MailboxID              string
	Epoch                  uint64
	HostTokenDigest        V2Digest
	DeviceTokenDigest      V2Digest
	HostIdentityCommitment V2Digest
	DeviceKeyCommitment    V2Digest
	State                  string
}

type V2StoredFrame struct {
	Frame       OpaqueFrameV2
	FrameDigest V2Digest
}

type V2MailboxDB struct{ db *sql.DB }

// V2CleanupWorker bounds ciphertext and replay-detail retention for a v2
// mailbox store. Its lifetime is controlled exclusively by the supplied
// context so the executable can stop cleanup before closing the database.
type V2CleanupWorker struct {
	db       *V2MailboxDB
	interval time.Duration
}

func NewV2CleanupWorker(db *V2MailboxDB, interval time.Duration) (*V2CleanupWorker, error) {
	if db == nil {
		return nil, errors.New("relay v2: nil cleanup mailbox store")
	}
	if interval <= 0 {
		return nil, errors.New("relay v2: cleanup interval must be positive")
	}
	return &V2CleanupWorker{db: db, interval: interval}, nil
}

// Run performs an initial sweep so an expired backlog cannot occupy capacity
// for a full interval after restart, then continues until ctx is cancelled.
func (w *V2CleanupWorker) Run(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	default:
	}
	w.cleanup(ctx, time.Now())

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			w.cleanup(ctx, now)
		}
	}
}

func (w *V2CleanupWorker) cleanup(ctx context.Context, now time.Time) {
	expired, err := w.db.CleanupExpired(ctx, now)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("[relay][v2-cleanup] expired frame cleanup error: %v", err)
		}
		return
	}
	tombstones, err := w.db.CleanupTombstones(ctx, now)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("[relay][v2-cleanup] tombstone cleanup error: %v", err)
		}
		return
	}
	if expired > 0 || tombstones > 0 {
		log.Printf("[relay][v2-cleanup] removed expired_frames=%d tombstones=%d", expired, tombstones)
	}
}

// NewV2MailboxDB opens a storage boundary disjoint from Relay v1.
func NewV2MailboxDB(path string) (*V2MailboxDB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("relay v2: open db: %w", err)
	}
	db.SetMaxOpenConns(1)
	m := &V2MailboxDB{db: db}
	if err := m.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return m, nil
}

func (m *V2MailboxDB) Close() error { return m.db.Close() }

func (m *V2MailboxDB) init() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS v2_mailboxes (mailbox_id TEXT PRIMARY KEY, active_epoch INTEGER NOT NULL, host_token_digest BLOB NOT NULL CHECK(length(host_token_digest)=32), device_token_digest BLOB NOT NULL CHECK(length(device_token_digest)=32), host_identity_commitment BLOB NOT NULL CHECK(length(host_identity_commitment)=32), device_key_commitment BLOB NOT NULL CHECK(length(device_key_commitment)=32), state TEXT NOT NULL CHECK(state IN ('active','revoked')), revoked_at INTEGER)`,
		`CREATE TABLE IF NOT EXISTS v2_streams (mailbox_id TEXT NOT NULL, direction TEXT NOT NULL, epoch INTEGER NOT NULL, max_sequence INTEGER NOT NULL DEFAULT 0, max_seen_issued_at INTEGER NOT NULL DEFAULT 0, max_acked_sequence INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(mailbox_id,direction,epoch), FOREIGN KEY(mailbox_id) REFERENCES v2_mailboxes(mailbox_id))`,
		`CREATE TABLE IF NOT EXISTS v2_frames (mailbox_id TEXT NOT NULL, direction TEXT NOT NULL, epoch INTEGER NOT NULL, sequence INTEGER NOT NULL, message_id TEXT NOT NULL, nonce TEXT NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, frame_digest BLOB NOT NULL CHECK(length(frame_digest)=32), canonical_frame BLOB NOT NULL, PRIMARY KEY(mailbox_id,direction,epoch,sequence), UNIQUE(mailbox_id,direction,epoch,nonce), FOREIGN KEY(mailbox_id) REFERENCES v2_mailboxes(mailbox_id))`,
		`CREATE TABLE IF NOT EXISTS v2_tombstones (mailbox_id TEXT NOT NULL, direction TEXT NOT NULL, epoch INTEGER NOT NULL, sequence INTEGER NOT NULL, message_id TEXT NOT NULL, nonce TEXT NOT NULL, frame_digest BLOB NOT NULL CHECK(length(frame_digest)=32), retained_until INTEGER NOT NULL, PRIMARY KEY(mailbox_id,direction,epoch,sequence), UNIQUE(mailbox_id,direction,epoch,nonce), FOREIGN KEY(mailbox_id) REFERENCES v2_mailboxes(mailbox_id))`,
		`CREATE TABLE IF NOT EXISTS v2_rate_events (mailbox_id TEXT NOT NULL, direction TEXT NOT NULL, admitted_at_ns INTEGER NOT NULL, FOREIGN KEY(mailbox_id) REFERENCES v2_mailboxes(mailbox_id))`,
		`CREATE INDEX IF NOT EXISTS v2_frames_read ON v2_frames(mailbox_id,direction,epoch,sequence)`,
		`CREATE INDEX IF NOT EXISTS v2_tombstone_retention ON v2_tombstones(retained_until)`,
	}
	for _, stmt := range stmts {
		if _, err := m.db.Exec(stmt); err != nil {
			return fmt.Errorf("relay v2: init schema: %w", err)
		}
	}
	return nil
}

func digestIsZero(d V2Digest) bool { return d == V2Digest{} }

func subtleCompareDigest(left, right V2Digest) bool {
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}

func sameProvisionedMailbox(left, right ProvisionedMailbox) bool {
	return left.MailboxID == right.MailboxID &&
		left.Epoch == right.Epoch &&
		left.State == right.State &&
		subtleCompareDigest(left.HostTokenDigest, right.HostTokenDigest) &&
		subtleCompareDigest(left.DeviceTokenDigest, right.DeviceTokenDigest) &&
		subtleCompareDigest(left.HostIdentityCommitment, right.HostIdentityCommitment) &&
		subtleCompareDigest(left.DeviceKeyCommitment, right.DeviceKeyCommitment)
}

func scanProvisionedMailbox(scanner interface {
	Scan(...any) error
}) (ProvisionedMailbox, error) {
	var mailbox ProvisionedMailbox
	var hostTokenDigest []byte
	var deviceTokenDigest []byte
	var hostIdentityCommitment []byte
	var deviceKeyCommitment []byte
	if err := scanner.Scan(
		&mailbox.MailboxID,
		&mailbox.Epoch,
		&hostTokenDigest,
		&deviceTokenDigest,
		&hostIdentityCommitment,
		&deviceKeyCommitment,
		&mailbox.State,
	); err != nil {
		return ProvisionedMailbox{}, err
	}
	copy(mailbox.HostTokenDigest[:], hostTokenDigest)
	copy(mailbox.DeviceTokenDigest[:], deviceTokenDigest)
	copy(mailbox.HostIdentityCommitment[:], hostIdentityCommitment)
	copy(mailbox.DeviceKeyCommitment[:], deviceKeyCommitment)
	return mailbox, nil
}

// ProvisionMailbox is the M1-only local constructor/admin seam. It accepts
// digests, never bearer values, and cannot replace or reactivate a mailbox.
func (m *V2MailboxDB) ProvisionMailbox(ctx context.Context, p ProvisionedMailbox) (bool, error) {
	if !validatePrefixedHex(p.MailboxID, "mbx-", 64) || p.Epoch == 0 || digestIsZero(p.HostTokenDigest) ||
		digestIsZero(p.DeviceTokenDigest) || digestIsZero(p.HostIdentityCommitment) || digestIsZero(p.DeviceKeyCommitment) ||
		subtle.ConstantTimeCompare(p.HostTokenDigest[:], p.DeviceTokenDigest[:]) == 1 || p.State != "active" {
		return false, ErrV2InvalidMailbox
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `INSERT INTO v2_mailboxes(mailbox_id,active_epoch,host_token_digest,device_token_digest,host_identity_commitment,device_key_commitment,state) VALUES(?,?,?,?,?,?,'active') ON CONFLICT(mailbox_id) DO NOTHING`, p.MailboxID, p.Epoch, p.HostTokenDigest[:], p.DeviceTokenDigest[:], p.HostIdentityCommitment[:], p.DeviceKeyCommitment[:])
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n == 1 {
		for _, d := range []V2Direction{V2HostToDevice, V2DeviceToHost} {
			if _, err := tx.ExecContext(ctx, `INSERT INTO v2_streams(mailbox_id,direction,epoch) VALUES(?,?,?)`, p.MailboxID, d, p.Epoch); err != nil {
				return false, err
			}
		}
		return true, tx.Commit()
	}
	existing, err := scanProvisionedMailbox(tx.QueryRowContext(ctx, `SELECT mailbox_id,active_epoch,host_token_digest,device_token_digest,host_identity_commitment,device_key_commitment,state FROM v2_mailboxes WHERE mailbox_id=?`, p.MailboxID))
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrV2NotFound
	}
	if err != nil {
		return false, err
	}
	if existing.State == "revoked" {
		return false, ErrV2Conflict
	}
	if !sameProvisionedMailbox(existing, p) {
		return false, ErrV2Conflict
	}
	return false, tx.Commit()
}

type v2MailboxAuth struct {
	epoch        uint64
	host, device V2Digest
	state        string
}

func loadV2Auth(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, mailboxID string) (v2MailboxAuth, error) {
	var a v2MailboxAuth
	var host, device []byte
	err := q.QueryRowContext(ctx, `SELECT active_epoch,host_token_digest,device_token_digest,state FROM v2_mailboxes WHERE mailbox_id=?`, mailboxID).Scan(&a.epoch, &host, &device, &a.state)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrV2NotFound
	}
	if err != nil {
		return a, err
	}
	copy(a.host[:], host)
	copy(a.device[:], device)
	if a.state == "revoked" {
		return a, ErrV2Revoked
	}
	return a, nil
}

func authorizeV2(a v2MailboxAuth, role V2Role, supplied V2Digest) error {
	var expected V2Digest
	switch role {
	case V2RoleHost:
		expected = a.host
	case V2RoleDevice:
		expected = a.device
	default:
		return ErrV2Forbidden
	}
	if subtle.ConstantTimeCompare(expected[:], supplied[:]) != 1 {
		return ErrV2Unauthorized
	}
	return nil
}

func v2RoleAllows(role V2Role, direction V2Direction, operation string) bool {
	switch operation {
	case "publish":
		return role == V2RoleHost && direction == V2HostToDevice || role == V2RoleDevice && direction == V2DeviceToHost
	case "receive":
		return role == V2RoleDevice && direction == V2HostToDevice || role == V2RoleHost && direction == V2DeviceToHost
	case "revoke":
		return role == V2RoleHost
	default:
		return false
	}
}

// PublishFrame returns false,nil for an identical retry. Authorization and
// role checks happen inside the same transaction before mutation.
func (m *V2MailboxDB) PublishFrame(ctx context.Context, role V2Role, bearerDigest V2Digest, frame OpaqueFrameV2, now time.Time) (bool, error) {
	if !v2RoleAllows(role, frame.Direction, "publish") {
		return false, ErrV2Forbidden
	}
	if err := frame.ValidateAt(now); err != nil {
		return false, err
	}
	canonical, _ := frame.CanonicalBytes()
	digest := V2Digest(sha256.Sum256(canonical))
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	a, err := loadV2Auth(ctx, tx, frame.MailboxID)
	if err != nil {
		return false, err
	}
	if err := authorizeV2(a, role, bearerDigest); err != nil {
		return false, err
	}
	if frame.Epoch != a.epoch {
		return false, ErrV2Replay
	}
	var oldMessage, oldNonce string
	var oldDigest []byte
	err = tx.QueryRowContext(ctx, `SELECT message_id,nonce,frame_digest FROM v2_tombstones WHERE mailbox_id=? AND direction=? AND epoch=? AND sequence=?`, frame.MailboxID, frame.Direction, frame.Epoch, frame.Sequence).Scan(&oldMessage, &oldNonce, &oldDigest)
	if err == nil {
		if oldMessage == frame.MessageID && oldNonce == frame.Nonce && subtle.ConstantTimeCompare(oldDigest, digest[:]) == 1 {
			return false, tx.Commit()
		}
		return false, ErrV2Conflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	var maxSequence uint64
	var maxIssued int64
	if err := tx.QueryRowContext(ctx, `SELECT max_sequence,max_seen_issued_at FROM v2_streams WHERE mailbox_id=? AND direction=? AND epoch=?`, frame.MailboxID, frame.Direction, frame.Epoch).Scan(&maxSequence, &maxIssued); err != nil {
		return false, err
	}
	if frame.Sequence <= maxSequence || frame.IssuedAt < maxIssued {
		return false, ErrV2Replay
	}
	cutoff := now.Add(-time.Second).UnixNano()
	if _, err := tx.ExecContext(ctx, `DELETE FROM v2_rate_events WHERE admitted_at_ns<=?`, cutoff); err != nil {
		return false, err
	}
	var burst int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM v2_rate_events WHERE mailbox_id=? AND admitted_at_ns>?`, frame.MailboxID, cutoff).Scan(&burst); err != nil {
		return false, err
	}
	if burst >= V2MaxPublishBurst {
		return false, ErrV2RateLimited
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM v2_frames WHERE mailbox_id=? AND direction=? AND epoch=?`, frame.MailboxID, frame.Direction, frame.Epoch).Scan(&count); err != nil {
		return false, err
	}
	if count >= V2MaxUnackedFrames {
		return false, ErrV2Capacity
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v2_tombstones(mailbox_id,direction,epoch,sequence,message_id,nonce,frame_digest,retained_until) VALUES(?,?,?,?,?,?,?,?)`, frame.MailboxID, frame.Direction, frame.Epoch, frame.Sequence, frame.MessageID, frame.Nonce, digest[:], now.Add(V2TombstoneWindow).Unix()); err != nil {
		return false, ErrV2Replay
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v2_frames(mailbox_id,direction,epoch,sequence,message_id,nonce,issued_at,expires_at,frame_digest,canonical_frame) VALUES(?,?,?,?,?,?,?,?,?,?)`, frame.MailboxID, frame.Direction, frame.Epoch, frame.Sequence, frame.MessageID, frame.Nonce, frame.IssuedAt, frame.ExpiresAt, digest[:], canonical); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE v2_streams SET max_sequence=?,max_seen_issued_at=MAX(max_seen_issued_at,?) WHERE mailbox_id=? AND direction=? AND epoch=?`, frame.Sequence, frame.IssuedAt, frame.MailboxID, frame.Direction, frame.Epoch); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v2_rate_events(mailbox_id,direction,admitted_at_ns) VALUES(?,?,?)`, frame.MailboxID, frame.Direction, now.UnixNano()); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func (m *V2MailboxDB) ReadFrames(ctx context.Context, role V2Role, bearerDigest V2Digest, mailboxID string, direction V2Direction, epoch, after uint64, limit int, now time.Time) ([]V2StoredFrame, error) {
	if !v2RoleAllows(role, direction, "receive") {
		return nil, ErrV2Forbidden
	}
	if limit <= 0 || limit > V2MaxUnackedFrames {
		limit = V2MaxUnackedFrames
	}
	tx, err := m.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	a, err := loadV2Auth(ctx, tx, mailboxID)
	if err != nil {
		return nil, err
	}
	if err = authorizeV2(a, role, bearerDigest); err != nil {
		return nil, err
	}
	if epoch != a.epoch {
		return nil, ErrV2Replay
	}
	rows, err := tx.QueryContext(ctx, `SELECT canonical_frame,frame_digest FROM v2_frames WHERE mailbox_id=? AND direction=? AND epoch=? AND sequence>? AND expires_at>? ORDER BY sequence ASC LIMIT ?`, mailboxID, direction, epoch, after, now.Unix()-V2ClockSkewSeconds, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []V2StoredFrame
	for rows.Next() {
		var raw, d []byte
		if err := rows.Scan(&raw, &d); err != nil {
			return nil, err
		}
		f, parsed, err := ParseOpaqueFrameV2(raw)
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare(parsed[:], d) != 1 {
			return nil, ErrV2Conflict
		}
		out = append(out, V2StoredFrame{Frame: f, FrameDigest: V2Digest(parsed)})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

func (m *V2MailboxDB) Ack(ctx context.Context, role V2Role, bearerDigest V2Digest, ack OpaqueAckV2, now time.Time) error {
	if err := validateV2Ack(ack); err != nil {
		return err
	}
	if !v2RoleAllows(role, ack.Direction, "receive") {
		return ErrV2Forbidden
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	a, err := loadV2Auth(ctx, tx, ack.MailboxID)
	if err != nil {
		return err
	}
	if err = authorizeV2(a, role, bearerDigest); err != nil {
		return err
	}
	if ack.Epoch != a.epoch {
		return ErrV2Replay
	}
	var maxSeq, maxAck uint64
	if err := tx.QueryRowContext(ctx, `SELECT max_sequence,max_acked_sequence FROM v2_streams WHERE mailbox_id=? AND direction=? AND epoch=?`, ack.MailboxID, ack.Direction, ack.Epoch).Scan(&maxSeq, &maxAck); err != nil {
		return err
	}
	if ack.AckedThroughSequence < maxAck {
		return ErrV2AckRegression
	}
	if ack.AckedThroughSequence > maxSeq {
		return ErrV2Replay
	}
	if ack.AckedThroughSequence == maxAck {
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `UPDATE v2_streams SET max_acked_sequence=? WHERE mailbox_id=? AND direction=? AND epoch=?`, ack.AckedThroughSequence, ack.MailboxID, ack.Direction, ack.Epoch); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE v2_tombstones SET retained_until=MAX(retained_until,?) WHERE mailbox_id=? AND direction=? AND epoch=? AND sequence<=?`, now.Add(V2TombstoneWindow).Unix(), ack.MailboxID, ack.Direction, ack.Epoch, ack.AckedThroughSequence); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM v2_frames WHERE mailbox_id=? AND direction=? AND epoch=? AND sequence<=?`, ack.MailboxID, ack.Direction, ack.Epoch, ack.AckedThroughSequence); err != nil {
		return err
	}
	return tx.Commit()
}

// CleanupExpired deletes expired ciphertext while retaining replay evidence.
// Tombstones are extended through a full replay window measured from cleanup.
func (m *V2MailboxDB) CleanupExpired(ctx context.Context, now time.Time) (int64, error) {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE v2_tombstones SET retained_until=MAX(retained_until, ?) WHERE EXISTS (SELECT 1 FROM v2_frames f WHERE f.mailbox_id=v2_tombstones.mailbox_id AND f.direction=v2_tombstones.direction AND f.epoch=v2_tombstones.epoch AND f.sequence=v2_tombstones.sequence AND f.expires_at<=?)`, now.Add(V2TombstoneWindow).Unix(), now.Unix()); err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM v2_frames WHERE expires_at<=?`, now.Unix())
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

// CleanupTombstones removes replay details at the inclusive retention
// boundary. Permanent stream high-water marks continue to reject old sequence
// numbers after detail cleanup, so a removed tombstone never reopens a tuple.
func (m *V2MailboxDB) CleanupTombstones(ctx context.Context, now time.Time) (int64, error) {
	result, err := m.db.ExecContext(ctx, `DELETE FROM v2_tombstones WHERE retained_until<=?`, now.Unix())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (m *V2MailboxDB) Revoke(ctx context.Context, role V2Role, bearerDigest V2Digest, mailboxID string, now time.Time) error {
	if !v2RoleAllows(role, V2HostToDevice, "revoke") {
		return ErrV2Forbidden
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	a, err := loadV2Auth(ctx, tx, mailboxID)
	if err != nil {
		return err
	}
	if err = authorizeV2(a, role, bearerDigest); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE v2_mailboxes SET state='revoked',revoked_at=? WHERE mailbox_id=?`, now.Unix(), mailboxID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// Ciphertext cleanup is deliberately best-effort and occurs only after the
	// durable revocation commit. A cleanup failure must never reactivate or roll
	// back a revoked mailbox.
	_, _ = m.db.ExecContext(ctx, `DELETE FROM v2_frames WHERE mailbox_id=?`, mailboxID)
	return nil
}
