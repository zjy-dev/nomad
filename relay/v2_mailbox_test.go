package relay

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testV2Digest(label string) V2Digest { return V2Digest(sha256.Sum256([]byte(label))) }

func provisionV2(t *testing.T, db *V2MailboxDB) ProvisionedMailbox {
	t.Helper()
	p := ProvisionedMailbox{MailboxID: "mbx-" + strings.Repeat("ab", 32), Epoch: 1, HostTokenDigest: testV2Digest("host-token"), DeviceTokenDigest: testV2Digest("device-token"), HostIdentityCommitment: testV2Digest("host-id"), DeviceKeyCommitment: testV2Digest("device-key"), State: "active"}
	if created, err := db.ProvisionMailbox(context.Background(), p); err != nil || !created {
		t.Fatal(err)
	}
	return p
}

func openV2TestDB(t *testing.T, path string) *V2MailboxDB {
	t.Helper()
	db, err := NewV2MailboxDB(path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestV2MailboxRoleIdempotencyConflictAndAckReplay(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(2_000_000_000, 0)
	db := openV2TestDB(t, filepath.Join(t.TempDir(), "v2.db"))
	defer db.Close()
	p := provisionV2(t, db)
	f := validV2Frame(now, 1)
	if _, err := db.PublishFrame(ctx, V2RoleDevice, p.DeviceTokenDigest, f, now); !errors.Is(err, ErrV2Forbidden) {
		t.Fatalf("wrong-role publish=%v", err)
	}
	if _, err := db.PublishFrame(ctx, V2RoleHost, testV2Digest("wrong"), f, now); !errors.Is(err, ErrV2Unauthorized) {
		t.Fatalf("wrong-token publish=%v", err)
	}
	if fresh, err := db.PublishFrame(ctx, V2RoleHost, p.HostTokenDigest, f, now); err != nil || !fresh {
		t.Fatalf("first fresh=%v err=%v", fresh, err)
	}
	if fresh, err := db.PublishFrame(ctx, V2RoleHost, p.HostTokenDigest, f, now); err != nil || fresh {
		t.Fatalf("retry fresh=%v err=%v", fresh, err)
	}
	changed := f
	changed.Ciphertext = validV2Frame(now, 2).Ciphertext[:len(f.Ciphertext)-1] + "A"
	if _, err := db.PublishFrame(ctx, V2RoleHost, p.HostTokenDigest, changed, now); !errors.Is(err, ErrV2Conflict) {
		t.Fatalf("changed retry=%v", err)
	}
	if _, err := db.ReadFrames(ctx, V2RoleHost, p.HostTokenDigest, p.MailboxID, V2HostToDevice, 1, 0, 10, now); !errors.Is(err, ErrV2Forbidden) {
		t.Fatalf("sender read=%v", err)
	}
	frames, err := db.ReadFrames(ctx, V2RoleDevice, p.DeviceTokenDigest, p.MailboxID, V2HostToDevice, 1, 0, 10, now)
	if err != nil || len(frames) != 1 || frames[0].Frame.Sequence != 1 {
		t.Fatalf("read=%+v err=%v", frames, err)
	}
	ack := OpaqueAckV2{Schema: OpaqueAckV2Schema, MailboxID: p.MailboxID, Direction: V2HostToDevice, Epoch: 1, AckedThroughSequence: 1}
	if err := db.Ack(ctx, V2RoleHost, p.HostTokenDigest, ack, now); !errors.Is(err, ErrV2Forbidden) {
		t.Fatalf("sender ack=%v", err)
	}
	if err := db.Ack(ctx, V2RoleDevice, p.DeviceTokenDigest, ack, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PublishFrame(ctx, V2RoleHost, p.HostTokenDigest, f, now); err != nil {
		t.Fatalf("identical acked retry=%v", err)
	}
	if _, err := db.PublishFrame(ctx, V2RoleHost, p.HostTokenDigest, changed, now); !errors.Is(err, ErrV2Conflict) {
		t.Fatalf("acked replay=%v", err)
	}
}

func TestV2MailboxRestartPreservesCursorTombstoneAndRevocation(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(2_000_000_000, 0)
	path := filepath.Join(t.TempDir(), "restart.db")
	db := openV2TestDB(t, path)
	p := provisionV2(t, db)
	f := validV2Frame(now, 1)
	if _, err := db.PublishFrame(ctx, V2RoleHost, p.HostTokenDigest, f, now); err != nil {
		t.Fatal(err)
	}
	if err := db.Ack(ctx, V2RoleDevice, p.DeviceTokenDigest, OpaqueAckV2{OpaqueAckV2Schema, p.MailboxID, V2HostToDevice, 1, 1}, now); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = openV2TestDB(t, path)
	if _, err := db.PublishFrame(ctx, V2RoleHost, p.HostTokenDigest, validV2Frame(now, 1), now); err != nil {
		t.Fatalf("restart idempotency=%v", err)
	}
	f2 := validV2Frame(now.Add(time.Second), 2)
	if _, err := db.PublishFrame(ctx, V2RoleHost, p.HostTokenDigest, f2, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := db.Revoke(ctx, V2RoleDevice, p.DeviceTokenDigest, p.MailboxID, now); !errors.Is(err, ErrV2Forbidden) {
		t.Fatalf("device revoke=%v", err)
	}
	if err := db.Revoke(ctx, V2RoleHost, p.HostTokenDigest, p.MailboxID, now); err != nil {
		t.Fatal(err)
	}
	db.Close()
	db = openV2TestDB(t, path)
	defer db.Close()
	if _, err := db.ReadFrames(ctx, V2RoleDevice, p.DeviceTokenDigest, p.MailboxID, V2HostToDevice, 1, 0, 10, now); !errors.Is(err, ErrV2Revoked) {
		t.Fatalf("read after revoke=%v", err)
	}
	if created, err := db.ProvisionMailbox(ctx, p); !errors.Is(err, ErrV2Conflict) || created {
		t.Fatalf("reprovision after revoke created=%v err=%v", created, err)
	}
}

func TestV2ProvisionMailboxIdempotentSameAndConflictOnChangedDigest(t *testing.T) {
	ctx := context.Background()
	db := openV2TestDB(t, filepath.Join(t.TempDir(), "provision.db"))
	defer db.Close()
	p := provisionV2(t, db)
	if created, err := db.ProvisionMailbox(ctx, p); err != nil || created {
		t.Fatalf("same provision created=%v err=%v", created, err)
	}
	changed := p
	changed.DeviceKeyCommitment = testV2Digest("changed-device-key")
	if created, err := db.ProvisionMailbox(ctx, changed); !errors.Is(err, ErrV2Conflict) || created {
		t.Fatalf("changed provision created=%v err=%v", created, err)
	}
}

func TestV2MailboxUsesWALFullAndDisjointTables(t *testing.T) {
	db := openV2TestDB(t, filepath.Join(t.TempDir(), "pragma.db"))
	defer db.Close()
	var journal string
	var sync int
	if err := db.db.QueryRow("PRAGMA journal_mode").Scan(&journal); err != nil {
		t.Fatal(err)
	}
	if err := db.db.QueryRow("PRAGMA synchronous").Scan(&sync); err != nil {
		t.Fatal(err)
	}
	if strings.ToLower(journal) != "wal" || sync != 2 {
		t.Fatalf("journal=%s sync=%d", journal, sync)
	}
	var names string
	if err := db.db.QueryRow("SELECT group_concat(name,',') FROM sqlite_master WHERE type='table' AND name LIKE 'v2_%'").Scan(&names); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(names, "v2_mailboxes") {
		t.Fatalf("tables=%s", names)
	}
}

func TestV2CleanupExpiredRetainsReplaySemantics(t *testing.T) {
	ctx := context.Background()
	issued := time.Unix(2_000_000_000, 0)
	db := openV2TestDB(t, filepath.Join(t.TempDir(), "expired.db"))
	defer db.Close()
	p := provisionV2(t, db)
	f := validV2Frame(issued, 1)
	if _, err := db.PublishFrame(ctx, V2RoleHost, p.HostTokenDigest, f, issued); err != nil {
		t.Fatal(err)
	}
	cleanupAt := time.Unix(f.ExpiresAt, 0)
	cleaned, err := db.CleanupExpired(ctx, cleanupAt)
	if err != nil || cleaned != 1 {
		t.Fatalf("cleaned=%d err=%v", cleaned, err)
	}
	var payloads int
	var retainedUntil int64
	if err := db.db.QueryRow("SELECT COUNT(*) FROM v2_frames").Scan(&payloads); err != nil {
		t.Fatal(err)
	}
	if err := db.db.QueryRow("SELECT retained_until FROM v2_tombstones WHERE mailbox_id=? AND direction=? AND epoch=? AND sequence=1", p.MailboxID, V2HostToDevice, 1).Scan(&retainedUntil); err != nil {
		t.Fatal(err)
	}
	if payloads != 0 || retainedUntil < cleanupAt.Add(V2TombstoneWindow).Unix() {
		t.Fatalf("payloads=%d retained_until=%d", payloads, retainedUntil)
	}
	if fresh, err := db.PublishFrame(ctx, V2RoleHost, p.HostTokenDigest, f, issued); err != nil || fresh {
		t.Fatalf("identical after cleanup fresh=%v err=%v", fresh, err)
	}
	changed := f
	changed.Ciphertext = validV2Frame(issued, 2).Ciphertext[:len(f.Ciphertext)-1] + "A"
	if _, err := db.PublishFrame(ctx, V2RoleHost, p.HostTokenDigest, changed, issued); !errors.Is(err, ErrV2Conflict) {
		t.Fatalf("changed after cleanup=%v", err)
	}
	replayed := validV2Frame(issued.Add(time.Second), 1)
	if _, err := db.PublishFrame(ctx, V2RoleHost, p.HostTokenDigest, replayed, issued.Add(time.Second)); !errors.Is(err, ErrV2Conflict) {
		t.Fatalf("same sequence replay=%v", err)
	}
}

func TestV2CleanupTombstonesBoundaryAndRestartHighWater(t *testing.T) {
	ctx := context.Background()
	issued := time.Unix(2_000_000_000, 0)
	path := filepath.Join(t.TempDir(), "tombstone.db")
	db := openV2TestDB(t, path)
	p := provisionV2(t, db)
	f := validV2Frame(issued, 1)
	if _, err := db.PublishFrame(ctx, V2RoleHost, p.HostTokenDigest, f, issued); err != nil {
		t.Fatal(err)
	}
	boundary := issued.Add(V2TombstoneWindow)
	if count, err := db.CleanupTombstones(ctx, boundary.Add(-time.Second)); err != nil || count != 0 {
		t.Fatalf("early count=%d err=%v", count, err)
	}
	if count, err := db.CleanupTombstones(ctx, boundary); err != nil || count != 1 {
		t.Fatalf("boundary count=%d err=%v", count, err)
	}
	var count int
	if err := db.db.QueryRow("SELECT COUNT(*) FROM v2_tombstones").Scan(&count); err != nil || count != 0 {
		t.Fatalf("remaining=%d err=%v", count, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = openV2TestDB(t, path)
	defer db.Close()
	if _, err := db.PublishFrame(ctx, V2RoleHost, p.HostTokenDigest, f, issued); !errors.Is(err, ErrV2Replay) {
		t.Fatalf("old tuple after restart=%v", err)
	}
	next := validV2Frame(boundary, 2)
	if fresh, err := db.PublishFrame(ctx, V2RoleHost, p.HostTokenDigest, next, boundary); err != nil || !fresh {
		t.Fatalf("next fresh=%v err=%v", fresh, err)
	}
}

func TestV2CleanupWorkerInitialSweepReleasesExpiredUnackedCapacity(t *testing.T) {
	ctx := context.Background()
	db := openV2TestDB(t, filepath.Join(t.TempDir(), "cleanup-worker.db"))
	defer db.Close()
	p := provisionV2(t, db)

	base := time.Now().Add(-20 * time.Minute).Truncate(time.Second)
	for i := uint64(1); i <= V2MaxUnackedFrames; i++ {
		admittedAt := base.Add(time.Duration((i-1)/V2MaxPublishBurst) * time.Second)
		frame := validV2Frame(admittedAt, i)
		if fresh, err := db.PublishFrame(ctx, V2RoleHost, p.HostTokenDigest, frame, admittedAt); err != nil || !fresh {
			t.Fatalf("publish expired frame %d fresh=%v err=%v", i, fresh, err)
		}
	}
	current := validV2Frame(time.Now(), V2MaxUnackedFrames+1)
	if _, err := db.PublishFrame(ctx, V2RoleHost, p.HostTokenDigest, current, time.Now()); !errors.Is(err, ErrV2Capacity) {
		t.Fatalf("full expired mailbox publish=%v, want capacity", err)
	}

	worker, err := NewV2CleanupWorker(db, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		worker.Run(workerCtx)
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var count int
		if err := db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM v2_frames`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("initial cleanup left %d expired frames", count)
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanup worker did not stop after cancellation")
	}

	if fresh, err := db.PublishFrame(ctx, V2RoleHost, p.HostTokenDigest, current, time.Now()); err != nil || !fresh {
		t.Fatalf("publish after cleanup fresh=%v err=%v", fresh, err)
	}
}

func TestNewV2CleanupWorkerRejectsInvalidConfiguration(t *testing.T) {
	if _, err := NewV2CleanupWorker(nil, time.Second); err == nil {
		t.Fatal("nil cleanup store accepted")
	}
	db := openV2TestDB(t, filepath.Join(t.TempDir(), "cleanup-config.db"))
	defer db.Close()
	if _, err := NewV2CleanupWorker(db, 0); err == nil {
		t.Fatal("non-positive cleanup interval accepted")
	}
}

func TestV2CleanupWorkerInitialSweepRemovesDueTombstones(t *testing.T) {
	ctx := context.Background()
	db := openV2TestDB(t, filepath.Join(t.TempDir(), "cleanup-tombstone-worker.db"))
	defer db.Close()
	p := provisionV2(t, db)
	now := time.Now().Truncate(time.Second)
	frame := validV2Frame(now, 1)
	if _, err := db.PublishFrame(ctx, V2RoleHost, p.HostTokenDigest, frame, now); err != nil {
		t.Fatal(err)
	}
	ack := OpaqueAckV2{Schema: OpaqueAckV2Schema, MailboxID: p.MailboxID, Direction: V2HostToDevice, Epoch: 1, AckedThroughSequence: 1}
	if err := db.Ack(ctx, V2RoleDevice, p.DeviceTokenDigest, ack, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.ExecContext(ctx, `UPDATE v2_tombstones SET retained_until=?`, now.Add(-time.Second).Unix()); err != nil {
		t.Fatal(err)
	}

	worker, err := NewV2CleanupWorker(db, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		worker.Run(workerCtx)
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		var count int
		if err := db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM v2_tombstones`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("initial cleanup left %d due tombstones", count)
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanup worker did not stop after tombstone sweep")
	}
}
