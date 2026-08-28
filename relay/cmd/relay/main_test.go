package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	relay "github.com/nomad/relay"
	"golang.org/x/sys/unix"
)

type lifecycleTestServer struct {
	startErr     error
	startEntered chan struct{}
	stop         chan struct{}
	stopOnce     sync.Once
	shutdowns    int
	mu           sync.Mutex
}

func newLifecycleTestServer(startErr error) *lifecycleTestServer {
	return &lifecycleTestServer{startErr: startErr, startEntered: make(chan struct{}), stop: make(chan struct{})}
}

func (s *lifecycleTestServer) Start() error {
	close(s.startEntered)
	if s.startErr != nil {
		return s.startErr
	}
	<-s.stop
	return nil
}

func (s *lifecycleTestServer) Shutdown(context.Context) error {
	s.mu.Lock()
	s.shutdowns++
	s.mu.Unlock()
	s.stopOnce.Do(func() { close(s.stop) })
	return nil
}

func (s *lifecycleTestServer) Close() error {
	s.stopOnce.Do(func() { close(s.stop) })
	return nil
}

func TestRunLifecycleStartFailureStopsPeersAndWorkers(t *testing.T) {
	want := errors.New("listen failed")
	failed := newLifecycleTestServer(want)
	peer := newLifecycleTestServer(nil)
	workerStopped := make(chan struct{})
	err := runLifecycle(context.Background(), []namedServer{
		{name: "failed", server: failed},
		{name: "peer", server: peer},
	}, []func(context.Context){func(ctx context.Context) {
		<-ctx.Done()
		close(workerStopped)
	}}, time.Second)
	if !errors.Is(err, want) {
		t.Fatalf("runLifecycle error=%v, want wrapped start failure", err)
	}
	select {
	case <-peer.startEntered:
	default:
		t.Fatal("peer listener was not started")
	}
	select {
	case <-workerStopped:
	default:
		t.Fatal("worker was not cancelled")
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.shutdowns != 1 {
		t.Fatalf("peer shutdowns=%d, want 1", peer.shutdowns)
	}
}

func TestRunLifecycleCancellationBeforeServersStartIsSafe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	server := newLifecycleTestServer(nil)
	if err := runLifecycle(ctx, []namedServer{{name: "server", server: server}}, nil, time.Second); err != nil {
		t.Fatalf("cancelled lifecycle: %v", err)
	}
}

func TestExecutableSIGTERMShutsDownCleanly(t *testing.T) {
	bin := buildRelayExecutable(t)
	addr := freeLoopbackAddr(t)
	v2Addr := freeLoopbackAddr(t)
	directory := t.TempDir()
	cmd := exec.Command(bin,
		"-addr", addr,
		"-db", filepath.Join(directory, "v1.db"),
		"-v2-enable",
		"-v2-addr", v2Addr,
		"-v2-role", "host",
		"-v2-db", filepath.Join(directory, "v2.db"),
		"-v2-loopback-test-http",
	)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitForHealth(t, "http://"+addr+"/health")
	waitForTCP(t, v2Addr)
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SIGTERM exit=%v output=%s", err, output.String())
		}
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("relay did not stop after SIGTERM; output=%s", output.String())
	}
}

func TestExecutableV2ListenerFailureReturnsAndReleasesPeers(t *testing.T) {
	bin := buildRelayExecutable(t)
	v1Addr := freeLoopbackAddr(t)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	cmd := exec.Command(bin,
		"-addr", v1Addr,
		"-db", filepath.Join(t.TempDir(), "v1.db"),
		"-v2-enable",
		"-v2-addr", occupied.Addr().String(),
		"-v2-role", "host",
		"-v2-db", filepath.Join(t.TempDir(), "v2.db"),
		"-v2-loopback-test-http",
	)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("occupied v2 listener unexpectedly succeeded: %s", output)
	}
	if ctx.Err() != nil {
		t.Fatalf("listener failure did not return to main: %s", output)
	}
	if !bytes.Contains(output, []byte("v2 data server")) || !bytes.Contains(output, []byte("listen")) {
		t.Fatalf("missing unified listener error: %s", output)
	}
	probe, err := net.Listen("tcp", v1Addr)
	if err != nil {
		t.Fatalf("peer listener leaked after v2 failure: %v output=%s", err, output)
	}
	probe.Close()
}

func TestExecutableV2CleanupReleasesExpiredUnackedCapacity(t *testing.T) {
	bin := buildRelayExecutable(t)
	directory := t.TempDir()
	v2Path := filepath.Join(directory, "v2.db")
	db, p := fillExpiredV2Mailbox(t, v2Path)
	db.Close()

	v1Addr := freeLoopbackAddr(t)
	v2Addr := freeLoopbackAddr(t)
	cmd := exec.Command(bin,
		"-addr", v1Addr,
		"-db", filepath.Join(directory, "v1.db"),
		"-cleanup", "5ms",
		"-v2-enable",
		"-v2-addr", v2Addr,
		"-v2-role", "host",
		"-v2-db", v2Path,
		"-v2-loopback-test-http",
	)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			_ = cmd.Wait()
		}
	})
	waitForHealth(t, "http://"+v1Addr+"/health")

	check := func() bool {
		checkDB, err := relay.NewV2MailboxDB(v2Path)
		if err != nil {
			return false
		}
		defer checkDB.Close()
		now := time.Now()
		frame := executableV2Frame(now, relay.V2MaxUnackedFrames+1)
		fresh, err := checkDB.PublishFrame(context.Background(), relay.V2RoleHost, p.HostTokenDigest, frame, now)
		return err == nil && fresh
	}
	deadline := time.Now().Add(3 * time.Second)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatalf("v2 cleanup did not release expired capacity; output=%s", output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("cleanup relay exit=%v output=%s", err, output.String())
	}
}

func buildRelayExecutable(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "relay")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build relay executable: %v\n%s", err, output)
	}
	return bin
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	return addr
}

func waitForHealth(t *testing.T, endpoint string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(endpoint)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("relay health did not become ready: %s", endpoint)
}

func waitForTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			connection.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("relay listener did not become ready: %s", addr)
}

func fillExpiredV2Mailbox(t *testing.T, path string) (*relay.V2MailboxDB, relay.ProvisionedMailbox) {
	t.Helper()
	db, err := relay.NewV2MailboxDB(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := func(value string) relay.V2Digest { return relay.V2Digest(sha256.Sum256([]byte(value))) }
	p := relay.ProvisionedMailbox{
		MailboxID:              "mbx-" + strings.Repeat("ab", 32),
		Epoch:                  1,
		HostTokenDigest:        digest("host-token"),
		DeviceTokenDigest:      digest("device-token"),
		HostIdentityCommitment: digest("host-id"),
		DeviceKeyCommitment:    digest("device-key"),
		State:                  "active",
	}
	if created, err := db.ProvisionMailbox(context.Background(), p); err != nil || !created {
		t.Fatalf("provision mailbox created=%v err=%v", created, err)
	}
	base := time.Now().Add(-20 * time.Minute).Truncate(time.Second)
	for sequence := uint64(1); sequence <= relay.V2MaxUnackedFrames; sequence++ {
		now := base.Add(time.Duration((sequence-1)/relay.V2MaxPublishBurst) * time.Second)
		if fresh, err := db.PublishFrame(context.Background(), relay.V2RoleHost, p.HostTokenDigest, executableV2Frame(now, sequence), now); err != nil || !fresh {
			t.Fatalf("publish expired frame %d fresh=%v err=%v", sequence, fresh, err)
		}
	}
	return db, p
}

func executableV2Frame(now time.Time, sequence uint64) relay.OpaqueFrameV2 {
	return relay.OpaqueFrameV2{
		Schema:      relay.OpaqueFrameV2Schema,
		CryptoSuite: relay.V2CryptoSuite,
		MailboxID:   "mbx-" + strings.Repeat("ab", 32),
		Direction:   relay.V2HostToDevice,
		Epoch:       1,
		Sequence:    sequence,
		MessageID:   fmt.Sprintf("msg-%032x", sequence),
		IssuedAt:    now.Unix(),
		ExpiresAt:   now.Add(10 * time.Minute).Unix(),
		Nonce:       base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%012d", sequence))),
		Ciphertext:  base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, 32)),
	}
}

func writePrivateAdminToken(t *testing.T, directory string) string {
	t.Helper()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "admin.token")
	if err := os.WriteFile(path, []byte("admin-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadV2AdminCredentialRequiresPrivateNoFollowFile(t *testing.T) {
	private, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := writePrivateAdminToken(t, private)
	if credential, err := relay.LoadV2AdminCredentialFromPrivateFile(path); err != nil || credential.Token != "admin-secret" {
		t.Fatalf("valid credential rejected: %+v err=%v", credential, err)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.LoadV2AdminCredentialFromPrivateFile(path); err == nil {
		t.Fatal("world-readable admin credential accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(private, "link.token")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.LoadV2AdminCredentialFromPrivateFile(link); err == nil {
		t.Fatal("symlink admin credential accepted")
	}

	hardlink := filepath.Join(private, "hardlink.token")
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.LoadV2AdminCredentialFromPrivateFile(path); err == nil {
		t.Fatal("multiply-linked admin credential accepted")
	}
}

func TestLoadV2AdminCredentialRejectsSymlinkedOrPublicParentAndSupportsFD(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	realParent := filepath.Join(root, "private")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := writePrivateAdminToken(t, realParent)
	linkedParent := filepath.Join(root, "linked")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.LoadV2AdminCredentialFromPrivateFile(filepath.Join(linkedParent, filepath.Base(path))); err == nil {
		t.Fatal("symlinked parent accepted")
	}
	if err := os.Chmod(realParent, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.LoadV2AdminCredentialFromPrivateFile(path); err == nil {
		t.Fatal("public parent accepted")
	}
	if err := os.Chmod(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	reader := fds[0]
	writer := fds[1]
	defer unix.Close(writer)
	if _, err := unix.Write(writer, []byte("admin-secret")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Shutdown(writer, unix.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	credential, err := relay.LoadV2AdminCredentialFromFD(reader)
	if err != nil || credential.Token != "admin-secret" || !strings.Contains(credential.Label, "[redacted]") {
		t.Fatalf("fd credential=%+v err=%v", credential, err)
	}
}
