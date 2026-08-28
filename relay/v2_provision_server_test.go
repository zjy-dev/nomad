package relay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func provisionRequestJSON(t *testing.T, mailboxID string) []byte {
	t.Helper()
	digest := func(value string) string {
		sum := sha256.Sum256([]byte(value))
		return hex.EncodeToString(sum[:])
	}
	request := V2ProvisionRequest{
		Schema:                 V2ProvisionSchema,
		MailboxID:              mailboxID,
		Epoch:                  1,
		HostTokenDigest:        digest("host-token"),
		DeviceTokenDigest:      digest("device-token"),
		HostIdentityCommitment: digest("host-id"),
		DeviceKeyCommitment:    digest("device-key"),
	}
	raw, err := request.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func digestHex(label string) string {
	sum := testV2Digest(label)
	return hex.EncodeToString(sum[:])
}

func newV2ProvisionFixture(t *testing.T) (*V2MailboxDB, *V2ProvisionServer) {
	t.Helper()
	db := openV2TestDB(t, filepath.Join(t.TempDir(), "provision-http.db"))
	server, err := NewV2ProvisionServer(db, V2ProvisionServerConfig{
		Addr:                  "127.0.0.1:0",
		Credential:            V2ProvisionCredentialSource{Token: "admin-secret", Label: "test [redacted]"},
		AllowLoopbackHTTPOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, server
}

func provisionHTTP(t *testing.T, server *V2ProvisionServer, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, V2ProvisionAdminPath, bytes.NewReader(body))
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	r.ContentLength = int64(len(body))
	w := httptest.NewRecorder()
	server.ServeHTTP(w, r)
	return w
}

func TestV2ProvisionServerCreateIdempotentAndConflict(t *testing.T) {
	db, server := newV2ProvisionFixture(t)
	mailboxID := "mbx-" + strings.Repeat("ab", 32)
	raw := provisionRequestJSON(t, mailboxID)
	if got := provisionHTTP(t, server, "admin-secret", raw).Code; got != http.StatusCreated {
		t.Fatalf("first provision=%d", got)
	}
	if got := provisionHTTP(t, server, "admin-secret", raw).Code; got != http.StatusOK {
		t.Fatalf("idempotent provision=%d", got)
	}
	changed := append([]byte(nil), raw...)
	changed = bytes.Replace(changed, []byte(`"device_key_commitment":"`), []byte(`"device_key_commitment":"00`), 1)
	if got := provisionHTTP(t, server, "admin-secret", changed).Code; got != http.StatusBadRequest {
		t.Fatalf("non-canonical changed body=%d", got)
	}
	conflict := V2ProvisionRequest{
		Schema:                 V2ProvisionSchema,
		MailboxID:              mailboxID,
		Epoch:                  1,
		HostTokenDigest:        digestHex("host-token"),
		DeviceTokenDigest:      digestHex("device-token"),
		HostIdentityCommitment: digestHex("host-id"),
		DeviceKeyCommitment:    digestHex("changed-device-key"),
	}
	conflictRaw, err := conflict.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if got := provisionHTTP(t, server, "admin-secret", conflictRaw).Code; got != http.StatusConflict {
		t.Fatalf("conflict provision=%d", got)
	}
	if _, err := loadV2Auth(context.Background(), db.db, mailboxID); err != nil {
		t.Fatalf("auth lookup=%v", err)
	}
}

func TestV2ProvisionServerRejectsTransportSmugglingAndWrongPath(t *testing.T) {
	_, server := newV2ProvisionFixture(t)
	raw := provisionRequestJSON(t, "mbx-"+strings.Repeat("cd", 32))
	tests := []struct {
		name   string
		mutate func(*http.Request)
		want   int
	}{
		{"non-loopback", func(r *http.Request) { r.RemoteAddr = "198.51.100.4:9" }, http.StatusUpgradeRequired},
		{"forwarded", func(r *http.Request) { r.Header.Set("Forwarded", "for=127.0.0.1") }, http.StatusBadRequest},
		{"chunked", func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, http.StatusBadRequest},
		{"wrong-path", func(r *http.Request) { r.URL.Path = "/v2/mailboxes/register" }, http.StatusNotFound},
		{"wrong-token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrong") }, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, V2ProvisionAdminPath, bytes.NewReader(raw))
			r.RemoteAddr = "127.0.0.1:10"
			r.Header.Set("Authorization", "Bearer admin-secret")
			r.Header.Set("Content-Type", "application/json")
			r.ContentLength = int64(len(raw))
			tt.mutate(r)
			w := httptest.NewRecorder()
			server.ServeHTTP(w, r)
			if w.Code != tt.want {
				t.Fatalf("got=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestLoadV2AdminCredentialFromPrivateFileAndFD(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(root, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, "admin.token")
	if err := os.WriteFile(path, []byte("admin-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	credential, err := LoadV2AdminCredentialFromPrivateFile(path)
	if err != nil || credential.Token != "admin-secret" || !strings.Contains(credential.Label, "[redacted]") {
		t.Fatalf("file credential=%+v err=%v", credential, err)
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
	fdCredential, err := LoadV2AdminCredentialFromFD(reader)
	if err != nil || fdCredential.Token != "admin-secret" || !strings.Contains(fdCredential.Label, "fd:") {
		t.Fatalf("fd credential=%+v err=%v", fdCredential, err)
	}
}

func TestLoadV2AdminCredentialFromFDRejectsInvalidSources(t *testing.T) {
	newSocketpair := func(t *testing.T) (int, int) {
		t.Helper()
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		return fds[0], fds[1]
	}
	sendAndLoad := func(t *testing.T, payload []byte, shutdownWriter bool) error {
		t.Helper()
		reader, writer := newSocketpair(t)
		defer unix.Close(writer)
		if len(payload) > 0 {
			if _, err := unix.Write(writer, payload); err != nil {
				t.Fatal(err)
			}
		}
		if shutdownWriter {
			if err := unix.Shutdown(writer, unix.SHUT_WR); err != nil {
				t.Fatal(err)
			}
		}
		_, err := LoadV2AdminCredentialFromFD(reader)
		return err
	}

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "regular.token")
	if err := os.WriteFile(path, []byte("admin-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadV2AdminCredentialFromFD(int(file.Fd())); err == nil {
		t.Fatal("regular file fd accepted")
	}
	file.Close()

	if err := sendAndLoad(t, []byte(""), true); err == nil {
		t.Fatal("empty fd accepted")
	}
	if err := sendAndLoad(t, []byte("admin secret"), true); err == nil {
		t.Fatal("whitespace fd accepted")
	}
	if err := sendAndLoad(t, []byte("admin-secret\n"), true); err == nil {
		t.Fatal("newline fd accepted")
	}
	if err := sendAndLoad(t, []byte{0xff, 0xfe}, true); err == nil {
		t.Fatal("non-ascii fd accepted")
	}
	if err := sendAndLoad(t, bytes.Repeat([]byte("a"), v2AdminBearerMaxBytes+1), true); err == nil {
		t.Fatal("overlong fd accepted")
	}
	if err := sendAndLoad(t, []byte("admin-secret"), false); err == nil {
		t.Fatal("non-eof fd accepted")
	}

	pipeFDs := make([]int, 2)
	if err := unix.Pipe(pipeFDs); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pipeFDs[0])
	defer unix.Close(pipeFDs[1])
	if _, err := LoadV2AdminCredentialFromFD(pipeFDs[1]); err == nil {
		t.Fatal("write-only pipe fd accepted")
	}

	pipeSuccess := make([]int, 2)
	if err := unix.Pipe(pipeSuccess); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(pipeSuccess[1], []byte("pipe-secret")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(pipeSuccess[1]); err != nil {
		t.Fatal(err)
	}
	pipeCredential, err := LoadV2AdminCredentialFromFD(pipeSuccess[0])
	if err != nil || pipeCredential.Token != "pipe-secret" {
		t.Fatalf("pipe credential=%+v err=%v", pipeCredential, err)
	}

	fifoPath := filepath.Join(root, "admin.fifo")
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := unix.Open(fifoPath, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(reader)
	if _, err := LoadV2AdminCredentialFromFD(reader); err == nil {
		t.Fatal("empty non-eof fifo accepted")
	}
}

func TestV2ProvisionServerShutdownBeforeStartAndListenFailure(t *testing.T) {
	db := openV2TestDB(t, filepath.Join(t.TempDir(), "provision-lifecycle.db"))
	defer db.Close()
	preStopped, err := NewV2ProvisionServer(db, V2ProvisionServerConfig{
		Addr:                  "127.0.0.1:0",
		Credential:            V2ProvisionCredentialSource{Token: "admin-secret", Label: "test [redacted]"},
		AllowLoopbackHTTPOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := preStopped.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown before start: %v", err)
	}
	if err := preStopped.Start(); err != nil {
		t.Fatalf("start after pre-start shutdown: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server, err := NewV2ProvisionServer(db, V2ProvisionServerConfig{
		Addr:                  listener.Addr().String(),
		Credential:            V2ProvisionCredentialSource{Token: "admin-secret", Label: "test [redacted]"},
		AllowLoopbackHTTPOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err == nil || !strings.Contains(err.Error(), "listen") {
		t.Fatalf("occupied listener start error=%v", err)
	}
}
