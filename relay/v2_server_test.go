package relay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type v2HTTPFixture struct {
	db           *V2MailboxDB
	p            ProvisionedMailbox
	host, device *V2Server
}

func newV2HTTPFixture(t *testing.T) v2HTTPFixture {
	t.Helper()
	db := openV2TestDB(t, filepath.Join(t.TempDir(), "http.db"))
	p := ProvisionedMailbox{MailboxID: "mbx-" + strings.Repeat("ab", 32), Epoch: 1, HostTokenDigest: V2Digest(sha256.Sum256([]byte("host"))), DeviceTokenDigest: V2Digest(sha256.Sum256([]byte("device"))), HostIdentityCommitment: testV2Digest("host-id"), DeviceKeyCommitment: testV2Digest("device-id"), State: "active"}
	if created, err := db.ProvisionMailbox(context.Background(), p); err != nil || !created {
		t.Fatal(err)
	}
	host, err := NewV2Server(db, V2ServerConfig{Addr: "127.0.0.1:1", Role: V2RoleHost, AllowLoopbackHTTPTest: true})
	if err != nil {
		t.Fatal(err)
	}
	device, err := NewV2Server(db, V2ServerConfig{Addr: "127.0.0.1:2", Role: V2RoleDevice, AllowLoopbackHTTPTest: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return v2HTTPFixture{db, p, host, device}
}

func v2Request(t *testing.T, server *V2Server, method, path, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.RemoteAddr = "127.0.0.1:1234"
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
		r.ContentLength = int64(len(body))
	}
	w := httptest.NewRecorder()
	server.ServeHTTP(w, r)
	return w
}

func TestV2ServerRoleMatrixAndWrongToken(t *testing.T) {
	f := newV2HTTPFixture(t)
	now := time.Now()
	frame := validV2Frame(now, 1)
	raw, _ := json.Marshal(frame)
	path := "/v2/mailboxes/" + f.p.MailboxID + "/frames"
	if got := v2Request(t, f.device, http.MethodPost, path, "device", raw).Code; got != http.StatusForbidden {
		t.Fatalf("device host-direction publish=%d", got)
	}
	if got := v2Request(t, f.host, http.MethodPost, path, "wrong", raw).Code; got != http.StatusUnauthorized {
		t.Fatalf("wrong token=%d", got)
	}
	if got := v2Request(t, f.host, http.MethodPost, path, "host", raw).Code; got != http.StatusCreated {
		t.Fatalf("host publish=%d", got)
	}
	query := path + "?direction=host_to_device&after_sequence=0"
	if got := v2Request(t, f.host, http.MethodGet, query, "host", nil).Code; got != http.StatusForbidden {
		t.Fatalf("host same-dir read=%d", got)
	}
	if got := v2Request(t, f.device, http.MethodGet, query, "device", nil).Code; got != http.StatusOK {
		t.Fatalf("device read=%d", got)
	}
	ack := OpaqueAckV2{OpaqueAckV2Schema, f.p.MailboxID, V2HostToDevice, 1, 1}
	ackRaw, _ := ack.CanonicalBytes()
	ackPath := "/v2/mailboxes/" + f.p.MailboxID + "/acks"
	if got := v2Request(t, f.host, http.MethodPost, ackPath, "host", ackRaw).Code; got != http.StatusForbidden {
		t.Fatalf("host ack=%d", got)
	}
	if got := v2Request(t, f.device, http.MethodPost, ackPath, "device", ackRaw).Code; got != http.StatusOK {
		t.Fatalf("device ack=%d", got)
	}
}

func TestV2ServerStrictTransportSmugglingAndBodies(t *testing.T) {
	f := newV2HTTPFixture(t)
	path := "/v2/mailboxes/" + f.p.MailboxID + "/frames"
	raw, _ := validV2Frame(time.Now(), 1).CanonicalBytes()
	tests := []struct {
		name   string
		mutate func(*http.Request)
		want   int
	}{
		{"non-loopback", func(r *http.Request) { r.RemoteAddr = "198.51.100.1:42" }, http.StatusUpgradeRequired},
		{"forwarded", func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "https") }, http.StatusBadRequest},
		{"chunked", func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, http.StatusBadRequest},
		{"duplicate auth", func(r *http.Request) { r.Header.Add("Authorization", "Bearer host") }, http.StatusUnauthorized},
		{"content type params", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") }, http.StatusBadRequest},
		{"unknown query", func(r *http.Request) { r.URL.RawQuery = "role=host" }, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
			r.RemoteAddr = "127.0.0.1:9"
			r.Header.Set("Authorization", "Bearer host")
			r.Header.Set("Content-Type", "application/json")
			r.ContentLength = int64(len(raw))
			tt.mutate(r)
			w := httptest.NewRecorder()
			f.host.ServeHTTP(w, r)
			if w.Code != tt.want {
				t.Fatalf("got=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
	oversized := bytes.Repeat([]byte("x"), V2MaxWireFrame+1)
	if got := v2Request(t, f.host, http.MethodPost, path, "host", oversized).Code; got != http.StatusBadRequest {
		t.Fatalf("oversized=%d", got)
	}
	if got := v2Request(t, f.host, http.MethodPut, path, "host", raw).Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("method=%d", got)
	}
	if got := v2Request(t, f.host, http.MethodPost, path+"/", "host", raw).Code; got != http.StatusNotFound {
		t.Fatalf("path=%d", got)
	}
}

func TestV2ServerRevokeAndV1KeyIsolation(t *testing.T) {
	f := newV2HTTPFixture(t)
	mailboxPath := "/v2/mailboxes/" + f.p.MailboxID
	if got := v2Request(t, f.device, http.MethodDelete, mailboxPath, "device", nil).Code; got != http.StatusForbidden {
		t.Fatalf("device delete=%d", got)
	}
	if got := v2Request(t, f.host, http.MethodDelete, mailboxPath, "host", nil).Code; got != http.StatusNoContent {
		t.Fatalf("host delete=%d", got)
	}
	query := mailboxPath + "/frames?direction=host_to_device&after_sequence=0"
	if got := v2Request(t, f.device, http.MethodGet, query, "device", nil).Code; got != http.StatusGone {
		t.Fatalf("after revoke=%d", got)
	}
	f2 := newV2HTTPFixture(t)
	raw, _ := validV2Frame(time.Now(), 1).CanonicalBytes()
	if got := v2Request(t, f2.host, http.MethodPost, "/v2/mailboxes/"+f2.p.MailboxID+"/frames", "alpha-local-token", raw).Code; got != http.StatusUnauthorized {
		t.Fatalf("v1 token authenticated v2=%d", got)
	}
}

func TestV2ServerConfigAndNoPublicProvisioning(t *testing.T) {
	db := openV2TestDB(t, filepath.Join(t.TempDir(), "config.db"))
	defer db.Close()
	if _, err := NewV2Server(db, V2ServerConfig{Addr: "0.0.0.0:1", Role: V2RoleHost, AllowLoopbackHTTPTest: true}); err == nil {
		t.Fatal("non-loopback test HTTP allowed")
	}
	s, err := NewV2Server(db, V2ServerConfig{Addr: "127.0.0.1:1", Role: V2RoleHost, AllowLoopbackHTTPTest: true})
	if err != nil {
		t.Fatal(err)
	}
	r := v2Request(t, s, http.MethodPost, "/v2/mailboxes/register", "anything", []byte("{}"))
	if r.Code != http.StatusNotFound {
		t.Fatalf("public registration=%d", r.Code)
	}
}

func TestV2ServerShutdownBeforeStartAndListenFailure(t *testing.T) {
	db := openV2TestDB(t, filepath.Join(t.TempDir(), "lifecycle.db"))
	defer db.Close()
	preStopped, err := NewV2Server(db, V2ServerConfig{Addr: "127.0.0.1:0", Role: V2RoleHost, AllowLoopbackHTTPTest: true})
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
	server, err := NewV2Server(db, V2ServerConfig{Addr: listener.Addr().String(), Role: V2RoleHost, AllowLoopbackHTTPTest: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err == nil || !strings.Contains(err.Error(), "listen") {
		t.Fatalf("occupied listener start error=%v", err)
	}
}
