package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const (
	testPublicOrigin = "https://pair.example:8443"
	testJoinID       = "join-0123456789abcdef0123456789abcdef"
	testMailboxID    = "mbx-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func request(t *testing.T, handler http.Handler, method, target string, body []byte, headers http.Header) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, bytes.NewReader(body))
	r.Host = "pair.example:8443"
	r.RequestURI = target
	for name, values := range headers {
		for _, value := range values {
			r.Header.Add(name, value)
		}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestIngressTLS13AndExactJoinForwarding(t *testing.T) {
	var seen struct {
		sync.Mutex
		host   string
		path   string
		header http.Header
	}
	join := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Lock()
		seen.host, seen.path, seen.header = r.Host, r.URL.RequestURI(), r.Header.Clone()
		seen.Unlock()
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("join"))
	}))
	defer join.Close()
	relay := httptest.NewServer(http.NotFoundHandler())
	defer relay.Close()

	handler := newIngress(mustURL(t, testPublicOrigin), mustURL(t, join.URL), mustURL(t, relay.URL), []byte("trusted-token"))
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()

	legacyTransport := server.Client().Transport.(*http.Transport).Clone()
	legacyTransport.TLSClientConfig = legacyTransport.TLSClientConfig.Clone()
	legacyTransport.TLSClientConfig.MinVersion = tls.VersionTLS12
	legacyTransport.TLSClientConfig.MaxVersion = tls.VersionTLS12
	legacyClient := &http.Client{Transport: legacyTransport}
	if _, err := legacyClient.Get(server.URL + "/j/" + testJoinID); err == nil {
		t.Fatal("TLS 1.2 unexpectedly reached ingress")
	}

	req, err := http.NewRequest(http.MethodGet, server.URL+"/j/"+testJoinID, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "pair.example:8443"
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Authorization", "Bearer must-not-reach-join")
	req.Header.Set("Cookie", "private=must-not-reach-join")
	req.Header.Set("Forwarded", "for=attacker")
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Nomad-Trusted-Ingress", "attacker")
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || string(body) != "join" {
		t.Fatalf("status=%d body=%q", response.StatusCode, body)
	}
	seen.Lock()
	defer seen.Unlock()
	if seen.host != "pair.example:8443" || seen.path != "/j/"+testJoinID {
		t.Fatalf("host=%q path=%q", seen.host, seen.path)
	}
	if seen.header.Get("X-Forwarded-Proto") != "https" || seen.header.Get("X-Forwarded-Host") != "pair.example:8443" || seen.header.Get("X-Nomad-Trusted-Ingress") != "trusted-token" {
		t.Fatalf("missing normalized ingress headers: %#v", seen.header)
	}
	for _, name := range []string{"Authorization", "Cookie", "Forwarded", "Connection"} {
		if got := seen.header.Values(name); len(got) != 0 {
			t.Fatalf("join leaked %s=%q", name, got)
		}
	}
}

func TestIngressJoinCookieBoundaryAndRelayHeaderIsolation(t *testing.T) {
	type captured struct {
		path   string
		header http.Header
		body   string
	}
	joinSeen := make(chan captured, 1)
	relaySeen := make(chan captured, 1)
	join := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		joinSeen <- captured{r.URL.RequestURI(), r.Header.Clone(), string(body)}
		w.Header().Add("Set-Cookie", "__Host-nomad-join=AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=120")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer join.Close()
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		relaySeen <- captured{r.URL.RequestURI(), r.Header.Clone(), string(body)}
		w.Header().Set("Set-Cookie", "relay=forbidden")
		w.Header().Set("X-Upstream-Secret", "forbidden")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"stored":true,"idempotent":false}`))
	}))
	defer relay.Close()

	handler := newIngress(mustURL(t, testPublicOrigin), mustURL(t, join.URL), mustURL(t, relay.URL), []byte("trusted-token"))
	joinHeaders := http.Header{
		"Content-Type":      {"application/json"},
		"Origin":            {testPublicOrigin},
		"Sec-Fetch-Site":    {"same-origin"},
		"Sec-Fetch-Mode":    {"cors"},
		"Sec-Fetch-Dest":    {"empty"},
		"Cookie":            {"tracking=no; __Host-nomad-join=AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA; analytics=no"},
		"Authorization":     {"Bearer relay-token-must-not-leak"},
		"X-Forwarded-For":   {"203.0.113.5"},
		"X-Internal-Canary": {"must-not-leak"},
	}
	joinResponse := request(t, handler, http.MethodPost, "/api/pairing/join/confirm", []byte(`{}`), joinHeaders)
	if joinResponse.Code != http.StatusOK {
		t.Fatalf("join status=%d body=%s", joinResponse.Code, joinResponse.Body.String())
	}
	if got := joinResponse.Header().Values("Set-Cookie"); len(got) != 1 || !strings.HasPrefix(got[0], "__Host-nomad-join=") {
		t.Fatalf("join Set-Cookie=%q", got)
	}
	if joinResponse.Header().Get("Connection") != "" {
		t.Fatal("hop-by-hop response header leaked")
	}
	joined := <-joinSeen
	if joined.header.Get("Cookie") != "__Host-nomad-join=AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA" {
		t.Fatalf("normalized cookie=%q", joined.header.Get("Cookie"))
	}
	for _, name := range []string{"Authorization", "X-Forwarded-For", "X-Internal-Canary"} {
		if joined.header.Get(name) != "" {
			t.Fatalf("join leaked %s", name)
		}
	}

	relayHeaders := http.Header{
		"Authorization":           {"Bearer device-token"},
		"Content-Type":            {"application/json"},
		"Cookie":                  {"__Host-nomad-join=must-not-reach-relay"},
		"Origin":                  {testPublicOrigin},
		"Forwarded":               {"for=attacker"},
		"X-Forwarded-Proto":       {"https"},
		"X-Nomad-Trusted-Ingress": {"trusted-token"},
	}
	relayResponse := request(t, handler, http.MethodPost, "/v2/mailboxes/"+testMailboxID+"/frames", []byte(`{}`), relayHeaders)
	if relayResponse.Code != http.StatusCreated {
		t.Fatalf("relay status=%d body=%s", relayResponse.Code, relayResponse.Body.String())
	}
	proxied := <-relaySeen
	if proxied.header.Get("Authorization") != "Bearer device-token" || proxied.header.Get("Content-Type") != "application/json" {
		t.Fatalf("relay auth/content type missing: %#v", proxied.header)
	}
	for _, name := range []string{"Cookie", "Origin", "Forwarded", "X-Forwarded-Proto", "X-Nomad-Trusted-Ingress"} {
		if proxied.header.Get(name) != "" {
			t.Fatalf("relay leaked %s", name)
		}
	}
	if relayResponse.Header().Get("Set-Cookie") != "" || relayResponse.Header().Get("X-Upstream-Secret") != "" {
		t.Fatalf("relay response leaked upstream headers: %#v", relayResponse.Header())
	}
}

func TestIngressRejectsNonAllowlistedAndEncodedRoutesLocally(t *testing.T) {
	var hits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer upstream.Close()
	handler := newIngress(mustURL(t, testPublicOrigin), mustURL(t, upstream.URL), mustURL(t, upstream.URL), []byte("trusted-token"))

	tests := []struct {
		name, method, target string
		mutate               func(*http.Request)
	}{
		{"desktop", http.MethodPost, "/api/desktop/pairing/create", nil},
		{"internal", http.MethodGet, "/internal/session/current", nil},
		{"admin", http.MethodPost, "/v2/admin/mailboxes/provision", nil},
		{"legacy", http.MethodGet, "/v1/frames", nil},
		{"unknown pairing", http.MethodPost, "/api/pairing/extra", nil},
		{"join method", http.MethodPost, "/j/" + testJoinID, nil},
		{"assets traversal", http.MethodGet, "/assets/../secret", nil},
		{"mailbox delete", http.MethodDelete, "/v2/mailboxes/" + testMailboxID, nil},
		{"mailbox slash", http.MethodGet, "/v2/mailboxes/" + testMailboxID + "/frames/", nil},
		{"read query order", http.MethodGet, "/v2/mailboxes/" + testMailboxID + "/frames?after_sequence=0&direction=host_to_device", nil},
		{"read wrong direction", http.MethodGet, "/v2/mailboxes/" + testMailboxID + "/frames?direction=device_to_host&after_sequence=0", nil},
		{"encoded join", http.MethodGet, "/j/" + testJoinID, func(r *http.Request) { r.URL.RawPath = "/%6a/" + testJoinID; r.RequestURI = r.URL.RawPath }},
		{"encoded slash", http.MethodGet, "/j/" + testJoinID, func(r *http.Request) { r.URL.RawPath = "/j%2f" + testJoinID; r.RequestURI = r.URL.RawPath }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(test.method, test.target, nil)
			r.Host = "pair.example:8443"
			if test.mutate != nil {
				test.mutate(r)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusNotFound {
				t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
			}
		})
	}
	if hits.Load() != 0 {
		t.Fatalf("rejected routes reached upstream %d times", hits.Load())
	}
}

func TestIngressBoundsRequestsAndResponses(t *testing.T) {
	var hits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxPairingResponse+1))
	}))
	defer upstream.Close()
	handler := newIngress(mustURL(t, testPublicOrigin), mustURL(t, upstream.URL), mustURL(t, upstream.URL), []byte("trusted-token"))
	headers := http.Header{"Content-Type": {"application/json"}}
	oversized := request(t, handler, http.MethodPost, "/api/pairing/join/start", bytes.Repeat([]byte("x"), maxPairingBody+1), headers)
	if oversized.Code != http.StatusBadRequest || hits.Load() != 0 {
		t.Fatalf("oversized request status=%d hits=%d", oversized.Code, hits.Load())
	}
	response := request(t, handler, http.MethodPost, "/api/pairing/join/start", []byte(`{}`), headers)
	if response.Code != http.StatusBadGateway || hits.Load() != 1 {
		t.Fatalf("oversized response status=%d hits=%d", response.Code, hits.Load())
	}
}

func TestIngressRejectsInvalidJoinSetCookieAndRedirect(t *testing.T) {
	var redirectHits atomic.Int64
	var badCookieHits atomic.Int64
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectHits.Add(1)
		w.Header().Set("Location", "http://127.0.0.1/internal")
		w.WriteHeader(http.StatusFound)
	}))
	defer redirect.Close()
	badCookie := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		badCookieHits.Add(1)
		w.Header().Set("Set-Cookie", "tracking=forbidden; Secure")
		w.WriteHeader(http.StatusOK)
	}))
	defer badCookie.Close()

	headers := http.Header{"Content-Type": {"application/json"}}
	redirectIngress := newIngress(mustURL(t, testPublicOrigin), mustURL(t, redirect.URL), mustURL(t, redirect.URL), []byte("trusted-token"))
	if got := request(t, redirectIngress, http.MethodPost, "/api/pairing/join/start", []byte(`{}`), headers); got.Code != http.StatusBadGateway {
		t.Fatalf("redirect status=%d", got.Code)
	}
	if redirectHits.Load() != 1 {
		t.Fatalf("redirect followed: hits=%d", redirectHits.Load())
	}
	badCookieIngress := newIngress(mustURL(t, testPublicOrigin), mustURL(t, badCookie.URL), mustURL(t, badCookie.URL), []byte("trusted-token"))
	if got := request(t, badCookieIngress, http.MethodPost, "/api/pairing/join/start", []byte(`{}`), headers); got.Code != http.StatusBadGateway {
		t.Fatalf("invalid cookie status=%d headers=%#v", got.Code, got.Header())
	}
	if badCookieHits.Load() != 1 {
		t.Fatalf("unexpected cookie upstream hits=%d", badCookieHits.Load())
	}
}

func TestReadyFrameIsExactCanonicalAndContentFree(t *testing.T) {
	var output bytes.Buffer
	if err := writeReady(&output); err != nil {
		t.Fatal(err)
	}
	raw := output.Bytes()
	if len(raw) < 4 {
		t.Fatal("ready frame too short")
	}
	length := binary.BigEndian.Uint32(raw[:4])
	if int(length) != len(raw)-4 {
		t.Fatalf("length=%d actual=%d", length, len(raw)-4)
	}
	want := `{"schema":"nomad.https-ingress.ready.v1","ready":true}`
	if string(raw[4:]) != want {
		t.Fatalf("ready=%q", raw[4:])
	}
	for _, forbidden := range []string{"host", "port", "path", "token", "cert", "trusted-token", "pair.example"} {
		if bytes.Contains(bytes.ToLower(raw[4:]), []byte(forbidden)) {
			t.Fatalf("ready frame leaked %q", forbidden)
		}
	}
}

type recordingWriteCloser struct {
	bytes.Buffer
	closed bool
}

func (w *recordingWriteCloser) Close() error {
	w.closed = true
	return nil
}

func TestSignalReadyClosesDescriptorAfterExactFrame(t *testing.T) {
	writer := &recordingWriteCloser{}
	if err := signalReady(writer); err != nil {
		t.Fatal(err)
	}
	if !writer.closed {
		t.Fatal("ready descriptor was not closed")
	}
	want := make([]byte, 4+len(readyPayload))
	binary.BigEndian.PutUint32(want[:4], uint32(len(readyPayload)))
	copy(want[4:], readyPayload)
	if !bytes.Equal(writer.Bytes(), want) {
		t.Fatalf("ready frame=%q", writer.Bytes())
	}
}

func TestConfigurationRejectsWildcardLoopbackAndSecretAlternatives(t *testing.T) {
	for _, addr := range []string{"", "0.0.0.0:8443", "[::]:8443", "127.0.0.1:8443", "localhost:8443", "192.0.2.10:443", "https://192.0.2.10:8443"} {
		if err := validateListen(addr); err == nil {
			t.Fatalf("accepted listen %q", addr)
		}
	}
	if err := validateListen("192.0.2.10:8443"); err != nil {
		t.Fatalf("valid explicit listen: %v", err)
	}
	for _, raw := range []string{"http://pair.example:8443", "https://pair.example", "https://user@pair.example:8443", "https://pair.example:8443/path", "https://pair.example:8443?x=1"} {
		if _, err := parsePublicOrigin(raw); err == nil {
			t.Fatalf("accepted public origin %q", raw)
		}
	}
	for _, raw := range []string{"http://localhost:9000", "http://0.0.0.0:9000", "https://127.0.0.1:9000", "http://127.0.0.1:9000/path"} {
		if _, err := parseLoopbackOrigin(raw, "test"); err == nil {
			t.Fatalf("accepted upstream %q", raw)
		}
	}
	base := []string{"--listen", "192.0.2.10:8443", "--public-origin", testPublicOrigin, "--join-upstream", "http://127.0.0.1:9001", "--device-relay-upstream", "http://127.0.0.1:9002", "--tls-cert-fd", "10", "--tls-key-fd", "11", "--trusted-join-token-fd", "12", "--ready-fd", "13"}
	for _, secretOption := range []string{"--tls-cert", "--tls-key", "--trusted-join-token"} {
		if _, err := parseConfig(append(append([]string{}, base...), secretOption, "secret")); err == nil {
			t.Fatalf("accepted forbidden secret option %s", secretOption)
		}
	}
}

func TestTrustedTokenFDRequiresExactBytesEOFAndCloses(t *testing.T) {
	for _, size := range []int{31, 33} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(bytes.Repeat([]byte{0x5a}, size)); err != nil {
				t.Fatal(err)
			}
			_ = writer.Close()
			got, err := readAndCloseFD(int(reader.Fd()), 32, true)
			if err == nil {
				zeroBytes(got)
				t.Fatalf("accepted %d-byte token", size)
			}
			if _, err := reader.Stat(); err == nil {
				t.Fatal("consumed token descriptor remained open")
			}
		})
	}
}
