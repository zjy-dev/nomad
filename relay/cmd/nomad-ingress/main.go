package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	certFD             = 10
	keyFD              = 11
	trustedJoinFD      = 12
	readyFD            = 13
	maxTLSMaterial     = 1024 * 1024
	maxPairingBody     = 4 * 1024
	maxFrameBody       = 96 * 1024
	maxAckBody         = 4 * 1024
	maxPairingResponse = 64 * 1024
	maxStaticResponse  = 16 * 1024 * 1024
	maxFramesResponse  = 100*96*1024 + 64*1024
	shutdownTimeout    = 10 * time.Second
)

var (
	joinPathRE    = regexp.MustCompile(`^/j/join-[0-9a-f]{32}$`)
	mailboxPathRE = regexp.MustCompile(`^/v2/mailboxes/mbx-[0-9a-f]{64}/(frames|acks)$`)
)

var readyPayload = []byte(`{"schema":"nomad.https-ingress.ready.v1","ready":true}`)

type config struct {
	listen              string
	publicOrigin        *url.URL
	joinUpstream        *url.URL
	deviceRelayUpstream *url.URL
	tlsCertificate      tls.Certificate
	trustedJoinToken    []byte
	readyWriter         io.WriteCloser
}

type routeKind uint8

const (
	routeDenied routeKind = iota
	routeJoinShell
	routeJoinAsset
	routeJoinAPI
	routeRelayFrames
	routeRelayAcks
)

type route struct {
	kind        routeKind
	upstream    *url.URL
	requestMax  int64
	responseMax int64
}

type ingress struct {
	publicOrigin        *url.URL
	joinUpstream        *url.URL
	deviceRelayUpstream *url.URL
	trustedJoinToken    []byte
	client              *http.Client
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		log.Printf("nomad HTTPS ingress failed: %v", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	cfg, err := parseConfig(args)
	if err != nil {
		return err
	}
	defer cfg.readyWriter.Close()
	defer zeroBytes(cfg.trustedJoinToken)

	listener, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return fmt.Errorf("bind HTTPS listener: %w", err)
	}

	handler := newIngress(cfg.publicOrigin, cfg.joinUpstream, cfg.deviceRelayUpstream, cfg.trustedJoinToken)
	defer zeroBytes(handler.trustedJoinToken)
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      35 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cfg.tlsCertificate},
		},
	}
	tlsListener := tls.NewListener(listener, server.TLSConfig)

	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(tlsListener) }()
	if err := signalReady(cfg.readyWriter); err != nil {
		_ = server.Close()
		<-serveResult
		return fmt.Errorf("publish ready frame: %w", err)
	}
	cfg.readyWriter = nopWriteCloser{}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		err := server.Shutdown(shutdownCtx)
		cancel()
		if err != nil {
			_ = server.Close()
			return fmt.Errorf("shutdown HTTPS listener: %w", err)
		}
		serveErr := <-serveResult
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return fmt.Errorf("serve HTTPS: %w", serveErr)
		}
		return nil
	case serveErr := <-serveResult:
		if serveErr == nil || errors.Is(serveErr, http.ErrServerClosed) {
			return errors.New("HTTPS listener stopped unexpectedly")
		}
		return fmt.Errorf("serve HTTPS: %w", serveErr)
	}
}

func parseConfig(args []string) (config, error) {
	flags := flag.NewFlagSet("nomad-https-ingress", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	listen := flags.String("listen", "", "specific LAN IP and unprivileged port")
	publicOrigin := flags.String("public-origin", "", "exact public HTTPS origin")
	joinUpstream := flags.String("join-upstream", "", "exact loopback join Gateway origin")
	deviceUpstream := flags.String("device-relay-upstream", "", "exact loopback device Relay origin")
	tlsCertFD := flags.Int("tls-cert-fd", -1, "inherited TLS certificate descriptor")
	tlsKeyFD := flags.Int("tls-key-fd", -1, "inherited TLS private-key descriptor")
	trustedFD := flags.Int("trusted-join-token-fd", -1, "inherited trusted-ingress token descriptor")
	ready := flags.Int("ready-fd", -1, "inherited ready descriptor")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return config{}, errors.New("invalid ingress arguments")
	}
	if *tlsCertFD != certFD || *tlsKeyFD != keyFD || *trustedFD != trustedJoinFD || *ready != readyFD {
		return config{}, errors.New("ingress requires TLS certificate FD 10, TLS key FD 11, trusted token FD 12, and ready FD 13")
	}
	if err := validateListen(*listen); err != nil {
		return config{}, err
	}
	public, err := parsePublicOrigin(*publicOrigin)
	if err != nil {
		return config{}, err
	}
	_, listenPort, _ := net.SplitHostPort(*listen)
	if public.Port() != listenPort {
		return config{}, errors.New("--public-origin port must match --listen port")
	}
	join, err := parseLoopbackOrigin(*joinUpstream, "join upstream")
	if err != nil {
		return config{}, err
	}
	device, err := parseLoopbackOrigin(*deviceUpstream, "device Relay upstream")
	if err != nil {
		return config{}, err
	}

	certPEM, certErr := readAndCloseFD(certFD, maxTLSMaterial, false)
	if certErr != nil {
		return config{}, errors.New("invalid TLS certificate descriptor")
	}
	defer zeroBytes(certPEM)
	keyPEM, keyErr := readAndCloseFD(keyFD, maxTLSMaterial, false)
	if keyErr != nil {
		return config{}, errors.New("invalid TLS key descriptor")
	}
	defer zeroBytes(keyPEM)
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return config{}, errors.New("invalid TLS certificate or key")
	}
	token, tokenErr := readAndCloseFD(trustedJoinFD, 32, true)
	if tokenErr != nil || len(token) != 32 {
		zeroBytes(token)
		return config{}, errors.New("invalid trusted-ingress token descriptor")
	}
	trustedToken := make([]byte, base64.RawURLEncoding.EncodedLen(len(token)))
	base64.RawURLEncoding.Encode(trustedToken, token)
	zeroBytes(token)

	readyFile := os.NewFile(uintptr(readyFD), "ingress-ready")
	if readyFile == nil {
		zeroBytes(trustedToken)
		return config{}, errors.New("invalid ready descriptor")
	}
	if err := validatePipeOrSocket(readyFile); err != nil {
		_ = readyFile.Close()
		zeroBytes(trustedToken)
		return config{}, errors.New("invalid ready descriptor")
	}
	return config{*listen, public, join, device, certificate, trustedToken, readyFile}, nil
}

func validateListen(value string) error {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return errors.New("--listen must be one specific LAN IP and port")
	}
	ip := net.ParseIP(host)
	port, portErr := strconv.Atoi(portText)
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || portErr != nil || port < 1024 || port > 65535 {
		return errors.New("--listen must be one specific non-loopback LAN IP and unprivileged port")
	}
	return nil
}

func parsePublicOrigin(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("--public-origin must be an exact HTTPS origin with an explicit port")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("--public-origin has an invalid port")
	}
	if canonicalHost := net.JoinHostPort(strings.ToLower(u.Hostname()), u.Port()); u.Host != canonicalHost {
		return nil, errors.New("--public-origin authority is not canonical")
	}
	return u, nil
}

func parseLoopbackOrigin(value, label string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Port() == "" {
		return nil, fmt.Errorf("%s must be an exact loopback HTTP origin", label)
	}
	ip := net.ParseIP(u.Hostname())
	port, portErr := strconv.Atoi(u.Port())
	if ip == nil || !ip.IsLoopback() || portErr != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("%s must be an exact loopback HTTP origin", label)
	}
	return u, nil
}

func readAndCloseFD(fd int, max int64, pipeOnly bool) ([]byte, error) {
	file := os.NewFile(uintptr(fd), fmt.Sprintf("inherited-fd-%d", fd))
	if file == nil {
		return nil, os.ErrInvalid
	}
	defer file.Close()
	if pipeOnly {
		if err := validatePipeOrSocket(file); err != nil {
			return nil, err
		}
	} else {
		info, err := file.Stat()
		if err != nil || info.IsDir() {
			return nil, os.ErrInvalid
		}
	}
	raw, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > max || pipeOnly && int64(len(raw)) != max {
		zeroBytes(raw)
		return nil, os.ErrInvalid
	}
	return raw, nil
}

func validatePipeOrSocket(file *os.File) error {
	info, err := file.Stat()
	if err != nil || info.Mode()&(os.ModeNamedPipe|os.ModeSocket) == 0 {
		return os.ErrInvalid
	}
	return nil
}

func newIngress(publicOrigin, joinUpstream, deviceUpstream *url.URL, trustedToken []byte) *ingress {
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:      false,
		DisableCompression:     true,
		MaxIdleConns:           16,
		MaxIdleConnsPerHost:    8,
		MaxConnsPerHost:        32,
		IdleConnTimeout:        30 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 16 * 1024,
	}
	return &ingress{
		publicOrigin:        publicOrigin,
		joinUpstream:        joinUpstream,
		deviceRelayUpstream: deviceUpstream,
		trustedJoinToken:    trustedToken,
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (i *ingress) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Host != i.publicOrigin.Host {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	selected, ok := i.selectRoute(r)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	body, err := readRequestBody(r, selected.requestMax)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	target := *selected.upstream
	target.Path = r.URL.Path
	target.RawQuery = r.URL.RawQuery
	upstreamRequest, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	upstreamRequest.ContentLength = int64(len(body))
	if err := i.setRequestHeaders(upstreamRequest, r, selected.kind); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	response, err := i.client.Do(upstreamRequest)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	if response.Header.Get("Content-Encoding") != "" || !validResponseCookies(response.Header, selected.kind) {
		http.Error(w, "invalid upstream response", http.StatusBadGateway)
		return
	}
	if response.ContentLength > selected.responseMax {
		http.Error(w, "upstream response too large", http.StatusBadGateway)
		return
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, selected.responseMax+1))
	if err != nil || int64(len(responseBody)) > selected.responseMax {
		http.Error(w, "upstream response too large", http.StatusBadGateway)
		return
	}
	copyResponseHeaders(w.Header(), response.Header, selected.kind)
	w.Header().Set("Content-Length", strconv.Itoa(len(responseBody)))
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(responseBody)
}

func (i *ingress) selectRoute(r *http.Request) (route, bool) {
	if !canonicalRequestTarget(r) {
		return route{}, false
	}
	path := r.URL.Path
	switch {
	case joinPathRE.MatchString(path):
		if r.Method != http.MethodGet || r.URL.RawQuery != "" {
			return route{}, false
		}
		return route{routeJoinShell, i.joinUpstream, 0, maxStaticResponse}, true
	case validAssetPath(path):
		if r.Method != http.MethodGet || r.URL.RawQuery != "" {
			return route{}, false
		}
		return route{routeJoinAsset, i.joinUpstream, 0, maxStaticResponse}, true
	case isPairingPath(path):
		if r.Method != http.MethodPost || r.URL.RawQuery != "" {
			return route{}, false
		}
		return route{routeJoinAPI, i.joinUpstream, maxPairingBody, maxPairingResponse}, true
	case mailboxPathRE.MatchString(path):
		endpoint := path[strings.LastIndexByte(path, '/')+1:]
		if endpoint == "acks" {
			if r.Method != http.MethodPost || r.URL.RawQuery != "" {
				return route{}, false
			}
			return route{routeRelayAcks, i.deviceRelayUpstream, maxAckBody, maxPairingResponse}, true
		}
		if r.Method == http.MethodPost && r.URL.RawQuery == "" {
			return route{routeRelayFrames, i.deviceRelayUpstream, maxFrameBody, maxPairingResponse}, true
		}
		if r.Method == http.MethodGet && validFramesQuery(r.URL.RawQuery) {
			return route{routeRelayFrames, i.deviceRelayUpstream, 0, maxFramesResponse}, true
		}
	}
	return route{}, false
}

func canonicalRequestTarget(r *http.Request) bool {
	if r.URL == nil || r.URL.IsAbs() || r.URL.Opaque != "" || r.URL.RawPath != "" || r.URL.ForceQuery || r.URL.Path == "" || !strings.HasPrefix(r.RequestURI, "/") {
		return false
	}
	rawPath := r.RequestURI
	if q := strings.IndexByte(rawPath, '?'); q >= 0 {
		rawPath = rawPath[:q]
	}
	return rawPath == r.URL.Path && !strings.Contains(rawPath, "%") && !strings.Contains(rawPath, "\\") && !strings.Contains(rawPath, "//")
}

func validAssetPath(path string) bool {
	if !strings.HasPrefix(path, "/assets/") {
		return false
	}
	rest := strings.TrimPrefix(path, "/assets/")
	if rest == "" {
		return false
	}
	for _, part := range strings.Split(rest, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for _, ch := range part {
			if ch <= 0x20 || ch == 0x7f {
				return false
			}
		}
	}
	return true
}

func isPairingPath(path string) bool {
	switch path {
	case "/api/pairing/join/start", "/api/pairing/join/confirm", "/api/pairing/join/complete", "/api/pairing/join/abort":
		return true
	default:
		return false
	}
}

func validFramesQuery(raw string) bool {
	const prefix = "direction=host_to_device&after_sequence="
	if !strings.HasPrefix(raw, prefix) {
		return false
	}
	value := strings.TrimPrefix(raw, prefix)
	if value == "" || len(value) > 16 || len(value) > 1 && value[0] == '0' {
		return value == "0"
	}
	n, err := strconv.ParseUint(value, 10, 64)
	return err == nil && n <= 9_007_199_254_740_991
}

func readRequestBody(r *http.Request, max int64) ([]byte, error) {
	if len(r.TransferEncoding) != 0 || r.Header.Get("Transfer-Encoding") != "" || r.Header.Get("Content-Encoding") != "" {
		return nil, errors.New("unsupported framing")
	}
	if max == 0 {
		if r.ContentLength != 0 {
			return nil, errors.New("body not allowed")
		}
		return nil, nil
	}
	if r.ContentLength <= 0 || r.ContentLength > max || len(r.Header.Values("Content-Length")) > 1 {
		return nil, errors.New("invalid content length")
	}
	if values := r.Header.Values("Content-Type"); len(values) != 1 || values[0] != "application/json" {
		return nil, errors.New("invalid content type")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil || int64(len(body)) != r.ContentLength {
		return nil, errors.New("invalid body")
	}
	return body, nil
}

func (i *ingress) setRequestHeaders(out, in *http.Request, kind routeKind) error {
	if isJoin(kind) {
		out.Host = i.publicOrigin.Host
		copySingleHeader(out.Header, in.Header, "Accept")
		copySingleHeader(out.Header, in.Header, "Origin")
		copySingleHeader(out.Header, in.Header, "Sec-Fetch-Site")
		copySingleHeader(out.Header, in.Header, "Sec-Fetch-Mode")
		copySingleHeader(out.Header, in.Header, "Sec-Fetch-Dest")
		copySingleHeader(out.Header, in.Header, "User-Agent")
		if kind == routeJoinAPI {
			copySingleHeader(out.Header, in.Header, "Content-Type")
			cookie, err := normalizedJoinCookie(in.Header.Values("Cookie"))
			if err != nil {
				return err
			}
			if cookie != "" {
				out.Header.Set("Cookie", cookie)
			}
		}
		out.Header.Set("X-Forwarded-Proto", "https")
		out.Header.Set("X-Forwarded-Host", i.publicOrigin.Host)
		out.Header.Set("X-Nomad-Trusted-Ingress", string(i.trustedJoinToken))
		return nil
	}

	copySingleHeader(out.Header, in.Header, "Authorization")
	copySingleHeader(out.Header, in.Header, "Accept")
	copySingleHeader(out.Header, in.Header, "User-Agent")
	if in.Method == http.MethodPost {
		copySingleHeader(out.Header, in.Header, "Content-Type")
	}
	return nil
}

func copySingleHeader(dst, src http.Header, name string) {
	values := src.Values(name)
	if len(values) == 1 {
		dst.Set(name, values[0])
	} else if len(values) > 1 {
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func normalizedJoinCookie(values []string) (string, error) {
	var found string
	for _, header := range values {
		for _, raw := range strings.Split(header, ";") {
			part := strings.TrimSpace(raw)
			if part == "" {
				continue
			}
			name, value, ok := strings.Cut(part, "=")
			if !ok || name == "" {
				return "", errors.New("invalid cookie")
			}
			if name != "__Host-nomad-join" {
				continue
			}
			if found != "" || !validBase64URL32(value) {
				return "", errors.New("invalid join cookie")
			}
			found = "__Host-nomad-join=" + value
		}
	}
	return found, nil
}

func copyResponseHeaders(dst, src http.Header, kind routeKind) {
	for _, name := range []string{"Content-Type", "Cache-Control", "Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy"} {
		if values := src.Values(name); len(values) == 1 {
			dst.Set(name, values[0])
		}
	}
	if isJoin(kind) {
		for _, cookie := range src.Values("Set-Cookie") {
			if validJoinSetCookie(cookie) {
				dst.Add("Set-Cookie", cookie)
			}
		}
	}
}

func validResponseCookies(header http.Header, kind routeKind) bool {
	values := header.Values("Set-Cookie")
	if !isJoin(kind) {
		return true
	}
	if len(values) > 1 {
		return false
	}
	return len(values) == 0 || validJoinSetCookie(values[0])
}

func validJoinSetCookie(value string) bool {
	const prefix = "__Host-nomad-join="
	const attributes = "; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age="
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(value, prefix), attributes)
	if len(parts) != 2 {
		return false
	}
	if parts[0] != "" && !validBase64URL32(parts[0]) {
		return false
	}
	age, err := strconv.Atoi(parts[1])
	return err == nil && age >= 0 && age <= 120 && (age != 0 || parts[0] == "")
}

func validBase64URL32(value string) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(32) {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil
}

func isJoin(kind routeKind) bool {
	return kind == routeJoinShell || kind == routeJoinAsset || kind == routeJoinAPI
}

func writeReady(writer io.Writer) error {
	if len(readyPayload) > int(^uint32(0)) {
		return errors.New("ready payload too large")
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(readyPayload)))
	if err := writeFull(writer, length[:]); err != nil {
		return err
	}
	return writeFull(writer, readyPayload)
}

func signalReady(writer io.WriteCloser) error {
	writeErr := writeReady(writer)
	closeErr := writer.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func writeFull(writer io.Writer, value []byte) error {
	for len(value) != 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

type nopWriteCloser struct{}

func (nopWriteCloser) Write([]byte) (int, error) { return 0, os.ErrClosed }
func (nopWriteCloser) Close() error              { return nil }
