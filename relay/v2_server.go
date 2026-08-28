package relay

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const v2MaxAckBody = 4096

// V2ServerConfig fixes one authenticated role to one listener. Role is never
// accepted from a request. Cleartext is accepted only by an explicit loopback
// test listener or from an explicitly trusted loopback TLS terminator.
type V2ServerConfig struct {
	Addr                     string
	Role                     V2Role
	AllowLoopbackHTTPTest    bool
	TrustedTLSTerminatorPeer string
}

type V2Server struct {
	db      *V2MailboxDB
	config  V2ServerConfig
	httpSrv *http.Server
}

func NewV2Server(db *V2MailboxDB, config V2ServerConfig) (*V2Server, error) {
	if db == nil {
		return nil, errors.New("relay v2: nil mailbox store")
	}
	if config.Role != V2RoleHost && config.Role != V2RoleDevice {
		return nil, errors.New("relay v2: listener role must be host or device")
	}
	if config.Addr == "" {
		return nil, errors.New("relay v2: empty listen address")
	}
	if config.AllowLoopbackHTTPTest && !IsLoopbackAddr(config.Addr) {
		return nil, errors.New("relay v2: cleartext exceptions require loopback")
	}
	if config.TrustedTLSTerminatorPeer != "" {
		peer := net.ParseIP(config.TrustedTLSTerminatorPeer)
		if peer == nil || !peer.IsLoopback() || !IsLoopbackAddr(config.Addr) {
			return nil, errors.New("relay v2: trusted TLS terminator must be an explicit loopback IP on a loopback listener")
		}
	}
	server := &V2Server{db: db, config: config}
	server.httpSrv = &http.Server{
		Addr:              config.Addr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return server, nil
}

func (s *V2Server) Handler() http.Handler { return http.HandlerFunc(s.ServeHTTP) }

func (s *V2Server) Start() error {
	ln, err := net.Listen("tcp", s.config.Addr)
	if err != nil {
		return fmt.Errorf("relay v2: listen: %w", err)
	}
	if err := s.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *V2Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

// Close immediately stops the data-plane listener after a shutdown timeout.
func (s *V2Server) Close() error { return s.httpSrv.Close() }

func (s *V2Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.transportAllowed(r) {
		v2HTTPError(w, http.StatusUpgradeRequired, "secure transport required")
		return
	}
	if hasForwardingHeaders(r.Header) || !allowedV2Headers(r.Header) || len(r.TransferEncoding) != 0 || r.Header.Get("Transfer-Encoding") != "" {
		v2HTTPError(w, http.StatusBadRequest, "invalid transport headers")
		return
	}
	mailboxID, endpoint, ok := parseV2Path(r)
	if !ok {
		v2HTTPError(w, http.StatusNotFound, "not found")
		return
	}
	if !methodAllowed(endpoint, r.Method) {
		w.Header().Set("Allow", allowedMethods(endpoint))
		v2HTTPError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	digest, err := bearerDigest(r.Header)
	if err != nil {
		v2HTTPError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	switch {
	case endpoint == "frames" && r.Method == http.MethodPost:
		s.handlePublish(w, r, mailboxID, digest)
	case endpoint == "frames" && r.Method == http.MethodGet:
		s.handleRead(w, r, mailboxID, digest)
	case endpoint == "acks":
		s.handleAckV2(w, r, mailboxID, digest)
	case endpoint == "mailbox":
		s.handleRevokeV2(w, r, mailboxID, digest)
	default:
		v2HTTPError(w, http.StatusNotFound, "not found")
	}
}

func (s *V2Server) transportAllowed(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	peer := remoteIP(r.RemoteAddr)
	if peer == nil || !peer.IsLoopback() {
		return false
	}
	if s.config.AllowLoopbackHTTPTest {
		return true
	}
	trusted := net.ParseIP(s.config.TrustedTLSTerminatorPeer)
	return trusted != nil && trusted.Equal(peer)
}

func remoteIsLoopback(remote string) bool {
	ip := remoteIP(remote)
	return ip != nil && ip.IsLoopback()
}

func remoteIP(remote string) net.IP {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func hasForwardingHeaders(h http.Header) bool {
	for name := range h {
		lower := strings.ToLower(name)
		if lower == "forwarded" || strings.HasPrefix(lower, "x-forwarded-") {
			return true
		}
	}
	return false
}

func allowedV2Headers(h http.Header) bool {
	allowed := map[string]bool{"Authorization": true, "Content-Type": true, "Content-Length": true, "Accept": true, "Accept-Encoding": true, "User-Agent": true}
	for name := range h {
		if !allowed[http.CanonicalHeaderKey(name)] {
			return false
		}
	}
	return true
}

func parseV2Path(r *http.Request) (string, string, bool) {
	if r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path || strings.Contains(r.URL.Path, "//") {
		return "", "", false
	}
	const prefix = "/v2/mailboxes/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), "/")
	if len(parts) == 1 && validatePrefixedHex(parts[0], "mbx-", 64) {
		return parts[0], "mailbox", true
	}
	if len(parts) == 2 && validatePrefixedHex(parts[0], "mbx-", 64) && (parts[1] == "frames" || parts[1] == "acks") {
		return parts[0], parts[1], true
	}
	return "", "", false
}

func methodAllowed(endpoint, method string) bool {
	return endpoint == "frames" && (method == http.MethodGet || method == http.MethodPost) || endpoint == "acks" && method == http.MethodPost || endpoint == "mailbox" && method == http.MethodDelete
}
func allowedMethods(endpoint string) string {
	if endpoint == "frames" {
		return "GET, POST"
	}
	if endpoint == "acks" {
		return "POST"
	}
	if endpoint == "mailbox" {
		return "DELETE"
	}
	return ""
}

func bearerDigest(h http.Header) (V2Digest, error) {
	values := h.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return V2Digest{}, ErrV2Unauthorized
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if token == "" || len(token) > 4096 || strings.IndexFunc(token, func(r rune) bool { return r <= ' ' || r == 0x7f }) >= 0 {
		return V2Digest{}, ErrV2Unauthorized
	}
	return V2Digest(sha256.Sum256([]byte(token))), nil
}

func requireNoQuery(r *http.Request) error {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		return ErrV2Malformed
	}
	return nil
}

func requireJSONBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, error) {
	if len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/json" || r.ContentLength <= 0 || r.ContentLength > max {
		return nil, ErrV2Malformed
	}
	limited := http.MaxBytesReader(w, r.Body, max)
	raw, err := io.ReadAll(limited)
	if err != nil || int64(len(raw)) != r.ContentLength {
		return nil, ErrV2Malformed
	}
	return raw, nil
}

func requireEmptyBody(r *http.Request) error {
	if r.ContentLength != 0 || r.Header.Get("Content-Type") != "" {
		return ErrV2Malformed
	}
	return nil
}

func (s *V2Server) handlePublish(w http.ResponseWriter, r *http.Request, mailboxID string, digest V2Digest) {
	if requireNoQuery(r) != nil {
		v2HTTPError(w, 400, "invalid query")
		return
	}
	raw, err := requireJSONBody(w, r, V2MaxWireFrame)
	if err != nil {
		v2HTTPError(w, 400, "invalid body")
		return
	}
	frame, _, err := ParseOpaqueFrameV2(raw)
	if err != nil || frame.MailboxID != mailboxID {
		v2HTTPError(w, 400, "invalid frame")
		return
	}
	fresh, err := s.db.PublishFrame(r.Context(), s.config.Role, digest, frame, time.Now())
	if err != nil {
		v2StoreError(w, err)
		return
	}
	status := http.StatusOK
	if fresh {
		status = http.StatusCreated
	}
	v2JSON(w, status, map[string]bool{"stored": fresh, "idempotent": !fresh})
}

func (s *V2Server) handleRead(w http.ResponseWriter, r *http.Request, mailboxID string, digest V2Digest) {
	if requireEmptyBody(r) != nil {
		v2HTTPError(w, 400, "body not allowed")
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 2 || len(query["direction"]) != 1 || len(query["after_sequence"]) != 1 {
		v2HTTPError(w, 400, "invalid query")
		return
	}
	direction := V2Direction(query.Get("direction"))
	after, parseErr := strconv.ParseUint(query.Get("after_sequence"), 10, 64)
	if !validV2Direction(direction) || parseErr != nil {
		v2HTTPError(w, 400, "invalid query")
		return
	}
	var epoch uint64
	auth, err := loadV2Auth(r.Context(), s.db.db, mailboxID)
	if err != nil {
		v2StoreError(w, err)
		return
	}
	if err := authorizeV2(auth, s.config.Role, digest); err != nil {
		v2StoreError(w, err)
		return
	}
	epoch = auth.epoch
	frames, err := s.db.ReadFrames(r.Context(), s.config.Role, digest, mailboxID, direction, epoch, after, V2MaxUnackedFrames, time.Now())
	if err != nil {
		v2StoreError(w, err)
		return
	}
	values := make([]OpaqueFrameV2, len(frames))
	for i := range frames {
		values[i] = frames[i].Frame
	}
	v2JSON(w, http.StatusOK, values)
}

func (s *V2Server) handleAckV2(w http.ResponseWriter, r *http.Request, mailboxID string, digest V2Digest) {
	if requireNoQuery(r) != nil {
		v2HTTPError(w, 400, "invalid query")
		return
	}
	raw, err := requireJSONBody(w, r, v2MaxAckBody)
	if err != nil {
		v2HTTPError(w, 400, "invalid body")
		return
	}
	ack, err := ParseOpaqueAckV2(raw)
	if err != nil || ack.MailboxID != mailboxID {
		v2HTTPError(w, 400, "invalid ack")
		return
	}
	if err := s.db.Ack(r.Context(), s.config.Role, digest, ack, time.Now()); err != nil {
		v2StoreError(w, err)
		return
	}
	v2JSON(w, http.StatusOK, map[string]bool{"acked": true})
}

func (s *V2Server) handleRevokeV2(w http.ResponseWriter, r *http.Request, mailboxID string, digest V2Digest) {
	if requireNoQuery(r) != nil || requireEmptyBody(r) != nil {
		v2HTTPError(w, 400, "invalid request")
		return
	}
	if err := s.db.Revoke(r.Context(), s.config.Role, digest, mailboxID, time.Now()); err != nil {
		v2StoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func v2JSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func v2HTTPError(w http.ResponseWriter, status int, message string) {
	v2JSON(w, status, map[string]string{"error": message})
}
func v2StoreError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, ErrV2Unauthorized):
		status = http.StatusUnauthorized
	case errors.Is(err, ErrV2Forbidden):
		status = http.StatusForbidden
	case errors.Is(err, ErrV2NotFound):
		status = http.StatusNotFound
	case errors.Is(err, ErrV2Revoked), errors.Is(err, ErrV2Expired):
		status = http.StatusGone
	case errors.Is(err, ErrV2Malformed), errors.Is(err, ErrV2InvalidFrame), errors.Is(err, ErrV2InvalidMailbox):
		status = http.StatusBadRequest
	case errors.Is(err, ErrV2Conflict), errors.Is(err, ErrV2Replay), errors.Is(err, ErrV2AckRegression), errors.Is(err, ErrV2Capacity):
		status = http.StatusConflict
	case errors.Is(err, ErrV2RateLimited):
		status = http.StatusTooManyRequests
	}
	v2HTTPError(w, status, http.StatusText(status))
}
