package relay

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	V2ProvisionAdminPath           = "/v2/admin/mailboxes/provision"
	v2ProvisionMaxBody       int64 = 4096
	v2AdminBearerMaxBytes          = 4096
	v2AdminBearerReadTimeout       = 2 * time.Second
)

type V2ProvisionCredentialSource struct {
	Token string
	Label string
}

type V2ProvisionServerConfig struct {
	Addr                  string
	Credential            V2ProvisionCredentialSource
	AllowLoopbackHTTPOnly bool
}

type V2ProvisionServer struct {
	db      *V2MailboxDB
	config  V2ProvisionServerConfig
	digest  V2Digest
	httpSrv *http.Server
}

func NewV2ProvisionServer(db *V2MailboxDB, config V2ProvisionServerConfig) (*V2ProvisionServer, error) {
	if db == nil {
		return nil, errors.New("relay v2: nil provision mailbox store")
	}
	if config.Addr == "" {
		return nil, errors.New("relay v2: empty provision listen address")
	}
	if !config.AllowLoopbackHTTPOnly || !IsLoopbackAddr(config.Addr) {
		return nil, errors.New("relay v2: provision listener requires explicit loopback cleartext mode")
	}
	if config.Credential.Token == "" {
		return nil, errors.New("relay v2: missing provision admin credential")
	}
	if config.Credential.Label == "" {
		config.Credential.Label = "redacted"
	}
	server := &V2ProvisionServer{
		db:     db,
		config: config,
		digest: V2Digest(sha256.Sum256([]byte(config.Credential.Token))),
	}
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

func (s *V2ProvisionServer) Handler() http.Handler { return http.HandlerFunc(s.ServeHTTP) }

func (s *V2ProvisionServer) Start() error {
	ln, err := net.Listen("tcp", s.config.Addr)
	if err != nil {
		return fmt.Errorf("relay v2: provision listen: %w", err)
	}
	log.Printf("[relay][v2-admin] listening on %s credential=%s mode=loopback-http-only production_external=NO_GO", ln.Addr().String(), s.config.Credential.Label)
	if err := s.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *V2ProvisionServer) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

// Close immediately stops the admin listener after a shutdown timeout.
func (s *V2ProvisionServer) Close() error { return s.httpSrv.Close() }

func (s *V2ProvisionServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS != nil || !remoteIsLoopback(r.RemoteAddr) {
		v2HTTPError(w, http.StatusUpgradeRequired, "loopback admin transport required")
		return
	}
	if hasForwardingHeaders(r.Header) || !allowedV2ProvisionHeaders(r.Header) || len(r.TransferEncoding) != 0 || r.Header.Get("Transfer-Encoding") != "" {
		v2HTTPError(w, http.StatusBadRequest, "invalid transport headers")
		return
	}
	if r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path || r.URL.Path != V2ProvisionAdminPath || r.URL.RawQuery != "" || r.URL.ForceQuery {
		v2HTTPError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		v2HTTPError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	digest, err := bearerDigest(r.Header)
	if err != nil || !subtleCompareDigest(digest, s.digest) {
		v2HTTPError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	raw, err := requireJSONBody(w, r, v2ProvisionMaxBody)
	if err != nil {
		v2HTTPError(w, http.StatusBadRequest, "invalid body")
		return
	}
	request, err := ParseV2ProvisionRequest(raw)
	if err != nil {
		v2StoreError(w, err)
		return
	}
	mailbox, err := request.ProvisionedMailbox()
	if err != nil {
		v2StoreError(w, err)
		return
	}
	created, err := s.db.ProvisionMailbox(r.Context(), mailbox)
	if err != nil {
		v2StoreError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	v2JSON(w, status, map[string]any{
		"schema":     "nomad.relay.mailbox-provision-result.v1",
		"mailbox_id": mailbox.MailboxID,
		"epoch":      mailbox.Epoch,
		"created":    created,
		"idempotent": !created,
	})
}

func allowedV2ProvisionHeaders(h http.Header) bool {
	allowed := map[string]bool{
		"Authorization":   true,
		"Content-Type":    true,
		"Content-Length":  true,
		"Accept":          true,
		"Accept-Encoding": true,
		"User-Agent":      true,
	}
	for name := range h {
		if !allowed[http.CanonicalHeaderKey(name)] {
			return false
		}
	}
	return true
}

func LoadV2AdminCredentialFromPrivateFile(path string) (V2ProvisionCredentialSource, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return V2ProvisionCredentialSource{}, fmt.Errorf("admin credential path must be absolute and canonical")
	}
	fd, err := openPrivateTokenPath(path)
	if err != nil {
		return V2ProvisionCredentialSource{}, err
	}
	file := os.NewFile(uintptr(fd), "v2-admin-credential-file")
	if file == nil {
		_ = unix.Close(fd)
		return V2ProvisionCredentialSource{}, fmt.Errorf("could not adopt admin credential file")
	}
	defer file.Close()
	token, err := readPrivateTokenFile(file)
	if err != nil {
		return V2ProvisionCredentialSource{}, err
	}
	return V2ProvisionCredentialSource{Token: token, Label: "file:" + path + " [redacted]"}, nil
}

func LoadV2AdminCredentialFromFD(fd int) (V2ProvisionCredentialSource, error) {
	if fd < 0 {
		return V2ProvisionCredentialSource{}, fmt.Errorf("invalid admin credential fd")
	}
	dup, err := dupBearerStreamFD(fd)
	if err != nil {
		return V2ProvisionCredentialSource{}, err
	}
	_ = unix.Close(fd)
	defer unix.Close(dup)
	token, err := readBearerFromFD(dup)
	if err != nil {
		return V2ProvisionCredentialSource{}, err
	}
	return V2ProvisionCredentialSource{Token: token, Label: "fd:" + strconv.Itoa(fd) + " [redacted]"}, nil
}

func readPrivateTokenFile(file *os.File) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return "", fmt.Errorf("invalid private token file size")
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || strings.IndexFunc(token, func(r rune) bool { return r <= ' ' || r == 0x7f }) >= 0 {
		return "", fmt.Errorf("invalid admin credential token")
	}
	return token, nil
}

func readBearerFromFD(fd int) (string, error) {
	deadline := time.Now().Add(v2AdminBearerReadTimeout)
	raw := make([]byte, 0, 256)
	buffer := make([]byte, 256)
	defer zeroize(raw)
	defer zeroize(buffer)
	pollFDs := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLHUP}}

	for {
		timeout := time.Until(deadline)
		if timeout <= 0 {
			return "", fmt.Errorf("invalid admin credential fd")
		}
		timeoutMS := int(timeout / time.Millisecond)
		if timeoutMS < 1 {
			timeoutMS = 1
		}
		n, err := unix.Poll(pollFDs, timeoutMS)
		if err == unix.EINTR {
			continue
		}
		if err != nil || n == 0 || pollFDs[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return "", fmt.Errorf("invalid admin credential fd")
		}
		count, err := unix.Read(fd, buffer)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("invalid admin credential fd")
		}
		if count == 0 {
			if len(raw) == 0 {
				return "", fmt.Errorf("invalid admin credential fd")
			}
			for _, b := range raw {
				if b < 0x21 || b > 0x7e {
					return "", fmt.Errorf("invalid admin credential fd")
				}
			}
			return string(raw), nil
		}
		raw = append(raw, buffer[:count]...)
		if len(raw) > v2AdminBearerMaxBytes {
			return "", fmt.Errorf("invalid admin credential fd")
		}
	}
}

func zeroize(raw []byte) {
	for index := range raw {
		raw[index] = 0
	}
}

func dupBearerStreamFD(fd int) (int, error) {
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(dup, &stat); err != nil {
		_ = unix.Close(dup)
		return -1, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFIFO && stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		_ = unix.Close(dup)
		return -1, fmt.Errorf("admin credential fd must be a fifo or socket")
	}
	flags, err := unix.FcntlInt(uintptr(dup), unix.F_GETFL, 0)
	if err != nil {
		_ = unix.Close(dup)
		return -1, err
	}
	if flags&unix.O_ACCMODE == unix.O_WRONLY {
		_ = unix.Close(dup)
		return -1, fmt.Errorf("admin credential fd must be readable")
	}
	return dup, nil
}

func openPrivateTokenPath(path string) (int, error) {
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	if len(parts) < 2 {
		return -1, fmt.Errorf("invalid admin credential path")
	}
	current, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." || part == ".." {
			_ = unix.Close(current)
			return -1, fmt.Errorf("invalid admin credential path")
		}
		next, openErr := unix.Openat(current, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(current)
		if openErr != nil {
			return -1, openErr
		}
		current = next
	}
	defer unix.Close(current)
	var parentStat unix.Stat_t
	if err := unix.Fstat(current, &parentStat); err != nil || parentStat.Uid != uint32(os.Geteuid()) || parentStat.Mode&unix.S_IFMT != unix.S_IFDIR || parentStat.Mode&0777 != 0700 {
		return -1, fmt.Errorf("admin credential parent must be a private owned directory")
	}
	fd, err := unix.Openat(current, parts[len(parts)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	var fileStat unix.Stat_t
	if err := unix.Fstat(fd, &fileStat); err != nil || fileStat.Uid != uint32(os.Geteuid()) || fileStat.Mode&unix.S_IFMT != unix.S_IFREG || fileStat.Mode&0777 != 0600 || fileStat.Nlink != 1 {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("admin credential must be a private regular file")
	}
	return fd, nil
}
