package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	relay "github.com/nomad/relay"
)

const relayShutdownTimeout = 10 * time.Second

type managedServer interface {
	Start() error
	Shutdown(context.Context) error
	Close() error
}

type namedServer struct {
	name   string
	server managedServer
}

type startResult struct {
	name string
	err  error
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		log.Printf("relay failed: %v", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("relay", flag.ContinueOnError)
	var (
		dbPath           = flags.String("db", ":memory:", "SQLite database path (use :memory: for ephemeral)")
		addr             = flags.String("addr", "127.0.0.1:8089", "HTTP server address")
		cleanup          = flags.Duration("cleanup", time.Minute, "Retention worker interval for v1 and enabled v2 storage")
		alphaLocal       = flags.Bool("alpha-local", false, "Enable loopback-only local Alpha mode with the fixed pre-registered local device fixture")
		alphaTokenEnv    = flags.String("alpha-token-env", "NOMAD_ALPHA_RELAY_TOKEN", "Environment variable name for the local Alpha read token")
		enableTestBridge = flags.Bool("enable-test-bridge", false, "Enable TEST-ONLY bridge endpoints (requires --test-token)")
		testToken        = flags.String("test-token", "", "Bearer token for TEST-ONLY bridge (required when --enable-test-bridge is set)")
		v2Enabled        = flags.Bool("v2-enable", false, "Enable the separately namespaced Relay v2 listener")
		v2Addr           = flags.String("v2-addr", "", "Dedicated Relay v2 listen address")
		v2Role           = flags.String("v2-role", "", "Fixed role for the v2 listener: host or device")
		v2DBPath         = flags.String("v2-db", "", "File-backed SQLite path for Relay v2")
		v2LoopbackHTTP   = flags.Bool("v2-loopback-test-http", false, "Allow cleartext v2 HTTP from loopback in explicit test mode")
		v2TLSTerminator  = flags.String("v2-trusted-tls-terminator-peer", "", "Exact loopback peer IP of the trusted TLS terminator")
		v2AdminAddr      = flags.String("v2-admin-addr", "", "Dedicated Relay v2 admin provision listen address")
		v2AdminCredFile  = flags.String("v2-admin-credential-file", "", "Private 0600 file containing the admin bearer token for the v2 provision listener")
		v2AdminCredFD    = flags.Int("v2-admin-credential-fd", -1, "Inherited private fd containing the admin bearer token for the v2 provision listener")
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *cleanup <= 0 {
		return fmt.Errorf("cleanup interval must be positive")
	}

	db, err := relay.NewMailboxDB(*dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	srv := relay.NewServer(db, *addr)
	servers := []namedServer{{name: "v1 data", server: srv}}
	worker := relay.NewWorker(db, *cleanup)
	workers := []func(context.Context){worker.Run}

	var v2db *relay.V2MailboxDB
	if *v2Enabled {
		if *v2Addr == "" || *v2DBPath == "" || *v2DBPath == ":memory:" || *v2Role == "" {
			return errors.New("v2 requires --v2-addr, --v2-role, and file-backed --v2-db")
		}
		v2db, err = relay.NewV2MailboxDB(*v2DBPath)
		if err != nil {
			return fmt.Errorf("open v2 db: %w", err)
		}
		defer v2db.Close()

		v2srv, err := relay.NewV2Server(v2db, relay.V2ServerConfig{
			Addr:                     *v2Addr,
			Role:                     relay.V2Role(*v2Role),
			AllowLoopbackHTTPTest:    *v2LoopbackHTTP,
			TrustedTLSTerminatorPeer: *v2TLSTerminator,
		})
		if err != nil {
			return fmt.Errorf("invalid v2 configuration: %w", err)
		}
		servers = append(servers, namedServer{name: "v2 data", server: v2srv})

		v2Cleanup, err := relay.NewV2CleanupWorker(v2db, *cleanup)
		if err != nil {
			return fmt.Errorf("configure v2 cleanup: %w", err)
		}
		workers = append(workers, v2Cleanup.Run)

		if *v2AdminCredFile != "" && *v2AdminCredFD >= 0 {
			return errors.New("choose exactly one of --v2-admin-credential-file or --v2-admin-credential-fd")
		}
		if *v2AdminAddr != "" {
			var credential relay.V2ProvisionCredentialSource
			switch {
			case *v2AdminCredFile != "":
				credential, err = relay.LoadV2AdminCredentialFromPrivateFile(*v2AdminCredFile)
			case *v2AdminCredFD >= 0:
				credential, err = relay.LoadV2AdminCredentialFromFD(*v2AdminCredFD)
			default:
				err = errors.New("v2 admin listener requires --v2-admin-credential-file or --v2-admin-credential-fd")
			}
			if err != nil {
				return fmt.Errorf("invalid v2 admin credential: %w", err)
			}
			v2AdminSrv, err := relay.NewV2ProvisionServer(v2db, relay.V2ProvisionServerConfig{
				Addr:                  *v2AdminAddr,
				Credential:            credential,
				AllowLoopbackHTTPOnly: true,
			})
			if err != nil {
				return fmt.Errorf("invalid v2 admin configuration: %w", err)
			}
			servers = append(servers, namedServer{name: "v2 admin", server: v2AdminSrv})
		} else if *v2AdminCredFile != "" || *v2AdminCredFD >= 0 {
			return errors.New("v2 admin credential requires --v2-admin-addr")
		}
		log.Printf("[relay][v2] data and optional admin listeners remain isolated production_external=NO_GO")
	}

	if *alphaLocal {
		if *dbPath == ":memory:" {
			return errors.New("local Alpha mode requires file-backed SQLite, got :memory:")
		}
		if !relay.IsLoopbackAddr(*addr) {
			return fmt.Errorf("local Alpha mode requires loopback address, got %s", *addr)
		}
		if strings.TrimSpace(*alphaTokenEnv) == "" {
			return errors.New("local Alpha mode requires a non-empty --alpha-token-env")
		}
		token := os.Getenv(*alphaTokenEnv)
		if token == "" {
			return fmt.Errorf("local Alpha mode requires %s", *alphaTokenEnv)
		}
		deviceID, pubKey, err := relay.AlphaLocalFixture()
		if err != nil {
			return fmt.Errorf("load local Alpha fixture: %w", err)
		}
		if err := db.RegisterDevice(deviceID, pubKey); err != nil {
			return fmt.Errorf("pre-register local Alpha fixture: %w", err)
		}
		if err := srv.SetLocalAlpha(token); err != nil {
			return fmt.Errorf("enable local Alpha read boundary: %w", err)
		}
	}

	if *enableTestBridge {
		if *testToken == "" {
			return errors.New("--test-token is required when --enable-test-bridge is set")
		}
		store, err := relay.NewTestBridgeStore(db.DB())
		if err != nil {
			return fmt.Errorf("open test bridge store: %w", err)
		}
		if err := srv.SetTestBridge(store, *testToken); err != nil {
			return fmt.Errorf("enable test bridge: %w", err)
		}
		log.Printf("TEST-ONLY bridge enabled on %s", *addr)
	}

	if *alphaLocal {
		log.Printf("nomad validation relay starting on %s (LOCAL ALPHA / TEST-ONLY PROTOCOL)", *addr)
	} else {
		log.Printf("nomad validation relay starting on %s (TEST-ONLY)", *addr)
	}
	return runLifecycle(ctx, servers, workers, relayShutdownTimeout)
}

// runLifecycle owns every long-running goroutine. A signal or any listener
// failure follows the same cancel -> graceful shutdown -> forced close -> join
// path, so resource defers in run always execute.
func runLifecycle(parent context.Context, servers []namedServer, workers []func(context.Context), shutdownTimeout time.Duration) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	results := make(chan startResult, len(servers))
	var serverWG sync.WaitGroup
	for _, managed := range servers {
		managed := managed
		serverWG.Add(1)
		go func() {
			defer serverWG.Done()
			results <- startResult{name: managed.name, err: managed.server.Start()}
		}()
	}

	var workerWG sync.WaitGroup
	for _, runWorker := range workers {
		runWorker := runWorker
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			runWorker(ctx)
		}()
	}

	var first startResult
	select {
	case <-parent.Done():
		log.Printf("shutting down...")
	case first = <-results:
	}
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	shutdownErrs := make(chan error, 2*len(servers))
	var shutdownWG sync.WaitGroup
	for _, managed := range servers {
		managed := managed
		shutdownWG.Add(1)
		go func() {
			defer shutdownWG.Done()
			if err := managed.server.Shutdown(shutdownCtx); err != nil {
				shutdownErrs <- fmt.Errorf("%s shutdown: %w", managed.name, err)
				if closeErr := managed.server.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) && !errors.Is(closeErr, http.ErrServerClosed) {
					shutdownErrs <- fmt.Errorf("%s close: %w", managed.name, closeErr)
				}
			}
		}()
	}
	shutdownWG.Wait()
	shutdownCancel()
	workerWG.Wait()
	serverWG.Wait()
	close(results)
	close(shutdownErrs)

	var errs []error
	if first.name != "" {
		if first.err != nil {
			errs = append(errs, fmt.Errorf("%s server: %w", first.name, first.err))
		} else if parent.Err() == nil {
			errs = append(errs, fmt.Errorf("%s server stopped unexpectedly", first.name))
		}
	}
	for result := range results {
		if result.err != nil {
			errs = append(errs, fmt.Errorf("%s server: %w", result.name, result.err))
		}
	}
	for err := range shutdownErrs {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
