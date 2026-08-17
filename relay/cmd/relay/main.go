package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	relay "github.com/nomad/relay"
)

func main() {
	var (
		dbPath           = flag.String("db", ":memory:", "SQLite database path (use :memory: for ephemeral)")
		addr             = flag.String("addr", "127.0.0.1:8089", "HTTP server address")
		cleanup          = flag.Duration("cleanup", 1*time.Minute, "Retention worker interval")
		enableTestBridge = flag.Bool("enable-test-bridge", false, "Enable TEST-ONLY bridge endpoints (requires --test-token)")
		testToken        = flag.String("test-token", "", "Bearer token for TEST-ONLY bridge (required when --enable-test-bridge is set)")
	)
	flag.Parse()

	db, err := relay.NewMailboxDB(*dbPath)
	if err != nil {
		log.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	srv := relay.NewServer(db, *addr)
	worker := relay.NewWorker(db, *cleanup)

	if *enableTestBridge {
		if *testToken == "" {
			log.Fatal("--test-token is required when --enable-test-bridge is set")
		}
		store, err := relay.NewTestBridgeStore(db.DB())
		if err != nil {
			log.Fatalf("failed to open test bridge store: %v", err)
		}
		if err := srv.SetTestBridge(store, *testToken); err != nil {
			log.Fatalf("failed to enable test bridge: %v", err)
		}
		log.Printf("TEST-ONLY bridge enabled on %s", *addr)
	}

	go worker.Run(context.Background())

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		log.Println("shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		worker.Stop()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("shutdown error: %v", err)
		}
	}()

	log.Printf("nomad validation relay starting on %s (TEST-ONLY)", *addr)
	if err := srv.Start(); err != nil {
		log.Fatalf("server error: %v", err)
	}

	fmt.Print("\n")
}
