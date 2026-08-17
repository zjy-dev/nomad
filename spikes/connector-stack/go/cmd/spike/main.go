package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/gofiber/fiber/v2"
	_ "github.com/mattn/go-sqlite3"
)

// SseEvent mirrors the Rust payload shape exactly.
type SseEvent struct {
	Seq     uint64 `json:"seq"`
	Label   string `json:"label"`
	Payload string `json:"payload"`
	Ts      int64  `json:"ts"`
}

// KeychainStore adapter boundary. Production would bridge to the
// Security.framework / keychain via a thin cgo-free shim (see ADR discussion).
type KeychainStore interface {
	Get(key string) ([]byte, bool)
	Set(key string, value []byte) error
}

// NoopKeychain is the spike no-op.
type NoopKeychain struct{}

func (NoopKeychain) Get(string) ([]byte, bool) { return nil, false }
func (NoopKeychain) Set(string, []byte) error  { return nil }

type mode int

const (
	modeIdle mode = iota
	modeSQLite
	modeSSE
)

func parseMode() mode {
	if len(os.Args) < 2 {
		return modeIdle
	}
	switch os.Args[1] {
	case "sqlite":
		return modeSQLite
	case "sse":
		return modeSSE
	default:
		return modeIdle
	}
}

func nowMs() int64 {
	return time.Now().UnixMilli()
}

func runSQLiteBench(dbPath string, n int) error {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return err
	}
	// Remove prior DB so every run starts clean.
	_ = os.Remove(dbPath)
	_ = os.Remove(dbPath + "-wal")
	_ = os.Remove(dbPath + "-shm")

	// _journal_mode=WAL&_synchronous=NORMAL — matches Rust pragma.
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=5000", dbPath)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		seq INTEGER NOT NULL,
		payload TEXT NOT NULL,
		ts INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_events_seq ON events(seq);`); err != nil {
		return err
	}

	var txTimes []float64
	txTimes = make([]float64, 0, n)

	start := time.Now()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO events (seq, payload, ts) VALUES (?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	for i := 0; i < n; i++ {
		t0 := time.Now()
		if _, err := stmt.Exec(i, fmt.Sprintf("payload-%d", i), nowMs()); err != nil {
			stmt.Close()
			tx.Rollback()
			return err
		}
		txTimes = append(txTimes, float64(time.Since(t0).Microseconds())/1000.0)
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		return err
	}
	total := float64(time.Since(start).Microseconds()) / 1000.0

	sort.Float64s(txTimes)
	p50 := txTimes[len(txTimes)/2]
	// p95 formula: nearest-rank ceil, 0-indexed — same as Rust and Python driver.
	p95Idx := int(math.Ceil(float64(len(txTimes)) * 0.95)) - 1
	if p95Idx < 0 {
		p95Idx = 0
	}
	p95 := txTimes[p95Idx]
	maxv := txTimes[len(txTimes)-1]

	fmt.Printf("SQLITE_WAL result={\"n\":%d,\"total_ms\":%.3f,\"p50_ms\":%.6f,\"p95_ms\":%.6f,\"max_ms\":%.6f}\n",
		n, total, p50, p95, maxv)
	return nil
}

func runSSEServer() error {
	app := fiber.New(fiber.Config{
		// Keep the server lean — no error stack traces in output during bench.
		DisableStartupMessage: true,
	})

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	app.Post("/sse", func(c *fiber.Ctx) error {
		var ev SseEvent
		if err := json.Unmarshal(c.Body(), &ev); err != nil {
			return c.Status(http.StatusBadRequest).SendString(err.Error())
		}
		body, err := json.Marshal(ev)
		if err != nil {
			return c.Status(http.StatusBadRequest).SendString(err.Error())
		}
		c.Set("Content-Type", "text/event-stream")
		c.Set("Cache-Control", "no-cache")
		c.Set("Connection", "keep-alive")
		return c.Send([]byte(fmt.Sprintf("data: %s\n\n", body)))
	})

	addr := ":4097"
	log.Printf("SSE server listening on %s", addr)
	return app.Listen(addr)
}

func runIdle() {
	fmt.Println("READY")
	os.Stdout.Sync()
	// Sleep forever so the driver can sample RSS.
	for {
		time.Sleep(3600 * time.Second)
	}
}

// main drives the mode selector. The driver always prints READY first, so
// cold start timing is uniform.
func main() {
	mode := parseMode()
	// Flush READY for non-idle modes too.
	if mode != modeIdle {
		fmt.Println("READY")
		os.Stdout.Sync()
	}

	switch mode {
	case modeIdle:
		runIdle()
	case modeSQLite:
		dbPath := ":memory:"
		n := 5000
		if len(os.Args) >= 3 {
			dbPath = os.Args[2]
		}
		if len(os.Args) >= 4 {
			if _, err := fmt.Sscanf(os.Args[3], "%d", &n); err != nil {
				n = 5000
			}
		}
		if err := runSQLiteBench(dbPath, n); err != nil {
			log.Fatalf("sqlite bench failed: %v", err)
		}
	case modeSSE:
		if err := runSSEServer(); err != nil {
			log.Fatalf("sse server failed: %v", err)
		}
	}
}

// _ ensures KeychainStore interface is not flagged as unused.
var _ KeychainStore = NoopKeychain{}
