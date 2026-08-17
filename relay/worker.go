package relay

import (
	"context"
	"log"
	"time"
)

// Worker handles periodic retention and capacity cleanup.
type Worker struct {
	db       *mailboxDB
	interval time.Duration
	stop     chan struct{}
}

// NewWorker creates a new retention worker.
func NewWorker(db *mailboxDB, interval time.Duration) *Worker {
	return &Worker{
		db:       db,
		interval: interval,
		stop:     make(chan struct{}),
	}
}

// Run starts the cleanup loop. Blocks until Stop is called or context is cancelled.
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			w.cleanup()
		case <-ctx.Done():
			return
		case <-w.stop:
			return
		}
	}
}

// Stop signals the worker to shut down.
func (w *Worker) Stop() {
	select {
	case w.stop <- struct{}{}:
	default:
	}
}

func (w *Worker) cleanup() {
	removed, err := w.db.CleanupTTL()
	if err != nil {
		log.Printf("[relay][worker] TTL cleanup error: %v", err)
	} else if removed > 0 {
		log.Printf("[relay][worker] removed %d expired frames", removed)
	}

	acked, err := w.db.CleanupAcked()
	if err != nil {
		log.Printf("[relay][worker] ACK cleanup error: %v", err)
	} else if acked > 0 {
		log.Printf("[relay][worker] removed %d old acked frames", acked)
	}
}
