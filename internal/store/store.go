// Package store is mon-server's persistence layer: the GORM models of spec
// mon-server.md §3, their migration, and the typed accessors every other
// package uses instead of touching rows directly.
//
// One SQLite file holds everything (spec §3). It is opened with
// foreign_keys=ON, a five second busy timeout and a single connection, so that
// the poll loop, the HTTP handlers and the background jobs serialise their
// writes instead of fighting over the file.
//
// All times are int64 milliseconds since the Unix epoch, UTC; the store takes
// a clock.Clock so tests can drive them.
package store

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// BusyTimeout is how long SQLite waits for a lock before returning SQLITE_BUSY
// (spec §3).
const BusyTimeout = 5 * time.Second

// AdminRowID is the primary key of the single administrator row.
const AdminRowID int64 = 1

// Store owns the database handle and the clock every write stamps its times
// with. It is safe for concurrent use: SQLite is limited to one connection.
type Store struct {
	db  *gorm.DB
	log *slog.Logger
	clk clock.Clock
}

// Option customises Open.
type Option func(*Store)

// WithClock replaces the system clock, so tests can drive updated_at style
// columns with clock.Fake.
func WithClock(c clock.Clock) Option {
	return func(s *Store) {
		if c != nil {
			s.clk = c
		}
	}
}

// Open opens (creating it if needed) the SQLite database at path and migrates
// every model. It is idempotent: opening an already migrated file changes
// nothing.
func Open(path string, log *slog.Logger, opts ...Option) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("store: database path is empty")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Store{log: log, clk: clock.System{}}
	for _, opt := range opts {
		opt(s)
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("store: create data directory %s: %w", dir, err)
		}
	}
	_, statErr := os.Stat(path)
	fresh := os.IsNotExist(statErr)

	db, err := gorm.Open(sqlite.Open(dsn(path)), &gorm.Config{
		Logger:  gormlogger.New(gormWriter{log: log}, gormlogger.Config{SlowThreshold: time.Second, LogLevel: gormlogger.Warn, IgnoreRecordNotFoundError: true}),
		NowFunc: func() time.Time { return s.clk.Now() },
	})
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("store: database handle: %w", err)
	}
	// A single writer: SQLite takes one file lock anyway, and serialising in
	// the pool turns lock contention into a queue.
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0)

	s.db = db
	if err := s.migrate(); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	if fresh {
		// The file holds bcrypt hashes and client token hashes; keep it to
		// the service user.
		if err := os.Chmod(path, 0o600); err != nil {
			log.Warn("could not tighten database permissions", "path", path, "error", err)
		}
	}
	log.Debug("store opened", "path", path)
	return s, nil
}

// dsn builds the mattn/go-sqlite3 connection string with the pragmas of spec
// §3.
func dsn(path string) string {
	return fmt.Sprintf("file:%s?_foreign_keys=on&_busy_timeout=%d", path, BusyTimeout.Milliseconds())
}

// migrate brings the schema up to date. AutoMigrate adds missing tables,
// columns and indexes and leaves existing ones alone.
func (s *Store) migrate() error {
	if err := s.db.AutoMigrate(Models()...); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

// DB exposes the GORM handle for packages that build their own queries.
func (s *Store) DB() *gorm.DB { return s.db }

// Clock is the time source the store stamps rows with; components sharing the
// store share its clock.
func (s *Store) Clock() clock.Clock { return s.clk }

// NowMS is the current time in ms UTC, the storage form of every time column.
func (s *Store) NowMS() int64 { return clock.MS(s.clk.Now()) }

// Log is the store's logger, for packages that build on it.
func (s *Store) Log() *slog.Logger { return s.log }

// Close releases the database handle.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	sqlDB, err := s.db.DB()
	if err != nil {
		return fmt.Errorf("store: database handle: %w", err)
	}
	if err := sqlDB.Close(); err != nil {
		return fmt.Errorf("store: close: %w", err)
	}
	return nil
}

// gormWriter routes GORM's own diagnostics (slow queries, statement errors)
// into the injected logger instead of the standard output.
type gormWriter struct{ log *slog.Logger }

// Printf implements gormlogger.Writer.
func (w gormWriter) Printf(format string, args ...any) {
	w.log.Warn("gorm", "message", strings.TrimSpace(fmt.Sprintf(format, args...)))
}
