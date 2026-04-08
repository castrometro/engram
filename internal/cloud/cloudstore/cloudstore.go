// Package cloudstore implements the server-side persistent store for the
// Engram cloud sync hub.
//
// It uses the same SQLite driver as the local store so the cloud server can
// be deployed as a single binary with no external database dependency.
// The schema is intentionally kept separate from the local store schema:
//
//	cloud_mutations  – append-only log of every mutation pushed by any client
//	client_cursors   – per-client/project pull cursor (last seq seen)
//	api_keys         – bcrypt-hashed API keys scoped to a project
//
// API key security model:
//
//	Raw key format : "ek_" + 64 random hex chars (67 chars total, 256 bits entropy)
//	Lookup prefix  : first 19 chars ("ek_" + 16 hex) — stored as UNIQUE in DB
//	Stored hash    : bcrypt(full_raw_key) — validated with bcrypt.CompareHashAndPassword
//
// This follows the industry-standard split-key pattern: the prefix is used for
// a fast indexed lookup, and bcrypt protects the secret suffix from offline
// attacks even if the database is compromised.
package cloudstore

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	_ "modernc.org/sqlite"
)

// openDB is injectable for testing.
var openDB = sql.Open

// defaultBcryptCost is the work factor for bcrypt API key hashing.
// Cost 10 yields ~100 ms per operation on typical hardware, which is
// acceptable for a team sync server handling one request per client per
// 30-second poll interval.
const defaultBcryptCost = 10

// ─── Types ────────────────────────────────────────────────────────────────────

// ClientMutation is a single mutation entry sent by a client during a push.
type ClientMutation struct {
	Entity     string `json:"entity"`      // session / observation / prompt
	EntityKey  string `json:"entity_key"`  // sync_id (stable across machines)
	Op         string `json:"op"`          // upsert / delete
	Payload    string `json:"payload"`     // JSON-encoded full-state snapshot
	Project    string `json:"project"`     // project name (normalized)
	OccurredAt string `json:"occurred_at"` // RFC3339 timestamp from source
}

// CloudMutation is a mutation stored in the cloud, enriched with server metadata.
type CloudMutation struct {
	Seq          int64  `json:"seq"`
	SourceClient string `json:"source_client"`
	Entity       string `json:"entity"`
	EntityKey    string `json:"entity_key"`
	Op           string `json:"op"`
	Payload      string `json:"payload"`
	Project      string `json:"project"`
	OccurredAt   string `json:"occurred_at"`
	CreatedAt    string `json:"created_at"`
}

// APIKeyInfo contains the decoded metadata for a validated API key.
type APIKeyInfo struct {
	ClientID   string
	Project    string
	ClientName string
}

// CloudStore is the server-side database handle.
type CloudStore struct {
	db         *sql.DB
	bcryptCost int // injectable for testing via SetBcryptCost
}

// ─── Open / Close ─────────────────────────────────────────────────────────────

// Open opens (and migrates) the cloud server SQLite database at dbPath.
// dbPath may also be ":memory:" for tests.
func Open(dbPath string) (*CloudStore, error) {
	db, err := openDB("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("cloudstore: open %s: %w", dbPath, err)
	}
	db.SetMaxOpenConns(1) // SQLite single-writer
	cs := &CloudStore{db: db, bcryptCost: defaultBcryptCost}
	if err := cs.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("cloudstore: migrate: %w", err)
	}
	return cs, nil
}

// SetBcryptCost overrides the bcrypt work factor. Use bcrypt.MinCost in tests.
func (cs *CloudStore) SetBcryptCost(cost int) {
	cs.bcryptCost = cost
}

// Close closes the underlying database connection.
func (cs *CloudStore) Close() error {
	return cs.db.Close()
}

// ─── Schema ───────────────────────────────────────────────────────────────────

func (cs *CloudStore) migrate() error {
	_, err := cs.db.Exec(`
		CREATE TABLE IF NOT EXISTS cloud_mutations (
			seq           INTEGER PRIMARY KEY AUTOINCREMENT,
			source_client TEXT    NOT NULL,
			entity        TEXT    NOT NULL,
			entity_key    TEXT    NOT NULL,
			op            TEXT    NOT NULL,
			payload       TEXT    NOT NULL,
			project       TEXT    NOT NULL DEFAULT '',
			occurred_at   TEXT    NOT NULL,
			created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
		);

		CREATE INDEX IF NOT EXISTS idx_cm_project_seq
			ON cloud_mutations(project, seq);

		CREATE TABLE IF NOT EXISTS client_cursors (
			client_id       TEXT NOT NULL,
			project         TEXT NOT NULL DEFAULT '',
			last_pulled_seq INTEGER NOT NULL DEFAULT 0,
			last_push_at    TEXT,
			PRIMARY KEY (client_id, project)
		);

		CREATE TABLE IF NOT EXISTS api_keys (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			key_prefix  TEXT NOT NULL UNIQUE,
			key_hash    TEXT NOT NULL,
			client_id   TEXT NOT NULL,
			project     TEXT NOT NULL DEFAULT '',
			client_name TEXT NOT NULL DEFAULT '',
			created_at  TEXT NOT NULL DEFAULT (datetime('now')),
			expires_at  TEXT
		);

		CREATE INDEX IF NOT EXISTS idx_api_keys_client
			ON api_keys(client_id);
	`)
	return err
}

// ─── API Key Management ───────────────────────────────────────────────────────

// rawAPIKeyLen is the number of random bytes to generate for each API key.
// Results in a 67-char string: "ek_" (3) + 64 hex chars from 32 random bytes (256 bits entropy).
const rawAPIKeyLen = 32

// keyPrefixLen is the number of leading characters used for DB lookup.
// "ek_" (3) + 16 hex chars = 19 chars. Used as a UNIQUE index.
const keyPrefixLen = 19

// newRawAPIKey generates a cryptographically random API key.
// Format: "ek_" + 64 lowercase hex chars (32 random bytes = 256 bits entropy).
func newRawAPIKey() (string, error) {
	b := make([]byte, rawAPIKeyLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "ek_" + hex.EncodeToString(b), nil
}

// CreateAPIKey generates a new API key for the given client and stores a
// bcrypt hash in the database. It returns the raw key (shown only once to
// the user). The first 19 characters serve as a stable lookup prefix;
// the full key is validated via bcrypt.CompareHashAndPassword.
func (cs *CloudStore) CreateAPIKey(clientID, project, clientName string) (string, error) {
	raw, err := newRawAPIKey()
	if err != nil {
		return "", fmt.Errorf("cloudstore: generate api key: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(raw), cs.bcryptCost)
	if err != nil {
		return "", fmt.Errorf("cloudstore: hash api key: %w", err)
	}

	prefix := raw[:keyPrefixLen]
	_, err = cs.db.Exec(
		`INSERT INTO api_keys (key_prefix, key_hash, client_id, project, client_name)
		 VALUES (?, ?, ?, ?, ?)`,
		prefix, string(hash), clientID, project, clientName,
	)
	if err != nil {
		return "", fmt.Errorf("cloudstore: store api key: %w", err)
	}
	return raw, nil
}

// ValidateAPIKey looks up the API key by its prefix, then verifies the full
// key with bcrypt. Returns the associated APIKeyInfo on success, or an error
// if the key is missing, expired, or invalid.
func (cs *CloudStore) ValidateAPIKey(raw string) (*APIKeyInfo, error) {
	if len(raw) < keyPrefixLen {
		return nil, fmt.Errorf("cloudstore: invalid api key format")
	}
	prefix := raw[:keyPrefixLen]

	var storedHash string
	var info APIKeyInfo
	var expiresAt sql.NullString
	err := cs.db.QueryRow(
		`SELECT key_hash, client_id, project, client_name, expires_at
		 FROM api_keys WHERE key_prefix = ?`,
		prefix,
	).Scan(&storedHash, &info.ClientID, &info.Project, &info.ClientName, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("cloudstore: invalid api key")
	}
	if err != nil {
		return nil, fmt.Errorf("cloudstore: validate api key: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(raw)); err != nil {
		return nil, fmt.Errorf("cloudstore: invalid api key")
	}

	if expiresAt.Valid {
		exp, err := time.Parse(time.RFC3339, expiresAt.String)
		if err != nil {
			return nil, fmt.Errorf("cloudstore: malformed expiry timestamp: %w", err)
		}
		if time.Now().After(exp) {
			return nil, fmt.Errorf("cloudstore: api key expired")
		}
	}
	return &info, nil
}

// ─── Push ─────────────────────────────────────────────────────────────────────

// InsertMutations appends a batch of mutations from a client to cloud_mutations.
// It returns the globally assigned sequence numbers in the same order as the
// input slice.
func (cs *CloudStore) InsertMutations(sourceClient string, mutations []ClientMutation) ([]int64, error) {
	if len(mutations) == 0 {
		return nil, nil
	}

	tx, err := cs.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("cloudstore: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.Prepare(
		`INSERT INTO cloud_mutations
		   (source_client, entity, entity_key, op, payload, project, occurred_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		return nil, fmt.Errorf("cloudstore: prepare insert: %w", err)
	}
	defer stmt.Close()

	seqs := make([]int64, len(mutations))
	for i, m := range mutations {
		res, err := stmt.Exec(sourceClient, m.Entity, m.EntityKey, m.Op, m.Payload, m.Project, m.OccurredAt)
		if err != nil {
			return nil, fmt.Errorf("cloudstore: insert mutation: %w", err)
		}
		seqs[i], err = res.LastInsertId()
		if err != nil {
			return nil, fmt.Errorf("cloudstore: last insert id: %w", err)
		}
	}

	// Track the last push timestamp for this client.
	if _, err := tx.Exec(
		`INSERT INTO client_cursors (client_id, project, last_push_at)
		 VALUES (?, ?, datetime('now'))
		 ON CONFLICT(client_id, project) DO UPDATE SET last_push_at = excluded.last_push_at`,
		sourceClient, mutations[0].Project,
	); err != nil {
		return nil, fmt.Errorf("cloudstore: update client cursor push: %w", err)
	}

	return seqs, tx.Commit()
}

// ─── Pull ─────────────────────────────────────────────────────────────────────

// PullMutations returns at most limit mutations for the given project with
// seq > sinceSeq, excluding mutations originating from excludeClient.
// Results are ordered by seq ascending.
func (cs *CloudStore) PullMutations(excludeClient, project string, sinceSeq int64, limit int) ([]CloudMutation, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := cs.db.Query(
		`SELECT seq, source_client, entity, entity_key, op, payload, project, occurred_at, created_at
		 FROM cloud_mutations
		 WHERE project = ?
		   AND seq > ?
		   AND source_client != ?
		 ORDER BY seq ASC
		 LIMIT ?`,
		project, sinceSeq, excludeClient, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("cloudstore: pull mutations: %w", err)
	}
	defer rows.Close()

	var result []CloudMutation
	for rows.Next() {
		var m CloudMutation
		if err := rows.Scan(&m.Seq, &m.SourceClient, &m.Entity, &m.EntityKey, &m.Op, &m.Payload, &m.Project, &m.OccurredAt, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("cloudstore: scan mutation: %w", err)
		}
		result = append(result, m)
	}
	return result, rows.Err()
}

// UpdateClientCursor records the latest seq the client has pulled.
func (cs *CloudStore) UpdateClientCursor(clientID, project string, lastPulledSeq int64) error {
	_, err := cs.db.Exec(
		`INSERT INTO client_cursors (client_id, project, last_pulled_seq)
		 VALUES (?, ?, ?)
		 ON CONFLICT(client_id, project)
		 DO UPDATE SET last_pulled_seq = max(excluded.last_pulled_seq, client_cursors.last_pulled_seq)`,
		clientID, project, lastPulledSeq,
	)
	return err
}

// ─── Status ───────────────────────────────────────────────────────────────────

// ProjectStatus holds aggregated stats for a project's cloud sync state.
type ProjectStatus struct {
	Project      string `json:"project"`
	TotalPushed  int64  `json:"total_pushed"`
	ActiveClient int64  `json:"active_clients"`
	MaxSeq       int64  `json:"max_seq"`
}

// GetProjectStatus returns sync statistics for a project.
func (cs *CloudStore) GetProjectStatus(project string) (*ProjectStatus, error) {
	var s ProjectStatus
	s.Project = project
	err := cs.db.QueryRow(
		`SELECT COUNT(*), COUNT(DISTINCT source_client), COALESCE(MAX(seq), 0)
		 FROM cloud_mutations WHERE project = ?`,
		project,
	).Scan(&s.TotalPushed, &s.ActiveClient, &s.MaxSeq)
	if err != nil {
		return nil, fmt.Errorf("cloudstore: project status: %w", err)
	}
	return &s, nil
}

// NewClientID generates and returns a new unique client identifier.
func NewClientID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "client-" + hex.EncodeToString(b), nil
}


