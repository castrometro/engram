package autosync

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/castrometro/engram/internal/store"
)

// ─── Test Helpers ─────────────────────────────────────────────────────────────

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	cfg := store.Config{
		DataDir:      dir,
		DedupeWindow: time.Hour,
	}
	s, err := store.New(cfg)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func newTestManager(t *testing.T, s *store.Store, serverURL string) *Manager {
	t.Helper()
	cfg := Config{
		ServerURL:    serverURL,
		APIKey:       "ek_test",
		ClientID:     "client-test",
		Project:      "testproject",
		PushInterval: 24 * time.Hour, // disable timer-based push in tests
		PullInterval: 24 * time.Hour, // disable timer-based pull in tests
	}
	return New(cfg, s)
}

// seedObservation inserts a minimal observation so the store generates a sync mutation.
func seedObservation(t *testing.T, s *store.Store) {
	t.Helper()
	if err := s.CreateSession("sess-1", "testproject", "/tmp"); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := s.AddObservation(store.AddObservationParams{
		SessionID: "sess-1",
		Type:      "decision",
		Title:     "Test decision",
		Content:   "Content of the test decision",
		Project:   "testproject",
	}); err != nil {
		t.Fatalf("AddObservation: %v", err)
	}

	// Enroll project so mutations appear in ListPendingSyncMutations.
	if err := s.EnrollProject("testproject"); err != nil {
		t.Fatalf("EnrollProject: %v", err)
	}
}

// ─── Status Tests ─────────────────────────────────────────────────────────────

func TestStatus_InitialPhase(t *testing.T) {
	s := newTestStore(t)
	m := newTestManager(t, s, "http://localhost")
	st := m.Status()
	if st.Phase != string(PhaseIdle) {
		t.Errorf("initial phase: got %q, want %q", st.Phase, PhaseIdle)
	}
	if st.ConsecutiveFailures != 0 {
		t.Errorf("initial failures: got %d, want 0", st.ConsecutiveFailures)
	}
}

// ─── NotifyDirty Tests ────────────────────────────────────────────────────────

func TestNotifyDirty_NonBlocking(t *testing.T) {
	s := newTestStore(t)
	m := newTestManager(t, s, "http://localhost")

	// Fill the dirty channel.
	m.NotifyDirty()
	// A second call must not block.
	done := make(chan struct{})
	go func() {
		m.NotifyDirty()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("NotifyDirty blocked unexpectedly")
	}
}

// ─── Push Tests ───────────────────────────────────────────────────────────────

func TestRunPush_NoPendingMutations(t *testing.T) {
	s := newTestStore(t)
	// No observations => no mutations.
	var called atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	m := newTestManager(t, s, ts.URL)
	m.runPush()

	if called.Load() {
		t.Error("expected no HTTP call when there are no pending mutations")
	}
}

func TestRunPush_SendsMutationsAndAcks(t *testing.T) {
	s := newTestStore(t)
	seedObservation(t, s)

	var pushCalled atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sync/push":
			pushCalled.Store(true)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"accepted": 2, "seqs": []int64{1}})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	m := newTestManager(t, s, ts.URL)
	m.runPush()

	if !pushCalled.Load() {
		t.Error("expected push to be called")
	}

	st := m.Status()
	if st.Phase != string(PhaseHealthy) {
		t.Errorf("phase after push: got %q, want %q", st.Phase, PhaseHealthy)
	}
	if st.ConsecutiveFailures != 0 {
		t.Errorf("failures after successful push: got %d, want 0", st.ConsecutiveFailures)
	}
}

func TestRunPush_ServerError_RecordsDegradation(t *testing.T) {
	s := newTestStore(t)
	seedObservation(t, s)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"internal error"}`)
	}))
	defer ts.Close()

	m := newTestManager(t, s, ts.URL)
	m.runPush()

	st := m.Status()
	if st.Phase != string(PhaseDegraded) {
		t.Errorf("phase after server error: got %q, want %q", st.Phase, PhaseDegraded)
	}
	if st.ConsecutiveFailures < 1 {
		t.Errorf("expected failures >= 1, got %d", st.ConsecutiveFailures)
	}
	if st.LastError == "" {
		t.Error("expected LastError to be non-empty after server error")
	}
}

func TestRunPush_NetworkError_RecordsDegradation(t *testing.T) {
	s := newTestStore(t)
	seedObservation(t, s)

	m := newTestManager(t, s, "http://127.0.0.1:1") // unreachable
	m.runPush()

	st := m.Status()
	if st.Phase != string(PhaseDegraded) {
		t.Errorf("phase after network error: got %q, want %q", st.Phase, PhaseDegraded)
	}
}

func TestRunPush_SkipsWhenInBackoff(t *testing.T) {
	s := newTestStore(t)
	seedObservation(t, s)

	var called atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
	}))
	defer ts.Close()

	m := newTestManager(t, s, ts.URL)
	// Manually put manager into backoff.
	future := time.Now().Add(time.Hour)
	m.mu.Lock()
	m.status.BackoffUntil = &future
	m.status.Phase = string(PhaseDegraded)
	m.mu.Unlock()

	m.runPush()
	if called.Load() {
		t.Error("expected push to be skipped while in backoff")
	}
}

func TestRunPush_AuthHeaderSent(t *testing.T) {
	s := newTestStore(t)
	seedObservation(t, s)

	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sync/push" {
			gotAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"accepted": 1, "seqs": []int64{1}})
		}
	}))
	defer ts.Close()

	m := newTestManager(t, s, ts.URL)
	m.runPush()

	if !strings.HasPrefix(gotAuth, "Bearer ") {
		t.Errorf("expected Bearer auth header, got %q", gotAuth)
	}
}

// ─── Pull Tests ───────────────────────────────────────────────────────────────

func TestRunPull_NoMutations_NoError(t *testing.T) {
	s := newTestStore(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"mutations": []any{}, "count": 0, "has_more": false})
	}))
	defer ts.Close()

	m := newTestManager(t, s, ts.URL)
	m.runPull()

	st := m.Status()
	// No error, phase stays idle (no recordSuccess on empty pull).
	if st.ConsecutiveFailures != 0 {
		t.Errorf("failures: got %d, want 0", st.ConsecutiveFailures)
	}
}

func TestRunPull_ServerError_RecordsDegradation(t *testing.T) {
	s := newTestStore(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	m := newTestManager(t, s, ts.URL)
	m.runPull()

	st := m.Status()
	if st.Phase != string(PhaseDegraded) {
		t.Errorf("phase: got %q, want %q", st.Phase, PhaseDegraded)
	}
}

func TestRunPull_AppliesMutations(t *testing.T) {
	s := newTestStore(t)

	// Create a session first so the observation upsert has a valid session_id.
	if err := s.CreateSession("remote-sess-1", "testproject", "/remote"); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	syncID := "obs-remote-1"
	payload, _ := json.Marshal(map[string]any{
		"sync_id":    syncID,
		"session_id": "remote-sess-1",
		"type":       "decision",
		"title":      "Remote decision",
		"content":    "Content from remote",
		"scope":      "project",
		"project":    "testproject",
	})

	mutation := map[string]any{
		"seq":           int64(1),
		"source_client": "client-remote",
		"entity":        "observation",
		"entity_key":    syncID,
		"op":            "upsert",
		"payload":       string(payload),
		"project":       "testproject",
		"occurred_at":   "2026-01-01T00:00:00Z",
		"created_at":    "2026-01-01T00:00:00Z",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sync/pull":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"mutations": []any{mutation},
				"count":     1,
				"has_more":  false,
			})
		case "/v1/sync/ack":
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	m := newTestManager(t, s, ts.URL)
	m.runPull()

	st := m.Status()
	if st.Phase != string(PhaseHealthy) {
		t.Errorf("phase: got %q, want %q", st.Phase, PhaseHealthy)
	}

	// Confirm the observation was applied locally.
	obs, err := s.GetObservationBySyncID(syncID)
	if err != nil {
		t.Fatalf("GetObservationBySyncID: %v", err)
	}
	if obs.Title != "Remote decision" {
		t.Errorf("Title: got %q, want %q", obs.Title, "Remote decision")
	}
}

// ─── Start/Stop Tests ─────────────────────────────────────────────────────────

func TestStartStop(t *testing.T) {
	s := newTestStore(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"mutations": []any{}, "count": 0, "has_more": false})
	}))
	defer ts.Close()

	m := newTestManager(t, s, ts.URL)
	m.Start()

	// Give loops a moment to start.
	time.Sleep(50 * time.Millisecond)

	// Stop must return within a reasonable time.
	stopped := make(chan struct{})
	go func() {
		m.Stop()
		close(stopped)
	}()

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not return within 5 seconds")
	}
}

// ─── Config Read / Write ──────────────────────────────────────────────────────

func TestReadWriteCloudConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := &CloudConfig{
		ServerURL:  "https://engram.example.com",
		APIKey:     "ek_abc123",
		ClientID:   "client-xyz",
		ClientName: "test-machine",
		Project:    "myproject",
	}
	path := filepath.Join(dir, "cloud.json")

	if err := WriteCloudConfig(path, cfg); err != nil {
		t.Fatalf("WriteCloudConfig: %v", err)
	}

	loaded, err := ReadCloudConfig(path)
	if err != nil {
		t.Fatalf("ReadCloudConfig: %v", err)
	}
	if loaded.ServerURL != cfg.ServerURL {
		t.Errorf("ServerURL: got %q, want %q", loaded.ServerURL, cfg.ServerURL)
	}
	if loaded.APIKey != cfg.APIKey {
		t.Errorf("APIKey: got %q, want %q", loaded.APIKey, cfg.APIKey)
	}
	if loaded.Project != cfg.Project {
		t.Errorf("Project: got %q, want %q", loaded.Project, cfg.Project)
	}
}

func TestReadCloudConfig_Missing(t *testing.T) {
	_, err := ReadCloudConfig("/nonexistent/path/cloud.json")
	if !os.IsNotExist(err) {
		t.Errorf("expected IsNotExist error, got %v", err)
	}
}
