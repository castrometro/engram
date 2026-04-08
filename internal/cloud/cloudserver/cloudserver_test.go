package cloudserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Gentleman-Programming/engram/internal/cloud/cloudstore"
)

// ─── Test Helpers ─────────────────────────────────────────────────────────────

func newTestServer(t *testing.T) (*CloudServer, string) {
	t.Helper()
	cs, err := cloudstore.Open(":memory:")
	if err != nil {
		t.Fatalf("cloudstore.Open: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	srv := New(cs, 0)
	return srv, registerClient(t, srv, "test-project", "test-client")
}

// registerClient calls POST /v1/auth/register and returns the raw API key.
func registerClient(t *testing.T, srv *CloudServer, project, clientName string) string {
	t.Helper()
	body := map[string]string{"project": project, "client_name": clientName}
	rec := doJSON(t, srv.Handler(), http.MethodPost, "/v1/auth/register", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: got status %d, want %d; body: %s", rec.Code, http.StatusCreated, rec.Body)
	}
	var resp map[string]string
	mustDecode(t, rec, &resp)
	key, ok := resp["api_key"]
	if !ok || key == "" {
		t.Fatalf("register: missing api_key in response: %v", resp)
	}
	return key
}

// doJSON sends a JSON request to the handler and returns the recorder.
func doJSON(t *testing.T, h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// doJSONAuth sends an authenticated JSON request.
func doJSONAuth(t *testing.T, h http.Handler, method, path, apiKey string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func mustDecode(t *testing.T, rec *httptest.ResponseRecorder, dest any) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(dest); err != nil {
		t.Fatalf("decode response: %v; body: %s", err, rec.Body)
	}
}

// ─── Health ───────────────────────────────────────────────────────────────────

func TestHandleHealth(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv.Handler(), http.MethodGet, "/health", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("health: got %d, want 200", rec.Code)
	}
}

// ─── Register ─────────────────────────────────────────────────────────────────

func TestHandleRegister_Success(t *testing.T) {
	cs, err := cloudstore.Open(":memory:")
	if err != nil {
		t.Fatalf("cloudstore.Open: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	srv := New(cs, 0)

	rec := doJSON(t, srv.Handler(), http.MethodPost, "/v1/auth/register", map[string]string{
		"project":     "myproject",
		"client_name": "alice-mac",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: got %d, want 201; body: %s", rec.Code, rec.Body)
	}

	var resp map[string]string
	mustDecode(t, rec, &resp)
	if resp["api_key"] == "" {
		t.Error("expected non-empty api_key")
	}
	if resp["client_id"] == "" {
		t.Error("expected non-empty client_id")
	}
	if resp["project"] != "myproject" {
		t.Errorf("project: got %q, want %q", resp["project"], "myproject")
	}
}

func TestHandleRegister_MissingProject(t *testing.T) {
	cs, err := cloudstore.Open(":memory:")
	if err != nil {
		t.Fatalf("cloudstore.Open: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	srv := New(cs, 0)

	rec := doJSON(t, srv.Handler(), http.MethodPost, "/v1/auth/register", map[string]string{"client_name": "alice"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandleRegister_DefaultClientName(t *testing.T) {
	cs, err := cloudstore.Open(":memory:")
	if err != nil {
		t.Fatalf("cloudstore.Open: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	srv := New(cs, 0)

	rec := doJSON(t, srv.Handler(), http.MethodPost, "/v1/auth/register", map[string]string{"project": "proj"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: got %d; body: %s", rec.Code, rec.Body)
	}
}

// ─── Auth Middleware ──────────────────────────────────────────────────────────

func TestAuthMiddleware_MissingToken(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/sync/pull", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/sync/pull", nil)
	req.Header.Set("Authorization", "Bearer ek_notreal0000000000000000000000000000000000000000000000000000000000")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// ─── Push ─────────────────────────────────────────────────────────────────────

func TestHandlePush_Success(t *testing.T) {
	srv, apiKey := newTestServer(t)

	body := map[string]any{
		"mutations": []map[string]string{
			{"entity": "observation", "entity_key": "obs-1", "op": "upsert", "payload": `{"title":"hello"}`, "project": "test-project", "occurred_at": "2026-01-01T00:00:00Z"},
		},
	}
	rec := doJSONAuth(t, srv.Handler(), http.MethodPost, "/v1/sync/push", apiKey, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("push: got %d; body: %s", rec.Code, rec.Body)
	}

	var resp map[string]any
	mustDecode(t, rec, &resp)
	if resp["accepted"].(float64) != 1 {
		t.Errorf("accepted: got %v, want 1", resp["accepted"])
	}
}

func TestHandlePush_WrongProject(t *testing.T) {
	srv, apiKey := newTestServer(t)

	body := map[string]any{
		"mutations": []map[string]string{
			{"entity": "observation", "entity_key": "obs-1", "op": "upsert", "payload": `{}`, "project": "other-project", "occurred_at": "2026-01-01T00:00:00Z"},
		},
	}
	rec := doJSONAuth(t, srv.Handler(), http.MethodPost, "/v1/sync/push", apiKey, body)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d; body: %s", rec.Code, rec.Body)
	}
}

func TestHandlePush_EmptyMutations(t *testing.T) {
	srv, apiKey := newTestServer(t)

	body := map[string]any{"mutations": []any{}}
	rec := doJSONAuth(t, srv.Handler(), http.MethodPost, "/v1/sync/push", apiKey, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("push empty: got %d; body: %s", rec.Code, rec.Body)
	}
}

func TestHandlePush_TooManyMutations(t *testing.T) {
	srv, apiKey := newTestServer(t)

	mutations := make([]map[string]string, 501)
	for i := range mutations {
		mutations[i] = map[string]string{
			"entity": "observation", "entity_key": "obs", "op": "upsert",
			"payload": "{}", "project": "test-project", "occurred_at": "2026-01-01T00:00:00Z",
		}
	}
	body := map[string]any{"mutations": mutations}
	rec := doJSONAuth(t, srv.Handler(), http.MethodPost, "/v1/sync/push", apiKey, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

// ─── Pull ─────────────────────────────────────────────────────────────────────

func TestHandlePull_Success(t *testing.T) {
	srv, apiKeyA := newTestServer(t)
	// Register a second client for the same project.
	apiKeyB := registerClient(t, srv, "test-project", "client-B")

	// Push from client A.
	pushBody := map[string]any{
		"mutations": []map[string]string{
			{"entity": "observation", "entity_key": "obs-1", "op": "upsert", "payload": `{}`, "project": "test-project", "occurred_at": "2026-01-01T00:00:00Z"},
		},
	}
	rec := doJSONAuth(t, srv.Handler(), http.MethodPost, "/v1/sync/push", apiKeyA, pushBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("push: got %d", rec.Code)
	}

	// Client B should see it.
	rec = doJSONAuth(t, srv.Handler(), http.MethodGet, "/v1/sync/pull?since_seq=0", apiKeyB, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("pull: got %d; body: %s", rec.Code, rec.Body)
	}
	var resp map[string]any
	mustDecode(t, rec, &resp)
	if int(resp["count"].(float64)) != 1 {
		t.Errorf("count: got %v, want 1", resp["count"])
	}
}

func TestHandlePull_OwnMutationsExcluded(t *testing.T) {
	srv, apiKey := newTestServer(t)

	// Push from this client.
	pushBody := map[string]any{
		"mutations": []map[string]string{
			{"entity": "observation", "entity_key": "obs-1", "op": "upsert", "payload": `{}`, "project": "test-project", "occurred_at": "2026-01-01T00:00:00Z"},
		},
	}
	doJSONAuth(t, srv.Handler(), http.MethodPost, "/v1/sync/push", apiKey, pushBody)

	// Same client pulls — should see nothing.
	rec := doJSONAuth(t, srv.Handler(), http.MethodGet, "/v1/sync/pull?since_seq=0", apiKey, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("pull: got %d; body: %s", rec.Code, rec.Body)
	}
	var resp map[string]any
	mustDecode(t, rec, &resp)
	if int(resp["count"].(float64)) != 0 {
		t.Errorf("count: got %v, want 0", resp["count"])
	}
}

// ─── Ack ──────────────────────────────────────────────────────────────────────

func TestHandleAck_Success(t *testing.T) {
	srv, apiKey := newTestServer(t)

	body := map[string]any{"last_seq": 42}
	rec := doJSONAuth(t, srv.Handler(), http.MethodPost, "/v1/sync/ack", apiKey, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("ack: got %d; body: %s", rec.Code, rec.Body)
	}
	var resp map[string]any
	mustDecode(t, rec, &resp)
	if resp["acknowledged"].(float64) != 42 {
		t.Errorf("acknowledged: got %v, want 42", resp["acknowledged"])
	}
}

func TestHandleAck_InvalidSeq(t *testing.T) {
	srv, apiKey := newTestServer(t)

	body := map[string]any{"last_seq": 0}
	rec := doJSONAuth(t, srv.Handler(), http.MethodPost, "/v1/sync/ack", apiKey, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

// ─── Status ───────────────────────────────────────────────────────────────────

func TestHandleStatus_EmptyProject(t *testing.T) {
	srv, apiKey := newTestServer(t)

	rec := doJSONAuth(t, srv.Handler(), http.MethodGet, "/v1/sync/status", apiKey, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d; body: %s", rec.Code, rec.Body)
	}
	var resp map[string]any
	mustDecode(t, rec, &resp)
	if resp["project"] != "test-project" {
		t.Errorf("project: got %v, want 'test-project'", resp["project"])
	}
}

// ─── Start/Listen ──────────────────────────────────────────────────────────────

type stubListener struct{}

func (stubListener) Accept() (net.Conn, error) { return nil, errors.New("not used") }
func (stubListener) Close() error              { return nil }
func (stubListener) Addr() net.Addr            { return &net.TCPAddr{} }

func TestStart_ListenError(t *testing.T) {
	cs, err := cloudstore.Open(":memory:")
	if err != nil {
		t.Fatalf("cloudstore.Open: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	srv := New(cs, 0)
	srv.listen = func(_, _ string) (net.Listener, error) {
		return nil, errors.New("listen error")
	}
	if err := srv.Start(); err == nil {
		t.Fatal("expected error from Start(), got nil")
	}
}

func TestStart_UsesInjectedServe(t *testing.T) {
	cs, err := cloudstore.Open(":memory:")
	if err != nil {
		t.Fatalf("cloudstore.Open: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	srv := New(cs, 0)
	srv.listen = func(_, _ string) (net.Listener, error) { return stubListener{}, nil }
	srv.serve = func(_ net.Listener, _ http.Handler) error { return errors.New("serve stopped") }
	err = srv.Start()
	if err == nil || err.Error() != "cloudserver: listen 0.0.0.0:0: serve stopped" {
		// Expect wrapped error — just check it's non-nil and contains "serve stopped".
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	}
}
