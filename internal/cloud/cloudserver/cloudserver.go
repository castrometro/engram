// Package cloudserver implements the HTTP API for the Engram cloud sync hub.
//
// It exposes five endpoints under /v1:
//
//	POST /v1/auth/register   Register a client and obtain an API key
//	POST /v1/sync/push       Push a batch of local mutations to the cloud
//	GET  /v1/sync/pull       Pull mutations since a given sequence number
//	POST /v1/sync/ack        Acknowledge receipt and application of pulled mutations
//	GET  /v1/sync/status     Report aggregated stats for the caller's project
//	GET  /health             Liveness probe (no auth required)
//
// Authentication uses API keys issued by /v1/auth/register. Clients must
// pass the key as a Bearer token: "Authorization: Bearer ek_live_<hex>".
package cloudserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/Gentleman-Programming/engram/internal/cloud/cloudstore"
)

// CloudServer is the Engram cloud sync HTTP server.
type CloudServer struct {
	store  *cloudstore.CloudStore
	mux    *http.ServeMux
	port   int
	listen func(network, address string) (net.Listener, error)
	serve  func(net.Listener, http.Handler) error
}

// New creates a new CloudServer bound to the given port.
func New(cs *cloudstore.CloudStore, port int) *CloudServer {
	srv := &CloudServer{
		store:  cs,
		port:   port,
		listen: net.Listen,
		serve:  http.Serve,
	}
	srv.mux = http.NewServeMux()
	srv.routes()
	return srv
}

// Handler returns the underlying HTTP handler (useful in tests).
func (s *CloudServer) Handler() http.Handler {
	return s.mux
}

// Start begins listening for connections.
func (s *CloudServer) Start() error {
	addr := fmt.Sprintf("0.0.0.0:%d", s.port)
	ln, err := s.listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("cloudserver: listen %s: %w", addr, err)
	}
	log.Printf("[engram-cloud] HTTP server listening on %s", addr)
	return s.serve(ln, s.mux)
}

// ─── Routes ───────────────────────────────────────────────────────────────────

func (s *CloudServer) routes() {
	s.mux.HandleFunc("GET /health", s.handleHealth)
	s.mux.HandleFunc("POST /v1/auth/register", s.handleRegister)
	s.mux.HandleFunc("POST /v1/sync/push", s.withAuth(s.handlePush))
	s.mux.HandleFunc("GET /v1/sync/pull", s.withAuth(s.handlePull))
	s.mux.HandleFunc("POST /v1/sync/ack", s.withAuth(s.handleAck))
	s.mux.HandleFunc("GET /v1/sync/status", s.withAuth(s.handleStatus))
}

// ─── Auth Middleware ──────────────────────────────────────────────────────────

type contextKey string

const apiKeyInfoKey contextKey = "api_key_info"

// withAuth is a middleware that validates the Bearer API key before calling
// the inner handler. It injects the APIKeyInfo into the request context.
func (s *CloudServer) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := extractBearerToken(r)
		if raw == "" {
			jsonError(w, http.StatusUnauthorized, "missing or malformed Authorization header")
			return
		}
		info, err := s.store.ValidateAPIKey(raw)
		if err != nil {
			jsonError(w, http.StatusUnauthorized, "invalid or expired api key")
			return
		}
		// Store info in a request-local map; avoid importing context to keep deps minimal.
		r = r.WithContext(context.WithValue(r.Context(), apiKeyInfoKey, info))
		next(w, r)
	}
}

// extractBearerToken parses "Authorization: Bearer <token>" from the request.
func extractBearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}

// apiKeyFromContext retrieves the validated APIKeyInfo from the request context.
func apiKeyFromContext(r *http.Request) *cloudstore.APIKeyInfo {
	v := r.Context().Value(apiKeyInfoKey)
	if v == nil {
		return nil
	}
	info, _ := v.(*cloudstore.APIKeyInfo)
	return info
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

func (s *CloudServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]string{"status": "ok", "service": "engram-cloud"})
}

// handleRegister issues a new API key for the caller.
//
//	POST /v1/auth/register
//	Body: {"client_name": "alice-macbook", "project": "myproject"}
//	Response: {"client_id": "client-...", "api_key": "ek_...", "project": "myproject"}
func (s *CloudServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ClientName string `json:"client_name"`
		Project    string `json:"project"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if body.Project == "" {
		jsonError(w, http.StatusBadRequest, "project is required")
		return
	}
	if body.ClientName == "" {
		body.ClientName = "unnamed-client"
	}

	clientID, err := cloudstore.NewClientID()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to generate client id")
		return
	}
	rawKey, err := s.store.CreateAPIKey(clientID, body.Project, body.ClientName)
	if err != nil {
		log.Printf("[engram-cloud] register error: %v", err)
		jsonError(w, http.StatusInternalServerError, "failed to create api key")
		return
	}

	log.Printf("[engram-cloud] registered client %s (%s) for project %s", clientID, body.ClientName, body.Project)
	jsonResponse(w, http.StatusCreated, map[string]string{
		"client_id":   clientID,
		"client_name": body.ClientName,
		"project":     body.Project,
		"api_key":     rawKey,
	})
}

// handlePush receives a batch of local mutations from the client.
//
//	POST /v1/sync/push
//	Body: {"mutations": [{entity, entity_key, op, payload, project, occurred_at}, ...]}
//	Response: {"seqs": [1, 2, 3], "accepted": 3}
func (s *CloudServer) handlePush(w http.ResponseWriter, r *http.Request) {
	info := apiKeyFromContext(r)
	if info == nil {
		jsonError(w, http.StatusInternalServerError, "auth info missing")
		return
	}

	var body struct {
		Mutations []cloudstore.ClientMutation `json:"mutations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if len(body.Mutations) == 0 {
		jsonResponse(w, http.StatusOK, map[string]any{"seqs": []int64{}, "accepted": 0})
		return
	}
	if len(body.Mutations) > 500 {
		jsonError(w, http.StatusBadRequest, "too many mutations in one push (max 500)")
		return
	}

	// Enforce project scope: all mutations must match the API key's project.
	for i, m := range body.Mutations {
		if m.Project != info.Project {
			jsonError(w, http.StatusForbidden,
				fmt.Sprintf("mutation[%d] project %q does not match api key project %q", i, m.Project, info.Project))
			return
		}
	}

	seqs, err := s.store.InsertMutations(info.ClientID, body.Mutations)
	if err != nil {
		log.Printf("[engram-cloud] push error (client=%s): %v", info.ClientID, err)
		jsonError(w, http.StatusInternalServerError, "push failed")
		return
	}

	jsonResponse(w, http.StatusOK, map[string]any{
		"seqs":     seqs,
		"accepted": len(seqs),
	})
}

// handlePull returns mutations the caller has not yet seen.
//
//	GET /v1/sync/pull?since_seq=N&limit=L
//	Response: {"mutations": [...], "count": N, "has_more": bool}
func (s *CloudServer) handlePull(w http.ResponseWriter, r *http.Request) {
	info := apiKeyFromContext(r)
	if info == nil {
		jsonError(w, http.StatusInternalServerError, "auth info missing")
		return
	}

	sinceSeq := queryInt64(r, "since_seq", 0)
	limit := queryInt(r, "limit", 100)

	mutations, err := s.store.PullMutations(info.ClientID, info.Project, sinceSeq, limit)
	if err != nil {
		log.Printf("[engram-cloud] pull error (client=%s): %v", info.ClientID, err)
		jsonError(w, http.StatusInternalServerError, "pull failed")
		return
	}

	jsonResponse(w, http.StatusOK, map[string]any{
		"mutations": mutations,
		"count":     len(mutations),
		"has_more":  len(mutations) == limit,
	})
}

// handleAck records the highest sequence number the client has applied.
//
//	POST /v1/sync/ack
//	Body: {"last_seq": N}
//	Response: {"acknowledged": N}
func (s *CloudServer) handleAck(w http.ResponseWriter, r *http.Request) {
	info := apiKeyFromContext(r)
	if info == nil {
		jsonError(w, http.StatusInternalServerError, "auth info missing")
		return
	}

	var body struct {
		LastSeq int64 `json:"last_seq"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if body.LastSeq <= 0 {
		jsonError(w, http.StatusBadRequest, "last_seq must be > 0")
		return
	}

	if err := s.store.UpdateClientCursor(info.ClientID, info.Project, body.LastSeq); err != nil {
		log.Printf("[engram-cloud] ack error (client=%s): %v", info.ClientID, err)
		jsonError(w, http.StatusInternalServerError, "ack failed")
		return
	}

	jsonResponse(w, http.StatusOK, map[string]any{"acknowledged": body.LastSeq})
}

// handleStatus returns aggregated sync statistics for the caller's project.
//
//	GET /v1/sync/status
//	Response: {"project": "...", "total_pushed": N, "active_clients": N, "max_seq": N}
func (s *CloudServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	info := apiKeyFromContext(r)
	if info == nil {
		jsonError(w, http.StatusInternalServerError, "auth info missing")
		return
	}

	status, err := s.store.GetProjectStatus(info.Project)
	if err != nil {
		log.Printf("[engram-cloud] status error (client=%s): %v", info.ClientID, err)
		jsonError(w, http.StatusInternalServerError, "status check failed")
		return
	}

	jsonResponse(w, http.StatusOK, status)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func jsonResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	jsonResponse(w, status, map[string]string{"error": msg})
}

func queryInt(r *http.Request, key string, defaultVal int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return defaultVal
	}
	return n
}

func queryInt64(r *http.Request, key string, defaultVal int64) int64 {
	v := r.URL.Query().Get(key)
	if v == "" {
		return defaultVal
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return defaultVal
	}
	return n
}
