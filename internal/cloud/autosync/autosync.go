// Package autosync implements the background cloud synchronization manager
// for Engram clients.
//
// The Manager runs two lightweight goroutines:
//
//   - Push loop: reads pending mutations from the local store's sync journal
//     and sends them to the cloud server. On success, acknowledges them
//     in the local store.
//
//   - Pull loop: polls the cloud server for mutations written by other clients
//     and applies them to the local store via ApplyPulledMutation.
//
// The Manager integrates with the existing store sync infrastructure:
//
//	store.ListPendingSyncMutations  → mutations to push
//	store.AckSyncMutations          → mark pushed mutations as acknowledged
//	store.ApplyPulledMutation       → apply remote mutations locally
//	store.GetSyncState              → read last_pulled_seq cursor
//	store.MarkSyncFailure           → record errors for back-off
//	store.MarkSyncHealthy           → clear error state after recovery
//
// The Manager also implements server.SyncStatusProvider so that its status
// can be reported via the local HTTP server's GET /sync/status endpoint.
package autosync

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/castrometro/engram/internal/cloud/cloudstore"
	"github.com/castrometro/engram/internal/store"
)

// maxMutationsPerBatch is the maximum number of mutations fetched and pushed
// in a single push cycle. The HasMore check uses the same constant.
const maxMutationsPerBatch = 100

// defaultPushInterval is how often the push loop wakes up when idle.
const defaultPushInterval = 30 * time.Second

// defaultPullInterval is how often the pull loop polls the cloud server.
const defaultPullInterval = 30 * time.Second

// maxBackoff caps the back-off delay between retries.
const maxBackoff = 5 * time.Minute

// ─── Config ───────────────────────────────────────────────────────────────────

// Config holds the runtime configuration for the autosync Manager.
type Config struct {
	// ServerURL is the base URL of the Engram cloud server,
	// e.g. "https://engram.mycompany.com".
	ServerURL string

	// APIKey is the Bearer token issued by POST /v1/auth/register.
	APIKey string

	// ClientID is the stable identifier for this machine/developer,
	// returned alongside the API key during registration.
	ClientID string

	// Project is the project name to sync (must match the API key's scope).
	Project string

	// PushInterval controls how often the push loop checks for pending mutations.
	// Defaults to 30 s if zero.
	PushInterval time.Duration

	// PullInterval controls how often the pull loop polls for remote mutations.
	// Defaults to 30 s if zero.
	PullInterval time.Duration
}

func (c *Config) pushInterval() time.Duration {
	if c.PushInterval > 0 {
		return c.PushInterval
	}
	return defaultPushInterval
}

func (c *Config) pullInterval() time.Duration {
	if c.PullInterval > 0 {
		return c.PullInterval
	}
	return defaultPullInterval
}

// ─── Status ───────────────────────────────────────────────────────────────────

// Phase is the current lifecycle state of the sync manager.
type Phase string

const (
	PhaseIdle     Phase = "idle"
	PhasePushing  Phase = "pushing"
	PhasePulling  Phase = "pulling"
	PhaseHealthy  Phase = "healthy"
	PhaseDegraded Phase = "degraded"
)

// Status holds the observable state of the Manager.
// It satisfies the server.SyncStatusProvider interface contract.
type Status struct {
	Phase               string     `json:"phase"`
	LastError           string     `json:"last_error,omitempty"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	BackoffUntil        *time.Time `json:"backoff_until,omitempty"`
	LastSyncAt          *time.Time `json:"last_sync_at,omitempty"`
}

// ─── Manager ──────────────────────────────────────────────────────────────────

// Manager orchestrates background push and pull loops.
type Manager struct {
	cfg    Config
	s      *store.Store
	client httpClient

	mu     sync.RWMutex
	status Status

	dirty chan struct{} // buffered; signalled by NotifyDirty()
	stop  chan struct{} // closed by Stop()
	done  chan struct{} // closed when both loops have exited
}

// httpClient is an abstraction over *http.Client to allow testing.
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// New creates a new Manager. Call Start() to begin background sync.
func New(cfg Config, s *store.Store) *Manager {
	return &Manager{
		cfg:    cfg,
		s:      s,
		client: &http.Client{Timeout: 30 * time.Second},
		dirty:  make(chan struct{}, 1),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		status: Status{Phase: string(PhaseIdle)},
	}
}

// Start launches the push and pull goroutines. It is safe to call once.
func (m *Manager) Start() {
	log.Printf("[engram-cloud] autosync starting (server=%s project=%s client=%s)",
		m.cfg.ServerURL, m.cfg.Project, m.cfg.ClientID)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		m.pushLoop()
	}()
	go func() {
		defer wg.Done()
		m.pullLoop()
	}()

	go func() {
		wg.Wait()
		close(m.done)
		log.Println("[engram-cloud] autosync stopped")
	}()
}

// Stop signals both loops to exit and waits for them to finish.
func (m *Manager) Stop() {
	close(m.stop)
	<-m.done
}

// NotifyDirty wakes the push loop immediately (non-blocking).
// Call this after any local write so new mutations are pushed promptly.
func (m *Manager) NotifyDirty() {
	select {
	case m.dirty <- struct{}{}:
	default:
	}
}

// Status returns a snapshot of the current sync state.
// It satisfies the server.SyncStatusProvider interface.
func (m *Manager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (m *Manager) setPhase(p Phase) {
	m.mu.Lock()
	m.status.Phase = string(p)
	m.mu.Unlock()
}

func (m *Manager) recordSuccess() {
	now := time.Now()
	m.mu.Lock()
	m.status.Phase = string(PhaseHealthy)
	m.status.ConsecutiveFailures = 0
	m.status.LastError = ""
	m.status.BackoffUntil = nil
	m.status.LastSyncAt = &now
	m.mu.Unlock()
}

func (m *Manager) recordFailure(err error) {
	m.mu.Lock()
	m.status.Phase = string(PhaseDegraded)
	m.status.ConsecutiveFailures++
	m.status.LastError = err.Error()
	backoff := time.Duration(m.status.ConsecutiveFailures) * 15 * time.Second
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	t := time.Now().Add(backoff)
	m.status.BackoffUntil = &t
	m.mu.Unlock()

	_ = m.s.MarkSyncFailure(store.DefaultSyncTargetKey, err.Error(), t)
}

func (m *Manager) isInBackoff() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.status.BackoffUntil == nil {
		return false
	}
	return time.Now().Before(*m.status.BackoffUntil)
}

// ─── Push Loop ────────────────────────────────────────────────────────────────

func (m *Manager) pushLoop() {
	ticker := time.NewTicker(m.cfg.pushInterval())
	defer ticker.Stop()

	for {
		select {
		case <-m.stop:
			return
		case <-m.dirty:
			m.runPush()
		case <-ticker.C:
			m.runPush()
		}
	}
}

func (m *Manager) runPush() {
	if m.isInBackoff() {
		return
	}

	mutations, err := m.s.ListPendingSyncMutations(store.DefaultSyncTargetKey, maxMutationsPerBatch)
	if err != nil {
		m.recordFailure(fmt.Errorf("list pending mutations: %w", err))
		return
	}
	if len(mutations) == 0 {
		return
	}

	m.setPhase(PhasePushing)

	clientMuts := make([]cloudstore.ClientMutation, 0, len(mutations))
	for _, mut := range mutations {
		clientMuts = append(clientMuts, cloudstore.ClientMutation{
			Entity:     mut.Entity,
			EntityKey:  mut.EntityKey,
			Op:         mut.Op,
			Payload:    mut.Payload,
			Project:    mut.Project,
			OccurredAt: mut.OccurredAt,
		})
	}

	body, err := json.Marshal(map[string]any{"mutations": clientMuts})
	if err != nil {
		m.recordFailure(fmt.Errorf("marshal push body: %w", err))
		return
	}

	req, err := http.NewRequest(http.MethodPost, m.cfg.ServerURL+"/v1/sync/push", bytes.NewReader(body))
	if err != nil {
		m.recordFailure(fmt.Errorf("create push request: %w", err))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+m.cfg.APIKey)

	resp, err := m.client.Do(req)
	if err != nil {
		m.recordFailure(fmt.Errorf("push request: %w", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		m.recordFailure(fmt.Errorf("push returned %d: %s", resp.StatusCode, body))
		return
	}

	// Acknowledge the pushed mutations in the local store.
	lastSeq := mutations[len(mutations)-1].Seq
	if err := m.s.AckSyncMutations(store.DefaultSyncTargetKey, lastSeq); err != nil {
		m.recordFailure(fmt.Errorf("ack mutations: %w", err))
		return
	}

	_ = m.s.MarkSyncHealthy(store.DefaultSyncTargetKey)
	m.recordSuccess()
	log.Printf("[engram-cloud] pushed %d mutations (up to seq %d)", len(mutations), lastSeq)

	// If there may be more pending mutations, trigger another push immediately.
	if len(mutations) == maxMutationsPerBatch {
		m.NotifyDirty()
	}
}

// RunPushOnce executes a single push cycle synchronously.
// It is used by "engram cloud push" for manual one-shot pushes.
func (m *Manager) RunPushOnce() {
	m.runPush()
}

// RunPullOnce executes a single pull cycle synchronously.
// It is used by "engram cloud pull" for manual one-shot pulls.
func (m *Manager) RunPullOnce() {
	m.runPull()
}

func (m *Manager) pullLoop() {
	ticker := time.NewTicker(m.cfg.pullInterval())
	defer ticker.Stop()

	for {
		select {
		case <-m.stop:
			return
		case <-m.dirty:
			// Also pull when dirty is signalled (e.g. HasMore from a previous pull).
			m.runPull()
		case <-ticker.C:
			m.runPull()
		}
	}
}

func (m *Manager) runPull() {
	if m.isInBackoff() {
		return
	}

	syncState, err := m.s.GetSyncState(store.DefaultSyncTargetKey)
	if err != nil {
		m.recordFailure(fmt.Errorf("get sync state: %w", err))
		return
	}

	m.setPhase(PhasePulling)

	url := fmt.Sprintf("%s/v1/sync/pull?since_seq=%d&limit=%d", m.cfg.ServerURL, syncState.LastPulledSeq, maxMutationsPerBatch)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		m.recordFailure(fmt.Errorf("create pull request: %w", err))
		return
	}
	req.Header.Set("Authorization", "Bearer "+m.cfg.APIKey)

	resp, err := m.client.Do(req)
	if err != nil {
		m.recordFailure(fmt.Errorf("pull request: %w", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		m.recordFailure(fmt.Errorf("pull returned %d: %s", resp.StatusCode, body))
		return
	}

	var pullResp struct {
		Mutations []cloudstore.CloudMutation `json:"mutations"`
		HasMore   bool                       `json:"has_more"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pullResp); err != nil {
		m.recordFailure(fmt.Errorf("decode pull response: %w", err))
		return
	}

	if len(pullResp.Mutations) == 0 {
		return
	}

	var lastAppliedSeq int64
	for _, cm := range pullResp.Mutations {
		mutation := store.SyncMutation{
			Seq:        cm.Seq,
			TargetKey:  store.DefaultSyncTargetKey,
			Entity:     cm.Entity,
			EntityKey:  cm.EntityKey,
			Op:         cm.Op,
			Payload:    cm.Payload,
			Project:    cm.Project,
			OccurredAt: cm.OccurredAt,
			Source:     store.SyncSourceRemote,
		}
		if err := m.s.ApplyPulledMutation(store.DefaultSyncTargetKey, mutation); err != nil {
			m.recordFailure(fmt.Errorf("apply mutation seq=%d: %w", cm.Seq, err))
			return
		}
		lastAppliedSeq = cm.Seq
	}

	// Ack pulled mutations back to the cloud server.
	if lastAppliedSeq > 0 {
		m.ackToServer(lastAppliedSeq)
	}

	_ = m.s.MarkSyncHealthy(store.DefaultSyncTargetKey)
	m.recordSuccess()
	log.Printf("[engram-cloud] pulled and applied %d mutations (up to seq %d)", len(pullResp.Mutations), lastAppliedSeq)

	// If there are more mutations, signal the pull loop to run again on the
	// next tick rather than spawning a new goroutine to avoid unbounded recursion.
	if pullResp.HasMore {
		m.NotifyDirty()
	}
}

// ackToServer sends POST /v1/sync/ack to inform the cloud of the highest
// applied seq. This is best-effort — failures don't block local progress
// because the client's last_pulled_seq is already updated in the local store.
func (m *Manager) ackToServer(lastSeq int64) {
	body, _ := json.Marshal(map[string]int64{"last_seq": lastSeq})
	req, err := http.NewRequest(http.MethodPost, m.cfg.ServerURL+"/v1/sync/ack", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+m.cfg.APIKey)
	resp, err := m.client.Do(req)
	if err != nil {
		log.Printf("[engram-cloud] ack request failed: %v", err)
		return
	}
	resp.Body.Close()
}
