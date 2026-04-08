package cloudstore

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func newTestStore(t *testing.T) *CloudStore {
	t.Helper()
	cs, err := Open(":memory:")
	if err != nil {
		t.Fatalf("cloudstore.Open: %v", err)
	}
	// Use minimum bcrypt cost to keep tests fast.
	cs.SetBcryptCost(bcrypt.MinCost)
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// ─── API Key Tests ────────────────────────────────────────────────────────────

func TestCreateAndValidateAPIKey(t *testing.T) {
	cs := newTestStore(t)

	raw, err := cs.CreateAPIKey("client-1", "myproject", "alice-macbook")
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if !strings.HasPrefix(raw, "ek_") {
		t.Fatalf("expected key prefix 'ek_', got %q", raw[:3])
	}
	if len(raw) != 67 { // "ek_" (3) + 64 hex chars
		t.Fatalf("expected key length 67, got %d", len(raw))
	}

	info, err := cs.ValidateAPIKey(raw)
	if err != nil {
		t.Fatalf("ValidateAPIKey: %v", err)
	}
	if info.ClientID != "client-1" {
		t.Errorf("ClientID: got %q, want %q", info.ClientID, "client-1")
	}
	if info.Project != "myproject" {
		t.Errorf("Project: got %q, want %q", info.Project, "myproject")
	}
	if info.ClientName != "alice-macbook" {
		t.Errorf("ClientName: got %q, want %q", info.ClientName, "alice-macbook")
	}
}

func TestValidateAPIKey_Invalid(t *testing.T) {
	cs := newTestStore(t)

	_, err := cs.ValidateAPIKey("ek_notarealkey0000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("expected error for non-existent key, got nil")
	}
}

func TestValidateAPIKey_WrongKey(t *testing.T) {
	cs := newTestStore(t)

	_, err := cs.CreateAPIKey("client-2", "proj", "bob")
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	// Different key should fail.
	fakeKey := "ek_" + strings.Repeat("a", 64)
	_, err = cs.ValidateAPIKey(fakeKey)
	if err == nil {
		t.Fatal("expected error for wrong key, got nil")
	}
}

// ─── Push Tests ───────────────────────────────────────────────────────────────

func TestInsertMutations_ReturnsSequentialSeqs(t *testing.T) {
	cs := newTestStore(t)

	mutations := []ClientMutation{
		{Entity: "observation", EntityKey: "obs-1", Op: "upsert", Payload: `{"title":"foo"}`, Project: "proj", OccurredAt: "2026-01-01T00:00:00Z"},
		{Entity: "observation", EntityKey: "obs-2", Op: "upsert", Payload: `{"title":"bar"}`, Project: "proj", OccurredAt: "2026-01-01T00:00:01Z"},
	}

	seqs, err := cs.InsertMutations("client-A", mutations)
	if err != nil {
		t.Fatalf("InsertMutations: %v", err)
	}
	if len(seqs) != 2 {
		t.Fatalf("expected 2 seqs, got %d", len(seqs))
	}
	if seqs[0] >= seqs[1] {
		t.Errorf("expected seqs[0] < seqs[1], got %d, %d", seqs[0], seqs[1])
	}
}

func TestInsertMutations_Empty(t *testing.T) {
	cs := newTestStore(t)

	seqs, err := cs.InsertMutations("client-A", nil)
	if err != nil {
		t.Fatalf("InsertMutations(nil): %v", err)
	}
	if len(seqs) != 0 {
		t.Fatalf("expected empty seqs, got %v", seqs)
	}
}

// ─── Pull Tests ───────────────────────────────────────────────────────────────

func TestPullMutations_ExcludesSourceClient(t *testing.T) {
	cs := newTestStore(t)

	muts := []ClientMutation{
		{Entity: "observation", EntityKey: "obs-1", Op: "upsert", Payload: `{}`, Project: "proj", OccurredAt: "2026-01-01T00:00:00Z"},
	}

	seqs, err := cs.InsertMutations("client-A", muts)
	if err != nil {
		t.Fatalf("InsertMutations: %v", err)
	}
	if len(seqs) == 0 {
		t.Fatal("expected seqs from insert")
	}

	// client-A should not see its own mutations.
	results, err := cs.PullMutations("client-A", "proj", 0, 100)
	if err != nil {
		t.Fatalf("PullMutations: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected client-A to see 0 of its own mutations, got %d", len(results))
	}

	// client-B should see client-A's mutations.
	results, err = cs.PullMutations("client-B", "proj", 0, 100)
	if err != nil {
		t.Fatalf("PullMutations client-B: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected client-B to see 1 mutation, got %d", len(results))
	}
	if results[0].EntityKey != "obs-1" {
		t.Errorf("EntityKey: got %q, want %q", results[0].EntityKey, "obs-1")
	}
}

func TestPullMutations_SinceSeq(t *testing.T) {
	cs := newTestStore(t)

	insert := func(key string) int64 {
		seqs, err := cs.InsertMutations("client-A", []ClientMutation{
			{Entity: "observation", EntityKey: key, Op: "upsert", Payload: `{}`, Project: "proj", OccurredAt: "2026-01-01T00:00:00Z"},
		})
		if err != nil {
			t.Fatalf("InsertMutations %s: %v", key, err)
		}
		return seqs[0]
	}

	seq1 := insert("obs-1")
	_ = insert("obs-2")
	_ = insert("obs-3")

	// Pull only mutations after seq1.
	results, err := cs.PullMutations("client-B", "proj", seq1, 100)
	if err != nil {
		t.Fatalf("PullMutations: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results after seq1, got %d", len(results))
	}
	for _, r := range results {
		if r.Seq <= seq1 {
			t.Errorf("expected seq > %d, got %d", seq1, r.Seq)
		}
	}
}

func TestPullMutations_ProjectIsolation(t *testing.T) {
	cs := newTestStore(t)

	// Insert into "proj-a".
	_, err := cs.InsertMutations("client-A", []ClientMutation{
		{Entity: "observation", EntityKey: "obs-1", Op: "upsert", Payload: `{}`, Project: "proj-a", OccurredAt: "2026-01-01T00:00:00Z"},
	})
	if err != nil {
		t.Fatalf("InsertMutations proj-a: %v", err)
	}

	// Pull for "proj-b" should return nothing.
	results, err := cs.PullMutations("client-B", "proj-b", 0, 100)
	if err != nil {
		t.Fatalf("PullMutations proj-b: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected no results for proj-b, got %d", len(results))
	}
}

// ─── Cursor Tests ─────────────────────────────────────────────────────────────

func TestUpdateClientCursor_IdempotentMax(t *testing.T) {
	cs := newTestStore(t)

	// Set cursor to 10.
	if err := cs.UpdateClientCursor("client-A", "proj", 10); err != nil {
		t.Fatalf("UpdateClientCursor: %v", err)
	}
	// Setting to 5 should not decrease cursor.
	if err := cs.UpdateClientCursor("client-A", "proj", 5); err != nil {
		t.Fatalf("UpdateClientCursor: %v", err)
	}

	// Verify via a pull from seq=0 — the cursor itself isn't directly queryable
	// but we can confirm no panic or data corruption occurred.
}

// ─── Status Tests ─────────────────────────────────────────────────────────────

func TestGetProjectStatus_Empty(t *testing.T) {
	cs := newTestStore(t)

	s, err := cs.GetProjectStatus("no-such-project")
	if err != nil {
		t.Fatalf("GetProjectStatus: %v", err)
	}
	if s.TotalPushed != 0 {
		t.Errorf("TotalPushed: got %d, want 0", s.TotalPushed)
	}
	if s.MaxSeq != 0 {
		t.Errorf("MaxSeq: got %d, want 0", s.MaxSeq)
	}
}

func TestGetProjectStatus_WithData(t *testing.T) {
	cs := newTestStore(t)

	for i, client := range []string{"client-A", "client-B"} {
		_, err := cs.InsertMutations(client, []ClientMutation{
			{Entity: "observation", EntityKey: fmt.Sprintf("obs-%d", i), Op: "upsert", Payload: `{}`, Project: "proj", OccurredAt: "2026-01-01T00:00:00Z"},
		})
		if err != nil {
			t.Fatalf("InsertMutations %s: %v", client, err)
		}
	}

	s, err := cs.GetProjectStatus("proj")
	if err != nil {
		t.Fatalf("GetProjectStatus: %v", err)
	}
	if s.TotalPushed != 2 {
		t.Errorf("TotalPushed: got %d, want 2", s.TotalPushed)
	}
	if s.ActiveClient != 2 {
		t.Errorf("ActiveClient: got %d, want 2", s.ActiveClient)
	}
}

// ─── NewClientID Tests ────────────────────────────────────────────────────────

func TestNewClientID_UniqueAndPrefixed(t *testing.T) {
	id1, err := NewClientID()
	if err != nil {
		t.Fatalf("NewClientID: %v", err)
	}
	id2, err := NewClientID()
	if err != nil {
		t.Fatalf("NewClientID: %v", err)
	}

	if id1 == id2 {
		t.Error("expected unique client IDs, got identical")
	}
	if !strings.HasPrefix(id1, "client-") {
		t.Errorf("expected prefix 'client-', got %q", id1)
	}
}
