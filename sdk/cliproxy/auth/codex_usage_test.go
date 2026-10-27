package auth

import (
	"context"
	"testing"
)

func TestCodexUsageCandidatesTrackInferenceOnly(t *testing.T) {
	m := NewManager(nil, nil, nil)
	ctx := context.Background()
	for _, id := range []string{"lite", "pro"} {
		if _, err := m.Register(ctx, &Auth{ID: id, Provider: "codex", Status: StatusActive, Metadata: map[string]any{"access_token": "test", "weight": 1}}); err != nil {
			t.Fatal(err)
		}
	}
	m.MarkResult(ctx, Result{AuthID: "pro", Model: "gpt-test", Success: true})
	m.MarkResult(ctx, Result{AuthID: "lite", Model: "gpt-test", Success: true, SkipQuotaObservation: true})
	m.MarkResult(ctx, Result{AuthID: "lite", Success: true})
	for i := 0; i < 2; i++ {
		got := m.CodexUsageCandidates()
		if len(got) != 2 || got[0].ID != "pro" {
			t.Fatal("non-inference activity changed the preferred usage account")
		}
	}
}
