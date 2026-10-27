package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const usageAvailable = `{"rate_limit":{"allowed":true,"limit_reached":false,"primary_window":{"used_percent":20}}}`
const usageExhausted = `{"rate_limit":{"allowed":false,"limit_reached":true,"primary_window":{"used_percent":100}}}`

type codexPoolUsageExecutor struct {
	codexSearchCaptureExecutor
	payloads map[string]string
	status   map[string]int
	errors   map[string]error
}

func (e *codexPoolUsageExecutor) HttpRequest(_ context.Context, selected *auth.Auth, _ *http.Request) (*http.Response, error) {
	e.authIDs = append(e.authIDs, selected.ID)
	if err := e.errors[selected.ID]; err != nil {
		return nil, err
	}
	status := e.status[selected.ID]
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(e.payloads[selected.ID]))}, nil
}

func TestCodexUsagePoolFallback(t *testing.T) {
	for _, affinity := range []bool{false, true} {
		for _, tc := range []struct {
			name, last, lite, pro string
			liteStatus            int
			liteError             error
			proWeight             int
			proDisabled           bool
			wantCalls             []string
			wantStatus            int
			wantBody              string
		}{
			{name: "last used available", last: "pro", lite: usageAvailable, pro: usageAvailable, proWeight: 1, wantCalls: []string{"pro"}, wantStatus: 200, wantBody: usageAvailable},
			{name: "exhausted falls back", last: "lite", lite: usageExhausted, pro: usageAvailable, proWeight: 1, wantCalls: []string{"lite", "pro"}, wantStatus: 200, wantBody: usageAvailable},
			{name: "all exhausted", last: "lite", lite: usageExhausted, pro: usageExhausted, proWeight: 1, wantCalls: []string{"lite", "pro"}, wantStatus: 200, wantBody: usageExhausted},
			{name: "zero weight excluded", last: "pro", lite: usageExhausted, pro: usageAvailable, proWeight: 0, wantCalls: []string{"lite"}, wantStatus: 200, wantBody: usageExhausted},
			{name: "disabled excluded", last: "pro", lite: usageExhausted, pro: usageAvailable, proWeight: 1, proDisabled: true, wantCalls: []string{"lite"}, wantStatus: 200, wantBody: usageExhausted},
			{name: "malformed is not exhausted", last: "lite", lite: `{`, pro: usageExhausted, proWeight: 1, wantCalls: []string{"lite", "pro"}, wantStatus: 502},
			{name: "missing limits is not exhausted", last: "lite", lite: `{}`, pro: usageExhausted, proWeight: 1, wantCalls: []string{"lite", "pro"}, wantStatus: 502},
			{name: "network error is not exhausted", last: "lite", liteError: errors.New("test transport failure"), pro: usageExhausted, proWeight: 1, wantCalls: []string{"lite", "pro"}, wantStatus: 502},
			{name: "http failure is not exhausted", last: "lite", liteStatus: 503, lite: `{"error":"unavailable"}`, pro: usageExhausted, proWeight: 1, wantCalls: []string{"lite", "pro"}, wantStatus: 503},
			{name: "failed probe still finds capacity", last: "lite", liteStatus: 503, pro: usageAvailable, proWeight: 1, wantCalls: []string{"lite", "pro"}, wantStatus: 200, wantBody: usageAvailable},
			{name: "no inference yet", lite: usageAvailable, pro: usageAvailable, proWeight: 1, wantCalls: []string{"lite"}, wantStatus: 200, wantBody: usageAvailable},
			{name: "weekly exhausted", last: "lite", lite: `{"rate_limit":{"allowed":true,"limit_reached":false,"secondary_window":{"used_percent":100}}}`, pro: usageAvailable, proWeight: 1, wantCalls: []string{"lite", "pro"}, wantStatus: 200, wantBody: usageAvailable},
			{name: "additional exhausted", last: "lite", lite: `{"rate_limit":{"allowed":true,"limit_reached":false},"additional_rate_limits":[{"rate_limit":{"allowed":false,"limit_reached":true}}]}`, pro: usageAvailable, proWeight: 1, wantCalls: []string{"lite", "pro"}, wantStatus: 200, wantBody: usageAvailable},
		} {
			t.Run(tc.name+map[bool]string{true: "/affinity", false: "/no-affinity"}[affinity], func(t *testing.T) {
				server := newTestServer(t)
				manager := server.handlers.AuthManager
				fallback := &codexUsageCountingSelector{}
				manager.SetSelector(fallback)
				var selector *auth.SessionAffinitySelector
				if affinity {
					selector = auth.NewSessionAffinitySelector(fallback)
					t.Cleanup(selector.Stop)
					manager.SetSelector(selector)
				}
				for _, a := range []*auth.Auth{
					{ID: "lite", Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"access_token": "test", "weight": 1}},
					{ID: "pro", Provider: "codex", Status: auth.StatusActive, Disabled: tc.proDisabled, Metadata: map[string]any{"access_token": "test", "weight": tc.proWeight}},
					{ID: "other-provider", Provider: "claude", Status: auth.StatusActive, Metadata: map[string]any{"access_token": "test"}},
					{ID: "api-key", Provider: "codex", Status: auth.StatusActive, Attributes: map[string]string{"api_key": "test"}},
				} {
					if _, err := manager.Register(context.Background(), a); err != nil {
						t.Fatal(err)
					}
				}
				if selector != nil {
					a, _ := manager.GetByID("lite")
					if _, err := selector.Pick(context.Background(), "mixed", "gpt-test", coreexecutor.Options{Headers: http.Header{"Session_id": {"session-a"}}}, []*auth.Auth{a}); err != nil {
						t.Fatal(err)
					}
				}
				if tc.last != "" {
					manager.MarkResult(context.Background(), auth.Result{AuthID: tc.last, Provider: "codex", Model: "gpt-test", Success: true})
				}
				executor := &codexPoolUsageExecutor{payloads: map[string]string{"lite": tc.lite, "pro": tc.pro}, status: map[string]int{"lite": tc.liteStatus}, errors: map[string]error{"lite": tc.liteError}}
				manager.RegisterExecutor(executor)
				before := fallback.calls
				for i := 0; i < 2; i++ {
					executor.authIDs = nil
					req := httptest.NewRequest(http.MethodGet, "/backend-api/wham/usage", nil)
					req.Header.Set("Authorization", "Bearer test-key")
					rr := httptest.NewRecorder()
					server.engine.ServeHTTP(rr, req)
					if rr.Code != tc.wantStatus || (tc.wantBody != "" && rr.Body.String() != tc.wantBody) {
						t.Fatalf("response = %d %s, want %d %s", rr.Code, rr.Body.String(), tc.wantStatus, tc.wantBody)
					}
					if !reflect.DeepEqual(executor.authIDs, tc.wantCalls) {
						t.Fatalf("probed %v, want %v", executor.authIDs, tc.wantCalls)
					}
				}
				if fallback.calls != before {
					t.Fatal("usage advanced inference selection")
				}
				if selector != nil {
					a, binding := manager.LookupSessionAffinity("codex", "gpt-test", "session-a")
					if binding != "bound" || a.ID != "lite" {
						t.Fatal("usage changed affinity")
					}
				}
			})
		}
	}
}

func TestCodexUsageFallbackRecoversOnlyAvailableAccount(t *testing.T) {
	server := newTestServer(t)
	manager := server.handlers.AuthManager
	ctx := context.Background()
	retry := time.Hour
	for _, id := range []string{"pro", "lite"} {
		if _, err := manager.Register(ctx, &auth.Auth{ID: id, Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"access_token": "test", "weight": 1}}); err != nil {
			t.Fatal(err)
		}
		manager.MarkResult(ctx, auth.Result{AuthID: id, Model: "gpt-test", CredentialScope: true, Error: &auth.Error{HTTPStatus: 429}, RetryAfter: &retry})
	}
	executor := &codexPoolUsageExecutor{payloads: map[string]string{"lite": usageExhausted, "pro": usageAvailable}}
	manager.RegisterExecutor(executor)
	req := httptest.NewRequest(http.MethodGet, "/backend-api/wham/usage", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	server.engine.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || rr.Body.String() != usageAvailable {
		t.Fatalf("response = %d %s", rr.Code, rr.Body.String())
	}
	if !reflect.DeepEqual(executor.authIDs, []string{"lite", "pro"}) {
		t.Fatalf("probed %v", executor.authIDs)
	}
	lite, _ := manager.GetByID("lite")
	pro, _ := manager.GetByID("pro")
	if !lite.Quota.Exceeded || pro.Quota.Exceeded {
		t.Fatal("usage recovered the wrong account")
	}
	if manager.CodexUsageCandidates()[0].ID != "lite" {
		t.Fatal("usage fallback replaced the last inference account")
	}
}
