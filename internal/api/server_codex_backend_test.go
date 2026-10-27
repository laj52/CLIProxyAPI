package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	proxyconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executionregistry"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type codexUsageCountingSelector struct{ calls int }

func (s *codexUsageCountingSelector) Pick(_ context.Context, _, _ string, _ coreexecutor.Options, candidates []*auth.Auth) (*auth.Auth, error) {
	s.calls++
	return candidates[0], nil
}

func TestCodexResetCreditsOnlyObservesInferenceAccount(t *testing.T) {
	for _, mode := range []string{"bound", "missing session", "unbound", "ambiguous", "quota exhausted"} {
		t.Run(mode, func(t *testing.T) {
			server := newTestServer(t)
			manager := server.handlers.AuthManager
			fallback := &codexUsageCountingSelector{}
			selector := auth.NewSessionAffinitySelector(fallback)
			t.Cleanup(selector.Stop)
			manager.SetSelector(selector)
			executor := &codexSearchCaptureExecutor{}
			manager.RegisterExecutor(executor)
			accounts := make([]*auth.Auth, 0, 2)
			for _, id := range []string{"pro", "lite"} {
				a, err := manager.Register(context.Background(), &auth.Auth{ID: id, Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"access_token": "test-token", "weight": 1}})
				if err != nil {
					t.Fatal(err)
				}
				accounts = append(accounts, a)
			}
			if mode != "unbound" {
				_, err := selector.Pick(context.Background(), "mixed", "gpt-test", coreexecutor.Options{Headers: http.Header{"Session_id": []string{"session-a"}}}, accounts[:1])
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "ambiguous" {
				_, err := selector.Pick(context.Background(), "mixed", "other-model", coreexecutor.Options{Headers: http.Header{"Session_id": []string{"session-a"}}}, accounts[1:])
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "quota exhausted" {
				cooldown := time.Hour
				manager.MarkResult(context.Background(), auth.Result{AuthID: "pro", Provider: "codex", Model: "gpt-test", CredentialScope: true, Error: &auth.Error{HTTPStatus: 429}, RetryAfter: &cooldown})
				// A quota read must remain possible for an existing binding, even when inference is exhausted.
				_, err := selector.Pick(context.Background(), "mixed", "gpt-test", coreexecutor.Options{Headers: http.Header{"Session_id": []string{"session-a"}}}, accounts[:1])
				if err != nil {
					t.Fatal(err)
				}
			}
			before := fallback.calls
			for i := 0; i < 4; i++ {
				req := httptest.NewRequest(http.MethodGet, "/backend-api/wham/rate-limit-reset-credits", nil)
				req.Header.Set("Authorization", "Bearer test-key")
				if mode != "missing session" {
					req.Header.Set("Session_id", "session-a")
				}
				rr := httptest.NewRecorder()
				server.engine.ServeHTTP(rr, req)
				want := http.StatusNoContent
				if mode == "bound" || mode == "quota exhausted" {
					want = http.StatusOK
				}
				if rr.Code != want {
					t.Fatalf("status = %d, want %d", rr.Code, want)
				}
			}
			if fallback.calls != before {
				t.Fatalf("usage selected accounts %d times", fallback.calls-before)
			}
			for _, id := range executor.authIDs {
				if id != "pro" {
					t.Fatalf("usage read another account: %s", id)
				}
			}
			if mode != "bound" && mode != "quota exhausted" && executor.httpCalls != 0 {
				t.Fatal("unidentified usage reached upstream")
			}
		})
	}
}

func TestCodexUsageRecoversQuotaCooldown(t *testing.T) {
	const recovered = `{"rate_limit":{"allowed":true,"limit_reached":false,"primary_window":{"used_percent":12},"secondary_window":null}}`
	for _, tc := range []struct {
		name, path, body                 string
		status                           int
		concurrentFailure, wantRecovered bool
		reload                           bool
		priorFailure                     bool
	}{
		{name: "recovered", body: recovered, wantRecovered: true},
		{name: "recovered after weight reload", body: recovered, reload: true, wantRecovered: true},
		{name: "recovered with earlier model failure", body: recovered, reload: true, priorFailure: true, wantRecovered: true},
		{name: "exhausted after weight reload", body: `{"rate_limit":{"allowed":false,"limit_reached":true}}`, reload: true},
		{name: "newer failure after weight reload", body: recovered, reload: true, concurrentFailure: true},
		{name: "still exhausted", body: `{"rate_limit":{"allowed":false,"limit_reached":true}}`},
		{name: "weekly exhausted", body: `{"rate_limit":{"allowed":true,"limit_reached":false,"secondary_window":{"used_percent":100}}}`},
		{name: "additional exhausted", body: `{"rate_limit":{"allowed":true,"limit_reached":false},"additional_rate_limits":[{"rate_limit":{"allowed":false,"limit_reached":true}}]}`},
		{name: "missing limits", body: `{}`},
		{name: "malformed", body: `{"rate_limit":`},
		{name: "failed response", body: recovered, status: http.StatusBadGateway},
		{name: "other endpoint", path: "/backend-api/wham/rate-limit-reset-credits", body: recovered},
		{name: "newer failure", body: recovered, concurrentFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newTestServer(t)
			manager := server.handlers.AuthManager
			selector := auth.NewSessionAffinitySelector(&auth.WeightedRoundRobinSelector{})
			t.Cleanup(selector.Stop)
			manager.SetSelector(selector)
			executor := &codexSearchCaptureExecutor{responseBody: io.NopCloser(strings.NewReader(tc.body)), statuses: []int{tc.status}}
			manager.RegisterExecutor(executor)
			const model = "usage-recovery-model"
			for id, weight := range map[string]int{"usage-account-a": 0, "usage-account-b": 1} {
				if tc.reload {
					weight = 0
				}
				_, err := manager.Register(context.Background(), &auth.Auth{ID: id, Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"access_token": "pooled-token", "weight": weight}})
				if err != nil {
					t.Fatal(err)
				}
				registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
			}
			bound, _ := manager.GetByID("usage-account-b")
			bound.Metadata["weight"] = 1
			bound.Attributes = nil
			if _, err := selector.Pick(context.Background(), "mixed", model, coreexecutor.Options{Headers: http.Header{"Session_id": []string{"usage-recovery-session"}}}, []*auth.Auth{bound}); err != nil {
				t.Fatal(err)
			}
			fail := func(id, model string, status int) {
				retry := 72 * time.Hour
				manager.MarkResult(context.Background(), auth.Result{AuthID: id, Provider: "codex", Model: model, Error: &auth.Error{HTTPStatus: status, Message: `{"error":{"type":"usage_limit_reached"}}`}, RetryAfter: &retry, CredentialScope: tc.reload && status == http.StatusTooManyRequests})
			}
			fail("usage-account-a", model, http.StatusTooManyRequests)
			if tc.priorFailure {
				fail("usage-account-b", "unrelated-model", http.StatusForbidden)
			}
			fail("usage-account-b", model, http.StatusTooManyRequests)
			if !tc.priorFailure {
				fail("usage-account-b", "unrelated-model", http.StatusForbidden)
			}
			if tc.reload {
				reloaded, err := manager.Update(context.Background(), &auth.Auth{ID: "usage-account-b", Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"access_token": "pooled-token", "weight": 1}})
				if err != nil {
					t.Fatal(err)
				}
				if !reloaded.Quota.Exceeded || reloaded.LastError != nil {
					t.Fatal("reload did not preserve the quota lock without error metadata")
				}
			}
			if tc.concurrentFailure {
				executor.beforeReturn = func() { fail("usage-account-b", model, http.StatusTooManyRequests) }
			}
			path := tc.path
			if path == "" {
				path = "/backend-api/wham/usage"
			}
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("Authorization", "Bearer test-key")
			req.Header.Set("Session_id", "usage-recovery-session")
			rr := httptest.NewRecorder()
			server.engine.ServeHTTP(rr, req)
			if path != "/backend-api/wham/usage" {
				b, _ := manager.GetByID("usage-account-b")
				if !b.ModelStates[model].Quota.Exceeded {
					t.Fatal("unrelated endpoint cleared quota")
				}
				return
			}
			wantStatus := tc.status
			if wantStatus == 0 {
				wantStatus = http.StatusOK
			}
			unknown := tc.name == "missing limits" || tc.name == "malformed"
			if unknown {
				wantStatus = http.StatusBadGateway
			}
			if rr.Code != wantStatus || (!unknown && rr.Body.String() != tc.body) {
				t.Fatalf("usage response = %d %s", rr.Code, rr.Body.String())
			}
			if len(executor.authIDs) != 1 || executor.authIDs[0] != "usage-account-b" {
				t.Fatalf("selected accounts = %v", executor.authIDs)
			}
			b, _ := manager.GetByID("usage-account-b")
			if got := !b.ModelStates[model].Quota.Exceeded; got != tc.wantRecovered {
				t.Fatalf("quota recovered = %v, want %v", got, tc.wantRecovered)
			}
			if tc.reload && !b.Quota.Exceeded != tc.wantRecovered {
				t.Fatalf("credential quota recovered = %v, want %v", !b.Quota.Exceeded, tc.wantRecovered)
			}
			unrelated := b.ModelStates["unrelated-model"]
			if unrelated.LastError == nil || unrelated.LastError.HTTPStatus != http.StatusForbidden {
				t.Fatal("unrelated error cleared")
			}
			if tc.wantRecovered && (unrelated.Quota.Exceeded || !unrelated.Unavailable || !unrelated.NextRetryAfter.After(time.Now())) {
				t.Fatal("quota recovery did not preserve the independent forbidden cooldown")
			}
			a, _ := manager.GetByID("usage-account-a")
			if !a.ModelStates[model].Quota.Exceeded {
				t.Fatal("other account quota cleared")
			}
			if tc.wantRecovered {
				selected, err := manager.SelectAuth(context.Background(), "codex", model, coreexecutor.Options{})
				if err != nil || selected.ID != "usage-account-b" {
					t.Fatalf("generation selection after usage = %v, %v", selected, err)
				}
				registry.GetGlobalRegistry().UnregisterClient("usage-account-a")
				if count := registry.GetGlobalRegistry().GetModelCount(model); count != 1 {
					t.Fatalf("registry model count = %d, want 1", count)
				}
			}
		})
	}
}

func TestCodexBackendPassthroughForwardsUsageWithPooledOAuthCredential(t *testing.T) {
	server := newTestServer(t)
	executor := &codexSearchCaptureExecutor{responseBody: io.NopCloser(strings.NewReader(usageAvailable))}
	server.handlers.AuthManager.RegisterExecutor(executor)
	credential := &auth.Auth{
		ID:       "codex-oauth",
		Provider: "codex",
		Status:   auth.StatusActive,
		Metadata: map[string]any{
			"access_token": "pooled-token",
			"account_id":   "acct-pooled",
		},
	}
	if _, errRegister := server.handlers.AuthManager.Register(context.Background(), credential); errRegister != nil {
		t.Fatalf("register Codex OAuth credential: %v", errRegister)
	}
	selector := auth.NewSessionAffinitySelector(nil)
	t.Cleanup(selector.Stop)
	server.handlers.AuthManager.SetSelector(selector)
	if _, err := selector.Pick(context.Background(), "mixed", "gpt-test", coreexecutor.Options{Headers: http.Header{"Session_id": []string{"usage-session"}}}, []*auth.Auth{credential}); err != nil {
		t.Fatal(err)
	}

	// The proxy key rides in the query here so the test also proves it is stripped
	// from the pooled upstream URL while functional parameters survive.
	req := httptest.NewRequest(http.MethodGet, "/backend-api/wham/usage?key=test-key&supports_luna_reserve=true", nil)
	req.Header.Set("Session_id", "usage-session")
	req.Header.Set("Chatgpt-Account-Id", "acct-client")
	rr := httptest.NewRecorder()
	server.engine.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if executor.request == nil {
		t.Fatal("Codex executor did not receive a request")
	}
	if got, want := executor.request.URL.String(), "https://chatgpt.com/backend-api/wham/usage?supports_luna_reserve=true"; got != want {
		t.Fatalf("upstream URL = %q, want %q", got, want)
	}
	if got := executor.request.Method; got != http.MethodGet {
		t.Fatalf("upstream method = %q, want GET", got)
	}
	if got := executor.request.Header.Get("Authorization"); got != "Bearer pooled-token" {
		t.Fatalf("Authorization = %q, want pooled credential bearer", got)
	}
	if got := executor.request.Header.Get("Chatgpt-Account-Id"); got != "acct-pooled" {
		t.Fatalf("Chatgpt-Account-Id = %q, want pooled account", got)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want upstream content type", got)
	}
}

func TestCodexBackendPassthroughRejectsAPIKeyCredentials(t *testing.T) {
	server := newTestServer(t)
	executor := &codexSearchCaptureExecutor{}
	server.handlers.AuthManager.RegisterExecutor(executor)
	credential := &auth.Auth{
		ID:       "codex-api-key",
		Provider: "codex",
		Status:   auth.StatusActive,
		Attributes: map[string]string{
			auth.AttributeAPIKey:           "codex-key",
			auth.AttributeCodexAlphaSearch: "true",
		},
	}
	if _, errRegister := server.handlers.AuthManager.Register(context.Background(), credential); errRegister != nil {
		t.Fatalf("register Codex API key: %v", errRegister)
	}

	req := httptest.NewRequest(http.MethodGet, "/backend-api/wham/usage", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	server.engine.ServeHTTP(rr, req)

	if rr.Code == http.StatusOK {
		t.Fatalf("status = %d, want a selection failure; body=%s", rr.Code, rr.Body.String())
	}
	if executor.httpCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0 for API key credential", executor.httpCalls)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// closeNotifyRecorder satisfies the CloseNotifier assertion httputil.ReverseProxy
// makes through Gin's response writer.
type closeNotifyRecorder struct{ *httptest.ResponseRecorder }

func (closeNotifyRecorder) CloseNotify() <-chan bool { return make(chan bool) }

func TestCodexBackendPassthroughForwardsAccountScopedCallsWithCallerIdentity(t *testing.T) {
	server := newTestServer(t)
	var upstream *http.Request
	server.codexBackendTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstream = req.Clone(req.Context())
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"plugins":[]}`)),
			Request:    req,
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/backend-api/ps/plugins/installed?limit=200", nil)
	req.Header.Set("X-Api-Key", "test-key")
	req.Header.Set("Authorization", "Bearer chatgpt-token")
	req.Header.Set("Chatgpt-Account-Id", "acct-client")
	req.Header.Set("X-Plugin-Token", "plugin-secret")
	rr := httptest.NewRecorder()
	server.engine.ServeHTTP(closeNotifyRecorder{rr}, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if upstream == nil {
		t.Fatal("identity passthrough did not reach the upstream transport")
	}
	if got, want := upstream.URL.String(), "https://chatgpt.com/backend-api/ps/plugins/installed?limit=200"; got != want {
		t.Fatalf("upstream URL = %q, want %q", got, want)
	}
	if got := upstream.Host; got != "chatgpt.com" {
		t.Fatalf("upstream Host = %q, want chatgpt.com", got)
	}
	if got := upstream.Header.Get("Authorization"); got != "Bearer chatgpt-token" {
		t.Fatalf("Authorization = %q, want the caller's own ChatGPT bearer", got)
	}
	for _, name := range []string{"X-Api-Key", "X-Plugin-Token"} {
		if got := upstream.Header.Get(name); got != "" {
			t.Fatalf("%s = %q, want credential headers outside the Codex allowlist dropped", name, got)
		}
	}
	if got := upstream.Header.Get("Chatgpt-Account-Id"); got != "acct-client" {
		t.Fatalf("Chatgpt-Account-Id = %q, want the caller's own account", got)
	}
	if got := rr.Body.String(); got != `{"plugins":[]}` {
		t.Fatalf("body = %q, want upstream body relayed", got)
	}
}

func TestCodexBackendPassthroughNeverForwardsProxyKey(t *testing.T) {
	for name, apply := range map[string]func(*http.Request){
		"authorization":    func(r *http.Request) { r.Header.Set("Authorization", "bearer test-key") },
		"x-goog-api-key":   func(r *http.Request) { r.Header.Set("X-Goog-Api-Key", "test-key") },
		"query key":        func(r *http.Request) { r.URL.RawQuery = "key=test-key&limit=1" },
		"query auth_token": func(r *http.Request) { r.URL.RawQuery = "auth_token=test-key" },
	} {
		t.Run(name, func(t *testing.T) {
			server := newTestServer(t)
			var upstream *http.Request
			server.codexBackendTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				upstream = req.Clone(req.Context())
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}")), Request: req}, nil
			})

			req := httptest.NewRequest(http.MethodGet, "/backend-api/settings/user", nil)
			apply(req)
			server.engine.ServeHTTP(closeNotifyRecorder{httptest.NewRecorder()}, req)

			if upstream == nil {
				t.Fatal("identity passthrough did not reach the upstream transport")
			}
			if dump, _ := httputil.DumpRequestOut(upstream, false); strings.Contains(string(dump), "test-key") || strings.Contains(upstream.URL.String(), "test-key") {
				t.Fatalf("proxy key reached upstream: %s %s", upstream.URL.String(), dump)
			}
		})
	}
}

// codexBackendHomeDispatcher records the model the Home dispatch receives.
type codexBackendHomeDispatcher struct {
	*codexSearchHomeDispatcher
	model atomic.Value
}

func (d *codexBackendHomeDispatcher) RPopAuthWithPolicy(ctx context.Context, model string, sessionID string, headers http.Header, count int, policy string) ([]byte, error) {
	d.model.Store(model)
	return d.codexSearchHomeDispatcher.RPopAuthWithPolicy(ctx, model, sessionID, headers, count, policy)
}

func TestCodexBackendUsageDoesNotSelectHomeAccount(t *testing.T) {
	server := newTestServer(t)
	dispatcher := &codexBackendHomeDispatcher{codexSearchHomeDispatcher: &codexSearchHomeDispatcher{}}
	server.handlers.AuthManager.SetConfig(&proxyconfig.Config{Home: proxyconfig.HomeConfig{Enabled: true}})
	server.handlers.AuthManager.PublishHomeDispatch(dispatcher, executionregistry.New(), 1)
	executor := &codexSearchCaptureExecutor{}
	server.handlers.AuthManager.RegisterExecutor(executor)

	req := httptest.NewRequest(http.MethodGet, "/backend-api/wham/usage", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	server.engine.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusServiceUnavailable, rr.Body.String())
	}
	if got := dispatcher.model.Load(); got != nil {
		t.Fatalf("usage dispatched a Home account with model %v", got)
	}
	if executor.httpCalls != 0 {
		t.Fatal("usage without a binding reached upstream")
	}
}

func TestCodexBackendIdentityProxyFollowsConfigReload(t *testing.T) {
	server := newTestServer(t)
	before := server.codexBackendIdentityProxy().Transport

	reloaded := *server.cfg
	reloaded.ProxyURL = "socks5://127.0.0.1:1"
	server.cfg = &reloaded

	if after := server.codexBackendIdentityProxy().Transport; after == before {
		t.Fatal("identity proxy reused the transport built before the config reload")
	}
}
