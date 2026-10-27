package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

const codexBackendUpstreamBase = "https://chatgpt.com/backend-api"

// codexBackendPooledPaths lists backend paths handled with pool credentials:
// pool usage reads and session-bound reset credits. Other paths retain caller identity.
var codexBackendPooledPaths = []string{"/wham/usage", "/wham/rate-limit-reset-credits"}

func codexBackendUsesPooledCredential(path string) bool {
	for _, prefix := range codexBackendPooledPaths {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

// codexBackendPassthrough serves chatgpt.com backend endpoints so a Codex client
// can point chatgpt_base_url at the proxy. Usage reads report available pool
// capacity without changing inference routing. Account-scoped endpoints (plugins,
// settings, tasks, profile) are forwarded with the caller's own identity, so the
// client keeps the environment of the account it is signed into.
func (s *Server) codexBackendPassthrough(c *gin.Context) {
	if s == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Codex backend unavailable"})
		return
	}
	path := "/" + strings.Trim(c.Param("segment"), "/") + c.Param("path")
	req := codexBackendStripProxyKey(c)
	if codexBackendUsesPooledCredential(path) {
		s.codexBackendPooledRequest(c, req, path)
		return
	}
	s.codexBackendIdentityProxy().ServeHTTP(c.Writer, req)
}

// codexBackendIdentityHeaders lists the headers Codex's backend client sends to
// chatgpt.com. The identity proxy forwards only these, so a credential that an
// auth provider (config key or plugin) accepted in any other header never
// reaches upstream.
var codexBackendIdentityHeaders = []string{
	"Authorization", "Chatgpt-Account-Id", "User-Agent", "Content-Type", "Accept",
	"Accept-Encoding", "Originator", "Version", "Session_id", "X-Client-Request-Id",
	"X-Openai-Fedramp",
}

// codexBackendStripProxyKey removes the configured proxy key that AuthMiddleware
// matched from the bearer and the query, so it never reaches chatgpt.com or the
// request log. Other header carriers are dropped by the identity allowlist and
// the pooled path's own header rebuild. With no configured keys nothing matched
// and the request is forwarded untouched.
func codexBackendStripProxyKey(c *gin.Context) *http.Request {
	key := c.GetString("userApiKey")
	if key == "" {
		return c.Request
	}
	req := c.Request.Clone(c.Request.Context())
	if bearer := req.Header.Get("Authorization"); len(bearer) > 7 && strings.EqualFold(bearer[:7], "Bearer ") && strings.TrimSpace(bearer[7:]) == key {
		req.Header.Del("Authorization")
	}
	query := req.URL.Query()
	stripped := false
	for _, name := range []string{"key", "auth_token"} {
		if query.Get(name) == key {
			query.Del(name)
			stripped = true
		}
	}
	if stripped {
		req.URL.RawQuery = query.Encode()
	}
	return req
}

// codexBackendIdentityProxy forwards the request with the caller's own
// Authorization and ChatGPT account headers to chatgpt.com, keeping only the
// headers Codex itself sends. It is built per request so a hot-reloaded
// proxy-url takes effect immediately, the same way the Codex executor builds
// its client per request.
func (s *Server) codexBackendIdentityProxy() *httputil.ReverseProxy {
	// The incoming path already carries /backend-api, so rewrite only the origin.
	upstream, _ := url.Parse(strings.TrimSuffix(codexBackendUpstreamBase, "/backend-api"))
	transport := s.codexBackendTransport
	if transport == nil {
		// chatgpt.com rejects Go's default TLS fingerprint on account endpoints
		// (451 no_biscuit_no_service), so reuse the Chrome-profile client the
		// Codex executor already uses; it also honors the configured proxy-url.
		transport = helps.NewUtlsHTTPClient(context.Background(), s.getConfig(), nil, 0).Transport
	}
	return &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.Out.Host = upstream.Host
			pr.Out.Header = make(http.Header, len(codexBackendIdentityHeaders))
			for _, name := range codexBackendIdentityHeaders {
				if values := pr.In.Header.Values(name); len(values) > 0 {
					pr.Out.Header[name] = values
				}
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, errProxy error) {
			log.WithError(errProxy).Warnf("codex backend passthrough: upstream request failed for %s", r.URL.Path)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
}

// codexBackendPooledRequest probes pool usage or forwards account-bound reset-credit operations.
// Usage probes never invoke inference selection or change affinity bindings.
func (s *Server) codexBackendPooledRequest(c *gin.Context, req *http.Request, path string) {
	if s.handlers == nil || s.handlers.AuthManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Codex auth manager unavailable"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 16<<20))
	if err != nil {
		c.JSON(clienterror.HTTPStatusFromErrorOr(err, http.StatusBadRequest), gin.H{"error": "Failed to read Codex backend request"})
		return
	}

	ctx := context.WithValue(c.Request.Context(), "gin", c)
	sessionID := auth.ExtractSessionID(req.Header, body, nil)
	selected, binding := s.handlers.AuthManager.LookupSessionAffinity("codex", "", sessionID)
	poolUsage := req.Method == http.MethodGet && path == "/wham/usage"
	if !poolUsage && (binding != "bound" || selected == nil || selected.Disabled || selected.Status == auth.StatusDisabled || selected.AuthKind() != auth.AuthKindOAuth) {
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			c.Status(http.StatusNoContent)
		} else {
			c.JSON(http.StatusConflict, gin.H{"error": "Codex inference account is not identified"})
		}
		return
	}

	upstreamURL := codexBackendUpstreamBase + path
	if rawQuery := req.URL.RawQuery; rawQuery != "" {
		upstreamURL += "?" + rawQuery
	}
	method := req.Method
	baseHeaders := make(http.Header)
	baseHeaders.Set("Accept", "application/json")
	baseHeaders.Set("Originator", "codex_cli_rs")
	for _, name := range []string{"Content-Type", "Version", "User-Agent", "Session_id", "X-Client-Request-Id"} {
		if value := strings.TrimSpace(req.Header.Get(name)); value != "" {
			baseHeaders.Set(name, value)
		}
	}
	var requestBody []byte
	if len(body) > 0 {
		requestBody = body
	}
	performRequest := func(current *auth.Auth) (*http.Response, error) {
		logging.SetGinCPATraceID(c, current.EnsureIndex())
		headers := baseHeaders.Clone()
		if accountID, ok := current.Metadata["account_id"].(string); ok && strings.TrimSpace(accountID) != "" {
			headers.Set("Chatgpt-Account-Id", accountID)
		}
		req, errRequest := s.handlers.AuthManager.NewHttpRequest(ctx, current, method, upstreamURL, requestBody, headers)
		if errRequest != nil {
			return nil, errRequest
		}
		authType, authValue := current.AccountInfo()
		helps.RecordAPIRequest(ctx, s.getConfig(), helps.UpstreamRequestLog{
			URL:       upstreamURL,
			Method:    method,
			Headers:   req.Header.Clone(),
			Body:      requestBody,
			Provider:  "codex",
			AuthID:    current.ID,
			AuthLabel: current.Label,
			AuthType:  authType,
			AuthValue: authValue,
		})
		return s.handlers.AuthManager.HttpRequest(ctx, current, req)
	}
	if poolUsage {
		candidates := s.handlers.AuthManager.CodexUsageCandidates()
		if len(candidates) == 0 {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "No enabled Codex OAuth accounts with positive weight"})
			return
		}
		request := performRequest
		performRequest = func(_ *auth.Auth) (*http.Response, error) {
			return s.codexBackendPoolUsage(ctx, candidates, request)
		}
	}
	s.relayCodexUpstream(c, ctx, nil, selected, "", "codex backend passthrough", performRequest, nil)
}

// codexBackendPoolUsage returns one upstream snapshot, never a fabricated combined quota.
func (s *Server) codexBackendPoolUsage(ctx context.Context, candidates []*auth.Auth, request func(*auth.Auth) (*http.Response, error)) (*http.Response, error) {
	var exhausted, failed *http.Response
	var probeErr error
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		requestedAt := time.Now()
		resp, err := request(candidate)
		if err != nil {
			probeErr = err
			continue
		}
		body, errRead := io.ReadAll(io.LimitReader(resp.Body, (32<<20)+1))
		if errClose := resp.Body.Close(); errClose != nil {
			log.WithError(errClose).Warn("close Codex usage response")
		}
		if errRead != nil {
			probeErr = errRead
			continue
		}
		if len(body) > 32<<20 {
			probeErr = errors.New("Codex usage response exceeds size limit")
			continue
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		if resp.StatusCode != http.StatusOK {
			if failed == nil {
				failed = resp
			}
			continue
		}
		available, known := auth.CodexUsageAvailability(body)
		if !known {
			probeErr = errors.New("Codex usage response did not establish available quota")
			continue
		}
		if available {
			if errReconcile := s.handlers.AuthManager.ReconcileCodexUsage(ctx, candidate.ID, body, requestedAt); errReconcile != nil {
				log.WithError(errReconcile).Warn("failed to reconcile Codex usage cooldown")
			}
			return resp, nil
		}
		if exhausted == nil {
			exhausted = resp
		}
	}
	if probeErr != nil {
		return nil, probeErr
	}
	if failed != nil {
		return failed, nil
	}
	return exhausted, nil
}
