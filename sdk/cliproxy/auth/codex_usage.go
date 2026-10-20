package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type codexUsageWindow struct {
	UsedPercent *float64 `json:"used_percent"`
}

type codexUsageLimit struct {
	Allowed      *bool             `json:"allowed"`
	LimitReached *bool             `json:"limit_reached"`
	Primary      *codexUsageWindow `json:"primary_window"`
	Secondary    *codexUsageWindow `json:"secondary_window"`
}

func (limit codexUsageLimit) available() bool {
	if limit.Allowed == nil || !*limit.Allowed || limit.LimitReached == nil || *limit.LimitReached {
		return false
	}
	for _, window := range []*codexUsageWindow{limit.Primary, limit.Secondary} {
		if window != nil && (window.UsedPercent == nil || *window.UsedPercent < 0 || *window.UsedPercent >= 100) {
			return false
		}
	}
	return true
}

// ReconcileCodexUsage clears older quota failures only when a complete usage
// response explicitly permits requests across the reported inference limits.
func (m *Manager) ReconcileCodexUsage(ctx context.Context, authID string, payload []byte, requestedAt time.Time) error {
	var usage struct {
		RateLimit  codexUsageLimit `json:"rate_limit"`
		Additional []struct {
			RateLimit codexUsageLimit `json:"rate_limit"`
		} `json:"additional_rate_limits"`
	}
	if requestedAt.IsZero() || json.Unmarshal(payload, &usage) != nil || !usage.RateLimit.available() {
		return nil
	}
	for _, additional := range usage.Additional {
		if !additional.RateLimit.available() {
			return nil
		}
	}
	_, _, errReset := m.resetQuota(ctx, authID, requestedAt)
	return errReset
}

func clearRecoveredCodexQuota(auth *Auth, before, now time.Time) ([]string, bool) {
	if auth == nil || !strings.EqualFold(auth.Provider, "codex") || auth.Disabled || auth.Status == StatusDisabled {
		return nil, false
	}
	models := make([]string, 0)
	changed := false
	if recoverableCodexQuota(auth.Quota, auth.LastError, auth.UpdatedAt, before) {
		clearAuthStateOnSuccess(auth, now)
		changed = true
	}
	for model, state := range auth.ModelStates {
		if state == nil || state.Status == StatusDisabled {
			continue
		}
		wrapped := state.credentialQuotaPropagated || state.Quota.Reason == "credential_quota"
		if wrapped && recoverableCodexQuota(state.Quota, nil, state.UpdatedAt, before) {
			restoreModelStateAfterCredentialQuota(state, now)
		} else if recoverableCodexQuota(state.Quota, state.LastError, state.UpdatedAt, before) {
			resetModelState(state, now)
		} else {
			continue
		}
		models = append(models, model)
		changed = true
	}
	if changed && len(auth.ModelStates) > 0 {
		updateAggregatedAvailability(auth, now)
	}
	return models, changed
}

func recoverableCodexQuota(quota QuotaState, lastError *Error, updatedAt, before time.Time) bool {
	// Auth reloads preserve credential quota locks without preserving LastError.
	return quota.Exceeded && (quota.Reason == "quota" || quota.Reason == "credential_quota") &&
		(lastError == nil || lastError.HTTPStatus == http.StatusTooManyRequests) && !updatedAt.After(before)
}
