package auth

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func withQuotaCooldownEnabled(t *testing.T) {
	t.Helper()
	prev := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(prev) })
}

func quotaResult(authID, model string) Result {
	return Result{
		AuthID:   authID,
		Provider: "codex",
		Model:    model,
		Success:  false,
		Error: &Error{
			Code:       "rate_limit",
			Message:    "quota",
			Retryable:  true,
			HTTPStatus: http.StatusTooManyRequests,
		},
	}
}

func TestMarkResultQuotaBackoffEscalatesOncePerWindow(t *testing.T) {
	withQuotaCooldownEnabled(t)

	manager := NewManager(nil, nil, nil)
	auth := &Auth{
		ID:       "auth-quota-window",
		Provider: "codex",
		Metadata: map[string]any{"type": "codex"},
	}
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register returned error: %v", errRegister)
	}

	manager.MarkResult(context.Background(), quotaResult(auth.ID, "gpt-5"))
	first, ok := manager.GetByID(auth.ID)
	if !ok || first == nil || first.ModelStates["gpt-5"] == nil {
		t.Fatalf("expected model state after first failure")
	}
	firstState := first.ModelStates["gpt-5"]
	if firstState.Quota.BackoffLevel != 1 {
		t.Fatalf("expected BackoffLevel 1 after first failure, got %d", firstState.Quota.BackoffLevel)
	}
	if !firstState.Quota.NextRecoverAt.After(time.Now()) {
		t.Fatalf("expected open cooldown window after first failure, got %v", firstState.Quota.NextRecoverAt)
	}

	// A second in-flight failure lands while the first window is still open.
	manager.MarkResult(context.Background(), quotaResult(auth.ID, "gpt-5"))
	second, ok := manager.GetByID(auth.ID)
	if !ok || second == nil || second.ModelStates["gpt-5"] == nil {
		t.Fatalf("expected model state after second failure")
	}
	secondState := second.ModelStates["gpt-5"]
	if secondState.Quota.BackoffLevel != 1 {
		t.Fatalf("expected BackoffLevel to stay 1 for in-window failure, got %d", secondState.Quota.BackoffLevel)
	}
	if !secondState.Quota.NextRecoverAt.Equal(firstState.Quota.NextRecoverAt) {
		t.Fatalf("expected NextRecoverAt to stay %v for in-window failure, got %v", firstState.Quota.NextRecoverAt, secondState.Quota.NextRecoverAt)
	}
	if !secondState.NextRetryAfter.Equal(firstState.NextRetryAfter) {
		t.Fatalf("expected NextRetryAfter to stay %v for in-window failure, got %v", firstState.NextRetryAfter, secondState.NextRetryAfter)
	}
}

func TestMarkResultQuotaBackoffEscalatesAfterWindowExpiry(t *testing.T) {
	withQuotaCooldownEnabled(t)

	expired := time.Now().Add(-time.Second)
	manager := NewManager(nil, nil, nil)
	auth := &Auth{
		ID:       "auth-quota-expired",
		Provider: "codex",
		Metadata: map[string]any{"type": "codex"},
		ModelStates: map[string]*ModelState{
			"gpt-5": {
				Status:         StatusError,
				Unavailable:    true,
				NextRetryAfter: expired,
				Quota:          QuotaState{Exceeded: true, Reason: "quota", NextRecoverAt: expired, BackoffLevel: 3},
			},
		},
	}
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register returned error: %v", errRegister)
	}

	manager.MarkResult(context.Background(), quotaResult(auth.ID, "gpt-5"))
	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil || updated.ModelStates["gpt-5"] == nil {
		t.Fatalf("expected model state after failure")
	}
	state := updated.ModelStates["gpt-5"]
	if state.Quota.BackoffLevel != 4 {
		t.Fatalf("expected BackoffLevel 4 after post-window failure, got %d", state.Quota.BackoffLevel)
	}
	if !state.Quota.NextRecoverAt.After(time.Now()) {
		t.Fatalf("expected a fresh cooldown window, got %v", state.Quota.NextRecoverAt)
	}
}

func TestApplyAuthFailureStateQuotaBackoffOncePerWindow(t *testing.T) {
	now := time.Now()
	quotaErr := &Error{Code: "rate_limit", Message: "quota", HTTPStatus: http.StatusTooManyRequests}
	auth := &Auth{ID: "auth-level-quota"}

	applyAuthFailureState(auth, quotaErr, nil, now, false)
	if auth.Quota.BackoffLevel != 1 {
		t.Fatalf("expected BackoffLevel 1 after first failure, got %d", auth.Quota.BackoffLevel)
	}
	firstRecover := auth.Quota.NextRecoverAt
	if !firstRecover.Equal(now.Add(time.Second)) {
		t.Fatalf("expected first window to close at %v, got %v", now.Add(time.Second), firstRecover)
	}

	// In-window failure keeps the current window and level.
	applyAuthFailureState(auth, quotaErr, nil, now.Add(100*time.Millisecond), false)
	if auth.Quota.BackoffLevel != 1 {
		t.Fatalf("expected BackoffLevel to stay 1 for in-window failure, got %d", auth.Quota.BackoffLevel)
	}
	if !auth.Quota.NextRecoverAt.Equal(firstRecover) {
		t.Fatalf("expected NextRecoverAt to stay %v for in-window failure, got %v", firstRecover, auth.Quota.NextRecoverAt)
	}

	// A failure after the window expired escalates to the next level.
	applyAuthFailureState(auth, quotaErr, nil, now.Add(2*time.Second), false)
	if auth.Quota.BackoffLevel != 2 {
		t.Fatalf("expected BackoffLevel 2 after post-window failure, got %d", auth.Quota.BackoffLevel)
	}
	if !auth.Quota.NextRecoverAt.Equal(now.Add(4 * time.Second)) {
		t.Fatalf("expected second window to close at %v, got %v", now.Add(4*time.Second), auth.Quota.NextRecoverAt)
	}

	// A provider supplied retry hint always takes effect, even in-window.
	retryAfter := 10 * time.Second
	applyAuthFailureState(auth, quotaErr, &retryAfter, now.Add(3*time.Second), false)
	if auth.Quota.BackoffLevel != 2 {
		t.Fatalf("expected BackoffLevel to stay 2 with retry hint, got %d", auth.Quota.BackoffLevel)
	}
	if !auth.Quota.NextRecoverAt.Equal(now.Add(13 * time.Second)) {
		t.Fatalf("expected retry hint window to close at %v, got %v", now.Add(13*time.Second), auth.Quota.NextRecoverAt)
	}
}

func TestJitteredCooldownWaitBounds(t *testing.T) {
	cases := []struct {
		wait      time.Duration
		maxWait   time.Duration
		maxJitter time.Duration
	}{
		{time.Second, 0, 250 * time.Millisecond},
		{8 * time.Second, 0, 2 * time.Second},
		{30 * time.Second, 0, 2 * time.Second},
		{time.Second, 30 * time.Second, 250 * time.Millisecond},
		{29 * time.Second, 30 * time.Second, time.Second},
	}
	for _, tc := range cases {
		for i := 0; i < 200; i++ {
			got := jitteredCooldownWait(tc.wait, tc.maxWait)
			if got < tc.wait || got >= tc.wait+tc.maxJitter {
				t.Fatalf("jitteredCooldownWait(%v, %v) = %v, want in [%v, %v)", tc.wait, tc.maxWait, got, tc.wait, tc.wait+tc.maxJitter)
			}
			if tc.maxWait > 0 && got > tc.maxWait {
				t.Fatalf("jitteredCooldownWait(%v, %v) = %v exceeds maxWait", tc.wait, tc.maxWait, got)
			}
		}
	}

	// maxWait is a hard ceiling: zero headroom disables jitter entirely.
	for i := 0; i < 50; i++ {
		if got := jitteredCooldownWait(30*time.Second, 30*time.Second); got != 30*time.Second {
			t.Fatalf("expected wait at maxWait to stay unjittered, got %v", got)
		}
	}

	if got := jitteredCooldownWait(0, time.Minute); got != 0 {
		t.Fatalf("expected zero wait to stay zero, got %v", got)
	}
	if got := jitteredCooldownWait(-time.Second, time.Minute); got != -time.Second {
		t.Fatalf("expected negative wait to pass through, got %v", got)
	}
	if got := jitteredCooldownWait(3, 0); got != 3 {
		t.Fatalf("expected sub-4ns wait to stay unchanged, got %v", got)
	}
}

func TestMarkResult_FreeUsageExhaustedUsesLongCooldown(t *testing.T) {
	withQuotaCooldownEnabled(t)
	m := NewManager(nil, nil, nil)
	auth := &Auth{ID: "auth-free", Provider: "xai", Status: StatusActive}
	if _, err := m.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	msg := `{"code":"subscription:free-usage-exhausted","error":"You've used all the included free usage for model grok-4.5-build-free for now. Usage resets over a rolling 24-hour window."}`
	m.MarkResult(context.Background(), Result{
		AuthID:  auth.ID,
		Model:   "grok-4.5",
		Success: false,
		Error:   &Error{HTTPStatus: http.StatusTooManyRequests, Message: msg},
	})

	updated, ok := m.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatal("auth not found after MarkResult")
	}
	state := updated.ModelStates["grok-4.5"]
	if state == nil {
		t.Fatal("model state missing")
	}
	if !state.Quota.Exceeded {
		t.Fatal("expected quota exceeded")
	}
	if state.Quota.Reason != "free_usage_exhausted" {
		t.Fatalf("Quota.Reason = %q, want free_usage_exhausted", state.Quota.Reason)
	}
	remaining := time.Until(state.NextRetryAfter)
	if remaining < 22*time.Hour || remaining > 24*time.Hour {
		t.Fatalf("NextRetryAfter remaining = %v, want ~23h", remaining)
	}

	// Selector must skip the exhausted credential until the long window ends.
	selector := &RoundRobinSelector{}
	if _, err := selector.Pick(context.Background(), "xai", "grok-4.5", cliproxyexecutor.Options{}, []*Auth{updated}); err == nil {
		t.Fatal("expected exhausted auth to be blocked by selector")
	}
}

func TestMarkResult_FreeUsageExhaustedWithRetryAfter(t *testing.T) {
	withQuotaCooldownEnabled(t)
	m := NewManager(nil, nil, nil)
	auth := &Auth{ID: "auth-free-retry", Provider: "xai", Status: StatusActive}
	if _, err := m.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	retryAfter := 23 * time.Hour
	m.MarkResult(context.Background(), Result{
		AuthID:     auth.ID,
		Model:      "grok-4.5",
		Success:    false,
		RetryAfter: &retryAfter,
		Error:      &Error{HTTPStatus: http.StatusTooManyRequests, Message: "subscription:free-usage-exhausted"},
	})
	updated, ok := m.GetByID(auth.ID)
	if !ok {
		t.Fatal("auth not found")
	}
	state := updated.ModelStates["grok-4.5"]
	if state == nil {
		t.Fatal("model state missing")
	}
	remaining := time.Until(state.NextRetryAfter)
	if remaining < 22*time.Hour || remaining > 24*time.Hour {
		t.Fatalf("NextRetryAfter remaining = %v, want ~23h", remaining)
	}
}

func TestMarkResult_CapturesFreeUsageFromHeaders(t *testing.T) {
	withQuotaCooldownEnabled(t)
	m := NewManager(nil, nil, nil)
	auth := &Auth{ID: "auth-free-headers", Provider: "xai", Status: StatusActive}
	if _, err := m.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	headers := http.Header{}
	headers.Set("x-ratelimit-limit-tokens", "2000000")
	headers.Set("x-ratelimit-remaining-tokens", "1500000")
	headers.Set("x-ratelimit-limit-requests", "21")
	headers.Set("x-ratelimit-remaining-requests", "20")
	m.MarkResult(context.Background(), Result{
		AuthID:  auth.ID,
		Model:   "grok-4.5",
		Success: true,
		Headers: headers,
	})
	updated, ok := m.GetByID(auth.ID)
	if !ok || updated == nil || updated.FreeUsage == nil {
		t.Fatal("expected free usage snapshot")
	}
	if updated.FreeUsage.LimitTokens != 2000000 {
		t.Fatalf("LimitTokens = %d, want 2000000", updated.FreeUsage.LimitTokens)
	}
	if updated.FreeUsage.UsedTokens != 500000 {
		t.Fatalf("UsedTokens = %d, want 500000", updated.FreeUsage.UsedTokens)
	}
	if updated.FreeUsage.RemainingTokens == nil || *updated.FreeUsage.RemainingTokens != 1500000 {
		t.Fatalf("RemainingTokens = %v, want 1500000", updated.FreeUsage.RemainingTokens)
	}
	if updated.FreeUsage.Window != "rolling_24h" {
		t.Fatalf("Window = %q, want rolling_24h", updated.FreeUsage.Window)
	}
}

func TestMarkResult_SyncsFreeUsageIntoMetadata(t *testing.T) {
	withQuotaCooldownEnabled(t)
	m := NewManager(nil, nil, nil)
	auth := &Auth{
		ID:       "auth-free-meta",
		Provider: "xai",
		Status:   StatusActive,
		Metadata: map[string]any{"type": "xai", "email": "free@example.com"},
	}
	if _, err := m.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	headers := http.Header{}
	headers.Set("x-ratelimit-limit-tokens", "2000000")
	headers.Set("x-ratelimit-remaining-tokens", "1500000")
	m.MarkResult(context.Background(), Result{
		AuthID:  auth.ID,
		Model:   "grok-4.5",
		Success: true,
		Headers: headers,
	})
	updated, ok := m.GetByID(auth.ID)
	if !ok || updated == nil || updated.FreeUsage == nil {
		t.Fatal("expected free usage snapshot")
	}
	raw, ok := updated.Metadata["free_usage"]
	if !ok || raw == nil {
		t.Fatal("expected free_usage in metadata")
	}
	hydrated := &Auth{Metadata: updated.Metadata}
	ApplyFreeUsageFromMetadata(hydrated)
	if hydrated.FreeUsage == nil || hydrated.FreeUsage.LimitTokens != 2000000 {
		t.Fatalf("hydrated free usage = %+v", hydrated.FreeUsage)
	}
}

func TestMarkResult_CapturesFreeUsageFromErrorBody(t *testing.T) {
	withQuotaCooldownEnabled(t)
	m := NewManager(nil, nil, nil)
	auth := &Auth{ID: "auth-free-error", Provider: "xai", Status: StatusActive}
	if _, err := m.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	msg := `{"code":"subscription:free-usage-exhausted","error":"You've used all the included free usage for model grok-4.5-build-free for now. Usage resets over a rolling 24-hour window — tokens (actual/limit): 1035914/1000000."}`
	m.MarkResult(context.Background(), Result{
		AuthID:  auth.ID,
		Model:   "grok-4.5",
		Success: false,
		Error:   &Error{HTTPStatus: http.StatusTooManyRequests, Message: msg},
	})
	updated, ok := m.GetByID(auth.ID)
	if !ok || updated == nil || updated.FreeUsage == nil {
		t.Fatal("expected free usage snapshot from error")
	}
	if !updated.FreeUsage.Exhausted {
		t.Fatal("expected exhausted=true")
	}
	if updated.FreeUsage.UsedTokens != 1035914 || updated.FreeUsage.LimitTokens != 1000000 {
		t.Fatalf("used/limit = %d/%d", updated.FreeUsage.UsedTokens, updated.FreeUsage.LimitTokens)
	}
	if !strings.Contains(updated.FreeUsage.Message, "tokens (actual/limit): 1035914/1000000") {
		t.Fatalf("Message = %q, want official free-usage text", updated.FreeUsage.Message)
	}
	if !strings.Contains(updated.StatusMessage, "tokens (actual/limit): 1035914/1000000") {
		t.Fatalf("StatusMessage = %q, want official free-usage text", updated.StatusMessage)
	}
}
