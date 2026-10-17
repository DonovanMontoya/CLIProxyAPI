package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	internallogging "github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestCodexQuotaReserveHit(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	weeklyReset := strconv.FormatInt(now.Add(72*time.Hour).Unix(), 10)
	shortReset := strconv.FormatInt(now.Add(2*time.Hour).Unix(), 10)

	tests := []struct {
		name       string
		signals    map[string]string
		reserve    float64
		wantHit    bool
		wantReset  time.Time
		wantWindow int
	}{
		{
			name: "weekly-only plan above reserve",
			signals: map[string]string{
				"X-Codex-Primary-Used-Percent":   "88",
				"X-Codex-Primary-Window-Minutes": "10080",
				"X-Codex-Primary-Reset-At":       weeklyReset,
			},
			reserve: 11,
		},
		{
			name: "weekly-only plan at reserve",
			signals: map[string]string{
				"X-Codex-Primary-Used-Percent":   "89",
				"X-Codex-Primary-Window-Minutes": "10080",
				"X-Codex-Primary-Reset-At":       weeklyReset,
			},
			reserve:    11,
			wantHit:    true,
			wantReset:  now.Add(72 * time.Hour),
			wantWindow: 10080,
		},
		{
			name: "both windows tripped waits for the later reset",
			signals: map[string]string{
				"X-Codex-Primary-Used-Percent":     "95",
				"X-Codex-Primary-Window-Minutes":   "300",
				"X-Codex-Primary-Reset-At":         shortReset,
				"X-Codex-Secondary-Used-Percent":   "90",
				"X-Codex-Secondary-Window-Minutes": "10080",
				"X-Codex-Secondary-Reset-At":       weeklyReset,
			},
			reserve:    11,
			wantHit:    true,
			wantReset:  now.Add(72 * time.Hour),
			wantWindow: 10080,
		},
		{
			name: "only the 5h window tripped",
			signals: map[string]string{
				"X-Codex-Primary-Used-Percent":        "95",
				"X-Codex-Primary-Window-Minutes":      "300",
				"X-Codex-Primary-Reset-After-Seconds": "7200",
				"X-Codex-Secondary-Used-Percent":      "40",
				"X-Codex-Secondary-Window-Minutes":    "10080",
				"X-Codex-Secondary-Reset-At":          weeklyReset,
			},
			reserve:    11,
			wantHit:    true,
			wantReset:  now.Add(2 * time.Hour),
			wantWindow: 300,
		},
		{
			name: "window that already reset is stale",
			signals: map[string]string{
				"X-Codex-Primary-Used-Percent":   "99",
				"X-Codex-Primary-Window-Minutes": "10080",
				"X-Codex-Primary-Reset-At":       strconv.FormatInt(now.Add(-time.Minute).Unix(), 10),
			},
			reserve: 11,
		},
		{
			name: "additional model limits are ignored",
			signals: map[string]string{
				"X-Codex-Bengalfox-Primary-Used-Percent": "99",
				"X-Codex-Bengalfox-Primary-Reset-At":     weeklyReset,
			},
			reserve: 11,
		},
		{
			name: "zero reserve disables",
			signals: map[string]string{
				"X-Codex-Primary-Used-Percent": "100",
				"X-Codex-Primary-Reset-At":     weeklyReset,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hit, ok := usageLimitHitForQuota("codex", QuotaState{Signals: tt.signals, ObservedAt: now}, usageLimitPolicy{ReservePercent: tt.reserve}, now)
			if ok != tt.wantHit {
				t.Fatalf("hit = %v, want %v (%+v)", ok, tt.wantHit, hit)
			}
			if !ok {
				return
			}
			if !hit.resumeAt.Equal(tt.wantReset) || hit.windowMinutes != tt.wantWindow {
				t.Fatalf("hit = %+v, want reset %v window %d", hit, tt.wantReset, tt.wantWindow)
			}
		})
	}
}

func TestUsageLimitPolicyForAuth(t *testing.T) {
	cfg := &internalconfig.Config{}
	cfg.QuotaExceeded.CodexReservePercent = 11

	if got := usageLimitPolicyForAuth(&Auth{Provider: "codex"}, cfg).ReservePercent; got != 11 {
		t.Fatalf("global reserve = %v, want 11", got)
	}
	override := &Auth{Provider: "codex", Metadata: map[string]any{"quota_reserve_percent": float64(25)}}
	if got := usageLimitPolicyForAuth(override, cfg).ReservePercent; got != 25 {
		t.Fatalf("override reserve = %v, want 25", got)
	}
	decimal := &Auth{Provider: "codex", Metadata: map[string]any{"quota_reserve_percent": json.Number("11.5")}}
	if got := usageLimitPolicyForAuth(decimal, cfg).ReservePercent; got != 11.5 {
		t.Fatalf("json.Number reserve = %v, want 11.5", got)
	}
	optOut := &Auth{Provider: "codex", Metadata: map[string]any{"quota-reserve-percent": "0"}}
	if got := usageLimitPolicyForAuth(optOut, cfg).ReservePercent; got != 0 {
		t.Fatalf("opt-out reserve = %v, want 0", got)
	}
	if got := usageLimitPolicyForAuth(&Auth{Provider: "gemini"}, cfg); got.enabled() {
		t.Fatalf("unsupported provider reserve = %v, want 0", got)
	}
}

func markCodexUsage(t *testing.T, manager *Manager, authID string, usedPercent string, resetAt time.Time) {
	t.Helper()
	ctx := internallogging.WithResponseHeadersHolder(context.Background())
	internallogging.SetResponseHeaders(ctx, http.Header{
		"X-Codex-Primary-Used-Percent":   []string{usedPercent},
		"X-Codex-Primary-Window-Minutes": []string{"10080"},
		"X-Codex-Primary-Reset-At":       []string{strconv.FormatInt(resetAt.Unix(), 10)},
	})
	manager.MarkResult(ctx, Result{AuthID: authID, Provider: "codex", Model: "gpt-6.1-sol", Success: true})
}

func TestMarkResultAppliesCodexQuotaReserve(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	cfg := &internalconfig.Config{}
	cfg.QuotaExceeded.CodexReservePercent = 11
	manager.runtimeConfig.Store(cfg)

	auth, errRegister := manager.Register(context.Background(), &Auth{ID: "reserve-auth", Provider: "codex"})
	if errRegister != nil {
		t.Fatalf("register: %v", errRegister)
	}
	resetAt := time.Now().Add(72 * time.Hour).Truncate(time.Second)

	markCodexUsage(t, manager, auth.ID, "88", resetAt)
	got, _ := manager.GetByID(auth.ID)
	if blocked, _, _ := isAuthBlockedForModel(got, "gpt-6.1-sol", time.Now()); blocked {
		t.Fatalf("auth blocked with 12%% left: %+v", got.Quota)
	}

	markCodexUsage(t, manager, auth.ID, "89.5", resetAt)
	got, _ = manager.GetByID(auth.ID)
	blocked, reason, next := isAuthBlockedForModel(got, "gpt-6.1-sol", time.Now())
	if !blocked || reason != blockReasonCooldown || !next.Equal(resetAt) {
		t.Fatalf("blocked=%v reason=%v next=%v, want cooldown until %v", blocked, reason, next, resetAt)
	}
	if got.LastError == nil || got.LastError.Code != QuotaReserveErrorCode {
		t.Fatalf("LastError = %+v, want %s", got.LastError, QuotaReserveErrorCode)
	}

	_, errSelect := manager.availableAuthsForRouteModel([]*Auth{got}, "codex", "gpt-6.1-sol", time.Now())
	if errSelect == nil {
		t.Fatal("expected selection to fail while reserve is held")
	}
	var body struct {
		Error struct {
			Type            string `json:"type"`
			Code            string `json:"code"`
			ResetsInSeconds int64  `json:"resets_in_seconds"`
			ResetsAt        int64  `json:"resets_at"`
		} `json:"error"`
	}
	if errUnmarshal := json.Unmarshal([]byte(errSelect.Error()), &body); errUnmarshal != nil {
		t.Fatalf("error body is not JSON: %v: %s", errUnmarshal, errSelect.Error())
	}
	if body.Error.Type != "usage_limit_reached" || body.Error.Code != "model_cooldown" || body.Error.ResetsInSeconds <= 0 {
		t.Fatalf("error body = %s", errSelect.Error())
	}
	if diff := body.Error.ResetsAt - resetAt.Unix(); diff < -1 || diff > 1 {
		t.Fatalf("resets_at = %d, want %d", body.Error.ResetsAt, resetAt.Unix())
	}
	if code, ok := errSelect.(interface{ StatusCode() int }); !ok || code.StatusCode() != http.StatusTooManyRequests {
		t.Fatalf("status = %v, want 429", errSelect)
	}
}

func TestQuotaReserveDisabledByDefault(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	manager.runtimeConfig.Store(&internalconfig.Config{})
	auth, errRegister := manager.Register(context.Background(), &Auth{ID: "no-reserve-auth", Provider: "codex"})
	if errRegister != nil {
		t.Fatalf("register: %v", errRegister)
	}
	markCodexUsage(t, manager, auth.ID, "99", time.Now().Add(time.Hour))
	got, _ := manager.GetByID(auth.ID)
	if blocked, _, _ := isAuthBlockedForModel(got, "gpt-6.1-sol", time.Now()); blocked {
		t.Fatalf("auth blocked without a configured reserve: %+v", got.Quota)
	}
}

func TestProbeQuotaCooldownsKeepsHeldReserve(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	ctx := context.Background()
	cfg := &internalconfig.Config{}
	cfg.QuotaExceeded.CodexReservePercent = 11
	cfg.QuotaExceeded.CredentialProbeInterval = 15 * time.Minute
	manager.runtimeConfig.Store(cfg)

	auth, errRegister := manager.Register(ctx, &Auth{ID: "reserve-probe-auth", Provider: "codex"})
	if errRegister != nil {
		t.Fatalf("register: %v", errRegister)
	}
	markCodexUsage(t, manager, auth.ID, "95", time.Now().Add(72*time.Hour))

	start := time.Now()
	lastProbe := make(map[string]time.Time)
	manager.probeQuotaCooldowns(ctx, start, lastProbe)
	manager.probeQuotaCooldowns(ctx, start.Add(16*time.Minute), lastProbe)
	if got, _ := manager.GetByID(auth.ID); !got.Quota.Exceeded {
		t.Fatal("probe cleared a cooldown held by the usage reserve")
	}
}

type quotaReserveExecutor struct {
	calls int
}

func (*quotaReserveExecutor) Identifier() string { return "codex" }

func (e *quotaReserveExecutor) Execute(ctx context.Context, _ *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.calls++
	internallogging.SetResponseHeaders(ctx, http.Header{
		"X-Codex-Primary-Used-Percent":        []string{"89"},
		"X-Codex-Primary-Window-Minutes":      []string{"10080"},
		"X-Codex-Primary-Reset-After-Seconds": []string{"86400"},
	})
	return cliproxyexecutor.Response{Payload: []byte(`{}`)}, nil
}

func (*quotaReserveExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, &Error{HTTPStatus: http.StatusNotImplemented, Message: "not implemented"}
}

func (*quotaReserveExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) { return auth, nil }

func (*quotaReserveExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, &Error{HTTPStatus: http.StatusNotImplemented, Message: "not implemented"}
}

func (*quotaReserveExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, &Error{HTTPStatus: http.StatusNotImplemented, Message: "not implemented"}
}

func TestExecuteRefusesRequestsOnceCodexReserveIsReached(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	cfg := &internalconfig.Config{}
	cfg.QuotaExceeded.CodexReservePercent = 11
	manager.SetConfig(cfg)
	executor := &quotaReserveExecutor{}
	manager.RegisterExecutor(executor)

	const authID = "reserve-execute-auth"
	const model = "gpt-quota-reserve-execute"
	if _, errRegister := manager.Register(context.Background(), &Auth{ID: authID, Provider: "codex", Status: StatusActive}); errRegister != nil {
		t.Fatalf("register: %v", errRegister)
	}
	registry.GetGlobalRegistry().RegisterClient(authID, "codex", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(authID) })

	run := func() error {
		ctx := internallogging.WithResponseHeadersHolder(context.Background())
		_, errExecute := manager.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
		return errExecute
	}
	// The request that crosses the reserve completes; it is not cut off.
	if errFirst := run(); errFirst != nil {
		t.Fatalf("first request error = %v", errFirst)
	}
	errSecond := run()
	if errSecond == nil {
		t.Fatal("second request succeeded, want reserve refusal")
	}
	if executor.calls != 1 {
		t.Fatalf("upstream calls = %d, want 1", executor.calls)
	}
	if !strings.Contains(errSecond.Error(), `"type":"usage_limit_reached"`) {
		t.Fatalf("refusal body = %s", errSecond.Error())
	}
}

func TestCodexDailyPacing(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	week := 7 * 24 * time.Hour
	weekly := func(used string, elapsed time.Duration) map[string]string {
		resetAt := now.Add(week - elapsed)
		return map[string]string{
			"X-Codex-Primary-Used-Percent":   used,
			"X-Codex-Primary-Window-Minutes": "10080",
			"X-Codex-Primary-Reset-At":       strconv.FormatInt(resetAt.Unix(), 10),
		}
	}
	windowStart := func(elapsed time.Duration) time.Time { return now.Add(-elapsed) }

	tests := []struct {
		name       string
		signals    map[string]string
		policy     usageLimitPolicy
		wantHit    bool
		wantKind   usageLimitKind
		wantResume time.Time
	}{
		{
			name:    "day 3 under the 3/7 allowance",
			signals: weekly("42", 60*time.Hour),
			policy:  usageLimitPolicy{DailyPacing: true},
		},
		{
			name:       "day 3 over the 3/7 allowance waits for day 4",
			signals:    weekly("43", 60*time.Hour),
			policy:     usageLimitPolicy{DailyPacing: true},
			wantHit:    true,
			wantKind:   usageLimitPace,
			wantResume: windowStart(60 * time.Hour).Add(72 * time.Hour),
		},
		{
			name:       "reserve shrinks the daily allowance",
			signals:    weekly("13", 10*time.Hour),
			policy:     usageLimitPolicy{ReservePercent: 11, DailyPacing: true},
			wantHit:    true,
			wantKind:   usageLimitPace,
			wantResume: windowStart(10 * time.Hour).Add(24 * time.Hour),
		},
		{
			name:    "unused allowance carries over",
			signals: weekly("12", 5*24*time.Hour+time.Hour),
			policy:  usageLimitPolicy{DailyPacing: true},
		},
		{
			name:       "last day defers to the reserve until reset",
			signals:    weekly("90", 6*24*time.Hour+time.Hour),
			policy:     usageLimitPolicy{ReservePercent: 11, DailyPacing: true},
			wantHit:    true,
			wantKind:   usageLimitReserve,
			wantResume: windowStart(6*24*time.Hour + time.Hour).Add(week),
		},
		{
			name: "5h window is not paced",
			signals: map[string]string{
				"X-Codex-Primary-Used-Percent":   "90",
				"X-Codex-Primary-Window-Minutes": "300",
				"X-Codex-Primary-Reset-At":       strconv.FormatInt(now.Add(time.Hour).Unix(), 10),
			},
			policy: usageLimitPolicy{DailyPacing: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hit, ok := usageLimitHitForQuota("codex", QuotaState{Signals: tt.signals, ObservedAt: now}, tt.policy, now)
			if ok != tt.wantHit {
				t.Fatalf("hit = %v, want %v (%+v)", ok, tt.wantHit, hit)
			}
			if !ok {
				return
			}
			if hit.kind != tt.wantKind || !hit.resumeAt.Equal(tt.wantResume) {
				t.Fatalf("hit kind=%s resume=%v, want kind=%s resume=%v", hit.kind, hit.resumeAt, tt.wantKind, tt.wantResume)
			}
		})
	}
}

func TestUsageLimitPolicyDailyPacingOverride(t *testing.T) {
	cfg := &internalconfig.Config{}
	cfg.QuotaExceeded.CodexDailyPacing = true
	if !usageLimitPolicyForAuth(&Auth{Provider: "codex"}, cfg).DailyPacing {
		t.Fatal("global daily pacing not applied")
	}
	off := &Auth{Provider: "codex", Metadata: map[string]any{"quota_daily_pacing": false}}
	if usageLimitPolicyForAuth(off, cfg).DailyPacing {
		t.Fatal("per-credential pacing override ignored")
	}
	inherit := &Auth{Provider: "codex", Metadata: map[string]any{"quota_daily_pacing": nil, "quota_reserve_percent": nil}}
	if policy := usageLimitPolicyForAuth(inherit, cfg); !policy.DailyPacing || policy.ReservePercent != 0 {
		t.Fatalf("null overrides should inherit, got %+v", policy)
	}
}

func TestClaudeUsageWindows(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	fiveHourReset := now.Add(2 * time.Hour)
	weeklyReset := now.Add(4 * 24 * time.Hour) // window opened 3 days ago, day 4 of 7
	quota := QuotaState{ObservedAt: now, Signals: map[string]string{
		"Anthropic-Ratelimit-Unified-5h-Utilization":    "0.90",
		"Anthropic-Ratelimit-Unified-5h-Reset":          strconv.FormatInt(fiveHourReset.Unix(), 10),
		"Anthropic-Ratelimit-Unified-7d-Utilization":    "0.70",
		"Anthropic-Ratelimit-Unified-7d-Reset":          strconv.FormatInt(weeklyReset.Unix(), 10),
		"Anthropic-Ratelimit-Unified-7d_oi-Utilization": "0.99",
		"Anthropic-Ratelimit-Unified-7d_oi-Reset":       strconv.FormatInt(weeklyReset.Unix(), 10),
	}}

	windows := usageWindows("claude", quota)
	if len(windows) != 2 || windows[0].minutes != 300 || windows[1].minutes != 10080 ||
		windows[0].used != 90 || windows[1].used != 70 || !windows[1].resetAt.Equal(weeklyReset) {
		t.Fatalf("claude windows = %+v", windows)
	}

	// 10% left in the session window trips an 11% reserve until the session resets.
	hit, ok := usageLimitHitForQuota("claude", quota, usageLimitPolicy{ReservePercent: 11}, now)
	if !ok || hit.kind != usageLimitReserve || !hit.resumeAt.Equal(fiveHourReset) {
		t.Fatalf("reserve hit = %+v ok=%v", hit, ok)
	}
	// 70% of the week by day 4 is ahead of the 4/7 pace, so pacing holds until day 5.
	hit, ok = usageLimitHitForQuota("claude", quota, usageLimitPolicy{DailyPacing: true}, now)
	wantResume := weeklyReset.Add(-7 * 24 * time.Hour).Add(4 * 24 * time.Hour)
	if !ok || hit.kind != usageLimitPace || !hit.resumeAt.Equal(wantResume) {
		t.Fatalf("pace hit = %+v ok=%v, want resume %v", hit, ok, wantResume)
	}
	// The 7d_oi window is model-specific and never counts.
	quota.Signals["Anthropic-Ratelimit-Unified-5h-Utilization"] = "0.10"
	quota.Signals["Anthropic-Ratelimit-Unified-7d-Utilization"] = "0.10"
	if hit, ok := usageLimitHitForQuota("claude", quota, usageLimitPolicy{ReservePercent: 11}, now); ok {
		t.Fatalf("7d_oi tripped the reserve: %+v", hit)
	}
}

func TestUsageLimitPolicyClaudeDefaultsAreIndependent(t *testing.T) {
	cfg := &internalconfig.Config{}
	cfg.QuotaExceeded.CodexReservePercent = 11
	cfg.QuotaExceeded.ClaudeReservePercent = 20
	cfg.QuotaExceeded.ClaudeDailyPacing = true
	if got := usageLimitPolicyForAuth(&Auth{Provider: "codex"}, cfg); got.ReservePercent != 11 || got.DailyPacing {
		t.Fatalf("codex policy = %+v", got)
	}
	if got := usageLimitPolicyForAuth(&Auth{Provider: "claude"}, cfg); got.ReservePercent != 20 || !got.DailyPacing {
		t.Fatalf("claude policy = %+v", got)
	}
	override := &Auth{Provider: "claude", Metadata: map[string]any{"quota_reserve_percent": float64(5), "quota_daily_pacing": false}}
	if got := usageLimitPolicyForAuth(override, cfg); got.ReservePercent != 5 || got.DailyPacing {
		t.Fatalf("claude override policy = %+v", got)
	}
}

func TestMarkResultAppliesClaudeUsageLimit(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	cfg := &internalconfig.Config{}
	cfg.QuotaExceeded.ClaudeReservePercent = 11
	manager.runtimeConfig.Store(cfg)
	auth, errRegister := manager.Register(context.Background(), &Auth{ID: "claude-reserve-auth", Provider: "claude"})
	if errRegister != nil {
		t.Fatalf("register: %v", errRegister)
	}
	resetAt := time.Now().Add(3 * time.Hour).Truncate(time.Second)
	ctx := internallogging.WithResponseHeadersHolder(context.Background())
	internallogging.SetResponseHeaders(ctx, http.Header{
		"Anthropic-Ratelimit-Unified-5h-Utilization": []string{"0.95"},
		"Anthropic-Ratelimit-Unified-5h-Reset":       []string{strconv.FormatInt(resetAt.Unix(), 10)},
		"Anthropic-Ratelimit-Unified-7d-Utilization": []string{"0.30"},
		"Anthropic-Ratelimit-Unified-7d-Reset":       []string{strconv.FormatInt(time.Now().Add(72*time.Hour).Unix(), 10)},
	})
	manager.MarkResult(ctx, Result{AuthID: auth.ID, Provider: "claude", Model: "claude-sonnet-5-5", Success: true})

	got, _ := manager.GetByID(auth.ID)
	blocked, reason, next := isAuthBlockedForModel(got, "claude-sonnet-5-5", time.Now())
	if !blocked || reason != blockReasonCooldown || !next.Equal(resetAt) {
		t.Fatalf("blocked=%v reason=%v next=%v, want cooldown until %v", blocked, reason, next, resetAt)
	}
	_, errSelect := manager.availableAuthsForRouteModel([]*Auth{got}, "claude", "claude-sonnet-5-5", time.Now())
	resume, limited := UsageLimitRefusalReset(errSelect)
	if !limited || resume.Sub(resetAt) > 2*time.Second || resetAt.Sub(resume) > 2*time.Second {
		t.Fatalf("UsageLimitRefusalReset = %v %v, want ~%v", resume, limited, resetAt)
	}
	if _, limited := UsageLimitRefusalReset(newModelCooldownError("m", "claude", time.Minute)); limited {
		t.Fatal("plain cooldown reported as a usage limit")
	}
}
