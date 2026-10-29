package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

// bankedResetExecutor answers HttpRequest calls from a canned route table and
// records every request it receives.
type bankedResetExecutor struct {
	provider string
	mu       sync.Mutex
	routes   map[string]string
	calls    []string
}

func (e *bankedResetExecutor) Identifier() string { return e.provider }
func (e *bankedResetExecutor) Execute(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}
func (e *bankedResetExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}
func (e *bankedResetExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) { return auth, nil }
func (e *bankedResetExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}
func (e *bankedResetExecutor) PrepareRequest(req *http.Request, _ *Auth) error {
	req.Header.Set("Authorization", "Bearer test")
	return nil
}
func (e *bankedResetExecutor) HttpRequest(_ context.Context, _ *Auth, req *http.Request) (*http.Response, error) {
	key := req.Method + " " + req.URL.String()
	e.mu.Lock()
	e.calls = append(e.calls, key)
	body, ok := e.routes[key]
	e.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unexpected request %s", key)
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
}

func (e *bankedResetExecutor) count(key string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, call := range e.calls {
		if call == key {
			n++
		}
	}
	return n
}

func newBankedResetManager(t *testing.T, exec *bankedResetExecutor, auth *Auth, lead time.Duration) *Manager {
	t.Helper()
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(exec)
	cfg := &internalconfig.Config{}
	cfg.QuotaExceeded.BankedResetAutoUseBefore = lead
	manager.runtimeConfig.Store(cfg)
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("register: %v", err)
	}
	return manager
}

func TestManager_BankedResetCodexConsumesNearExpiry(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	expires := now.Add(30 * time.Minute)
	exec := &bankedResetExecutor{provider: "codex", routes: map[string]string{
		"GET " + codexResetCreditsURL: fmt.Sprintf(`{"available_count":1,"credits":[{"id":"c1","reset_type":"codex_rate_limits","status":"available","expires_at":%q}]}`,
			expires.Format(time.RFC3339)),
		"POST " + codexResetCreditsConsumeURL: `{}`,
	}}
	next := now.Add(48 * time.Hour)
	manager := newBankedResetManager(t, exec, &Auth{
		ID:             "codex-auth",
		Provider:       "codex",
		Metadata:       map[string]any{"account_id": "acct"},
		Unavailable:    true,
		NextRetryAfter: next,
		Quota:          QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: next},
	}, 5*time.Minute)

	states := make(map[string]*bankedResetState)
	manager.useExpiringBankedResets(context.Background(), now, states)
	if got := exec.count("POST " + codexResetCreditsConsumeURL); got != 0 {
		t.Fatalf("consumed %d credits 30m before expiry", got)
	}

	// Within the hourly cache window the status is not re-read until expiry nears.
	manager.useExpiringBankedResets(context.Background(), now.Add(10*time.Minute), states)
	if got := exec.count("GET " + codexResetCreditsURL); got != 1 {
		t.Fatalf("status read %d times, want 1", got)
	}

	manager.useExpiringBankedResets(context.Background(), now.Add(26*time.Minute), states)
	if got := exec.count("POST " + codexResetCreditsConsumeURL); got != 1 {
		t.Fatalf("consumed %d credits near expiry, want 1", got)
	}
	if got, _ := manager.GetByID("codex-auth"); got.Quota.Exceeded {
		t.Fatal("cooldown not cleared after using a reset")
	}
}

func TestManager_BankedResetDisabledByDefault(t *testing.T) {
	now := time.Now()
	exec := &bankedResetExecutor{provider: "codex", routes: map[string]string{}}
	manager := newBankedResetManager(t, exec, &Auth{ID: "codex-auth", Provider: "codex"}, 0)
	manager.useExpiringBankedResets(context.Background(), now, make(map[string]*bankedResetState))
	if len(exec.calls) != 0 {
		t.Fatalf("made requests while disabled: %v", exec.calls)
	}
}

func TestManager_BankedResetClaudeClaimsGrant(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	org := "11111111-2222-3333-4444-555555555555"
	status := func(atLimit bool) string {
		return fmt.Sprintf(`{"cedar_ember":{"eligible":true,"at_limit":%t,"grants":[
			{"id":"late","resets_total":1,"resets_left":1,"usable_now":true,"use_requires_limit":true,"ends_at":%q},
			{"id":"soon","resets_total":1,"resets_left":1,"usable_now":true,"use_requires_limit":true,"ends_at":%q}]}}`,
			atLimit, now.Add(72*time.Hour).Format(time.RFC3339), now.Add(3*time.Minute).Format(time.RFC3339))
	}
	claimKey := "POST https://api.anthropic.com/api/organizations/" + org + "/reset_rate_limits"
	exec := &bankedResetExecutor{provider: "claude", routes: map[string]string{
		"GET " + claudeResetGrantStatusURL: status(false),
		claimKey:                           `{"result":"reset"}`,
	}}
	manager := newBankedResetManager(t, exec, &Auth{
		ID:       "claude-auth",
		Provider: "claude",
		Metadata: map[string]any{"organization_uuid": org},
	}, 5*time.Minute)

	states := make(map[string]*bankedResetState)
	manager.useExpiringBankedResets(context.Background(), now, states)
	if got := exec.count(claimKey); got != 0 {
		t.Fatalf("claimed %d grants while not at limit", got)
	}

	exec.mu.Lock()
	exec.routes["GET "+claudeResetGrantStatusURL] = status(true)
	exec.mu.Unlock()
	manager.useExpiringBankedResets(context.Background(), now.Add(time.Minute), states)
	if got := exec.count(claimKey); got != 1 {
		t.Fatalf("claimed %d grants at limit, want 1", got)
	}
}

func TestEarliestClaudeResetGrantSkipsUnusable(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	ends := now.Add(time.Minute).Format(time.RFC3339)
	block := fmt.Sprintf(`{"grants":[
		{"id":"paused","resets_left":1,"usable_now":true,"paused":true,"ends_at":%[1]q},
		{"id":"empty","resets_left":0,"usable_now":true,"ends_at":%[1]q},
		{"id":"never","resets_left":1,"usable_now":true},
		{"id":"ok","resets_left":1,"usable_now":true,"use_requires_limit":false,"ends_at":%[1]q}]}`, ends)
	grant, ok := earliestClaudeResetGrant(gjson.Parse(block), now)
	if !ok || grant.id != "ok" || grant.useRequiresLimit {
		t.Fatalf("got %+v ok=%v, want grant ok without limit requirement", grant, ok)
	}
}
