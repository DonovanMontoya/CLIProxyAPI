package auth

import (
	"context"
	"strconv"
	"testing"
	"time"
)

func TestUsageReportCoversCodexAndClaude(t *testing.T) {
	now := time.Now()
	sessionReset := now.Add(2 * time.Hour)
	weeklyReset := now.Add(3 * 24 * time.Hour)
	unix := func(at time.Time) string { return strconv.FormatInt(at.Unix(), 10) }

	manager := NewManager(nil, nil, nil)
	register := func(auth *Auth) {
		t.Helper()
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatalf("register %s: %v", auth.ID, err)
		}
	}
	register(&Auth{ID: "claude-a", Provider: "claude", Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
		"Anthropic-Ratelimit-Unified-5h-Utilization": "0.42",
		"Anthropic-Ratelimit-Unified-5h-Reset":       unix(sessionReset),
		"Anthropic-Ratelimit-Unified-7d-Utilization": "0.7",
		"Anthropic-Ratelimit-Unified-7d-Reset":       unix(weeklyReset),
	}}})
	register(&Auth{ID: "codex-a", Provider: "codex", Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
		"X-Codex-Primary-Used-Percent":     "30",
		"X-Codex-Primary-Window-Minutes":   "300",
		"X-Codex-Primary-Reset-At":         unix(sessionReset),
		"X-Codex-Secondary-Used-Percent":   "60",
		"X-Codex-Secondary-Window-Minutes": "10080",
		"X-Codex-Secondary-Reset-At":       unix(weeklyReset),
	}}})
	// The second Codex credential's weekly window reset after it was observed,
	// so it counts as unused.
	register(&Auth{ID: "codex-b", Provider: "codex", Quota: QuotaState{ObservedAt: now.Add(-8 * 24 * time.Hour), Signals: map[string]string{
		"X-Codex-Secondary-Used-Percent":   "90",
		"X-Codex-Secondary-Window-Minutes": "10080",
		"X-Codex-Secondary-Reset-At":       unix(now.Add(-time.Hour)),
	}}})
	register(&Auth{ID: "codex-off", Provider: "codex", Disabled: true, Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
		"X-Codex-Primary-Used-Percent":   "100",
		"X-Codex-Primary-Window-Minutes": "300",
		"X-Codex-Primary-Reset-At":       unix(sessionReset),
	}}})
	register(&Auth{ID: "gemini-a", Provider: "gemini"})
	// Some Claude responses carry utilization without reset headers; the
	// observed utilization still counts.
	register(&Auth{ID: "claude-b", Provider: "claude", Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
		"Anthropic-Ratelimit-Unified-5h-Utilization": "0.22",
		"Anthropic-Ratelimit-Unified-7d-Utilization": "0.9",
	}}})

	reports := manager.UsageReport(now)
	if len(reports) != 2 || reports[0].Provider != "claude" || reports[1].Provider != "codex" {
		t.Fatalf("providers = %+v, want claude and codex", reports)
	}

	claude := reports[0]
	if len(claude.PerCredential) != 2 || len(claude.Windows) != 2 {
		t.Fatalf("claude report = %+v", claude)
	}
	assertUsageWindow(t, claude.Windows[0], "5h", 32, &sessionReset)
	assertUsageWindow(t, claude.Windows[1], "7d", 80, &weeklyReset)
	assertUsageWindow(t, claude.PerCredential[1][0], "5h", 22, nil)

	codex := reports[1]
	if len(codex.PerCredential) != 2 || len(codex.Windows) != 2 {
		t.Fatalf("codex report = %+v", codex)
	}
	assertUsageWindow(t, codex.Windows[0], "5h", 30, &sessionReset)
	assertUsageWindow(t, codex.Windows[1], "7d", 30, &weeklyReset)
	assertUsageWindow(t, codex.PerCredential[1][0], "7d", 0, nil)
}

func assertUsageWindow(t *testing.T, got UsageWindowReport, window string, used float64, resetsAt *time.Time) {
	t.Helper()
	if got.Window != window || got.UsedPercent != used || got.RemainingPercent != 100-used {
		t.Fatalf("window = %+v, want %s used %.1f", got, window, used)
	}
	if (resetsAt == nil) != (got.ResetsAt == nil) || (resetsAt != nil && got.ResetsAt.Unix() != resetsAt.Unix()) {
		t.Fatalf("window %s resets_at = %v, want %v", window, got.ResetsAt, resetsAt)
	}
}
