package auth

import (
	"context"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestManager_ProbeQuotaCooldownsClearsAfterInterval(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	ctx := context.Background()
	start := time.Now()
	next := start.Add(48 * time.Hour)

	if _, err := manager.Register(ctx, &Auth{
		ID:             "probe-auth",
		Provider:       "codex",
		Status:         StatusError,
		Unavailable:    true,
		NextRetryAfter: next,
		Quota:          QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: next},
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	lastProbe := make(map[string]time.Time)
	cfg := &internalconfig.Config{}
	manager.runtimeConfig.Store(cfg)

	// Disabled by default: nothing is cleared.
	manager.probeQuotaCooldowns(ctx, start, lastProbe)
	manager.probeQuotaCooldowns(ctx, start.Add(time.Hour), lastProbe)
	if got, _ := manager.GetByID("probe-auth"); !got.Quota.Exceeded {
		t.Fatal("cooldown cleared while probing disabled")
	}

	cfg = &internalconfig.Config{}
	cfg.QuotaExceeded.CredentialProbeInterval = 15 * time.Minute
	manager.runtimeConfig.Store(cfg)

	manager.probeQuotaCooldowns(ctx, start, lastProbe) // first sighting
	manager.probeQuotaCooldowns(ctx, start.Add(10*time.Minute), lastProbe)
	if got, _ := manager.GetByID("probe-auth"); !got.Quota.Exceeded {
		t.Fatal("cooldown cleared before interval elapsed")
	}
	manager.probeQuotaCooldowns(ctx, start.Add(16*time.Minute), lastProbe)
	if got, _ := manager.GetByID("probe-auth"); got.Quota.Exceeded || got.Unavailable {
		t.Fatalf("cooldown not cleared after interval: %+v", got.Quota)
	}
}
