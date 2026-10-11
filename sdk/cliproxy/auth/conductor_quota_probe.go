package auth

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
)

const quotaProbeTickInterval = time.Minute

// runQuotaProbeLoop periodically clears credential-wide quota cooldowns so the
// next request probes upstream again. A cooldown is derived from the reset time
// reported by the provider on a past 429; if the provider lifted the limit early
// the cooldown would otherwise keep rejecting requests until it expires. When the
// quota is still exhausted the provider answers 429 again and the cooldown is
// re-applied, so a probe costs at most one failed request per interval.
func (m *Manager) runQuotaProbeLoop(ctx context.Context) {
	ticker := time.NewTicker(quotaProbeTickInterval)
	defer ticker.Stop()

	lastProbe := make(map[string]time.Time)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			m.probeQuotaCooldowns(ctx, now, lastProbe)
		}
	}
}

func (m *Manager) probeQuotaCooldowns(ctx context.Context, now time.Time, lastProbe map[string]time.Time) {
	cfg := m.runtimeConfigSnapshot()
	interval := time.Duration(0)
	if cfg != nil {
		interval = cfg.QuotaExceeded.CredentialProbeInterval
	}
	if interval <= 0 {
		clear(lastProbe)
		return
	}

	cooling := make(map[string]struct{})
	m.mu.RLock()
	for id, auth := range m.auths {
		if auth != nil && auth.Quota.Exceeded && auth.Quota.Reason == "credential_quota" && auth.Quota.NextRecoverAt.After(now) {
			cooling[id] = struct{}{}
		}
	}
	m.mu.RUnlock()

	for id := range lastProbe {
		if _, ok := cooling[id]; !ok {
			delete(lastProbe, id)
		}
	}
	for id := range cooling {
		last, seen := lastProbe[id]
		if !seen {
			lastProbe[id] = now
			continue
		}
		if now.Sub(last) < interval {
			continue
		}
		lastProbe[id] = now
		if _, _, err := m.ResetQuota(ctx, id); err != nil {
			log.Warnf("quota probe: failed to clear cooldown for auth %s: %v", id, err)
			continue
		}
		log.Infof("quota probe: cleared credential quota cooldown for auth %s to retry upstream", id)
	}
}
