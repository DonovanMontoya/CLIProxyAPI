package auth

import (
	"fmt"
	"strings"
	"time"
)

// bankedResetAttempt survives loop restarts and config reloads. A reservation is
// never rolled back: a transport error does not prove the provider did not spend
// the reset. Keep it for the entire expiry gate, even when status reads are stale.
type bankedResetAttempt struct {
	inFlight     bool
	blockedUntil time.Time
}

// BeginBankedReset reserves one account-wide reset attempt. Both automatic and
// dashboard resets must reserve before sending a mutation. The returned function
// releases only the in-flight flag; errors and cancellations retain the gate.
// Account IDs must identify the provider account, never a local credential file.
func (m *Manager) BeginBankedReset(provider, accountID string, now, expiresAt time.Time) (func(), error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	accountID = strings.TrimSpace(accountID)
	if m == nil || accountID == "" || (provider != "codex" && provider != "claude") {
		return nil, fmt.Errorf("banked reset: missing provider account identity")
	}
	if provider == "claude" {
		accountID = strings.ToLower(accountID)
	}
	// A manual reset must cover the automatic gate even when it wins before
	// the background worker has fetched the grant's expiration time.
	window := bankedResetRetryInterval
	if cfg := m.runtimeConfigSnapshot(); cfg != nil {
		window = max(window, cfg.QuotaExceeded.BankedResetAutoUseBefore)
	}
	window += bankedResetTickInterval
	until := now.Add(window)
	if expiresAt.Add(bankedResetTickInterval).After(until) {
		until = expiresAt.Add(bankedResetTickInterval)
	}

	m.bankedResetMu.Lock()
	defer m.bankedResetMu.Unlock()
	if m.bankedResetAttempts == nil {
		m.bankedResetAttempts = make(map[string]*bankedResetAttempt)
	}
	for key, attempt := range m.bankedResetAttempts {
		if !attempt.inFlight && !now.Before(attempt.blockedUntil) {
			delete(m.bankedResetAttempts, key)
		}
	}
	key := provider + ":" + accountID
	if attempt := m.bankedResetAttempts[key]; attempt != nil {
		return nil, fmt.Errorf("banked reset: an account reset is already in progress or was recently attempted")
	}
	started := time.Now()
	attempt := &bankedResetAttempt{inFlight: true, blockedUntil: until}
	m.bankedResetAttempts[key] = attempt
	return func() {
		m.bankedResetMu.Lock()
		defer m.bankedResetMu.Unlock()
		attempt.inFlight = false
		// A long upstream call must also protect clicks just after completion.
		attempt.blockedUntil = maxResetTime(attempt.blockedUntil, now.Add(time.Since(started)+window))
	}, nil
}

func maxResetTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
