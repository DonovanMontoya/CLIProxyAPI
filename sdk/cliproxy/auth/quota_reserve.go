package auth

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	log "github.com/sirupsen/logrus"
)

// QuotaReserveErrorCode marks a credential that was taken out of rotation
// because its remaining usage reached the configured reserve.
const QuotaReserveErrorCode = "quota_reserve_reached"

type usageLimitKind string

const (
	usageLimitReserve usageLimitKind = "reserve"
	usageLimitPace    usageLimitKind = "pace"
)

// usageLimitHit describes the usage window that tripped a usage limit.
type usageLimitHit struct {
	kind           usageLimitKind
	used           float64
	allowedUsed    float64
	reservePercent float64
	windowMinutes  int
	day, days      int
	resetAt        time.Time
	resumeAt       time.Time
}

// QuotaReservePercentOverride returns the per-credential reserve from metadata
// key "quota_reserve_percent" (or "quota-reserve-percent").
func (a *Auth) QuotaReservePercentOverride() (float64, bool) {
	if a == nil || a.Metadata == nil {
		return 0, false
	}
	for _, key := range []string{"quota_reserve_percent", "quota-reserve-percent"} {
		if val, ok := a.Metadata[key]; ok {
			if parsed, okParse := parseFloatAny(val); okParse {
				return parsed, true
			}
		}
	}
	return 0, false
}

// QuotaDailyPacingOverride returns the per-credential daily pacing switch from
// metadata key "quota_daily_pacing" (or "quota-daily-pacing").
func (a *Auth) QuotaDailyPacingOverride() (bool, bool) {
	if a == nil || a.Metadata == nil {
		return false, false
	}
	for _, key := range []string{"quota_daily_pacing", "quota-daily-pacing"} {
		if val, ok := a.Metadata[key]; ok {
			if parsed, okParse := parseBoolAny(val); okParse {
				return parsed, true
			}
		}
	}
	return false, false
}

// usageLimitPolicy is the effective usage limit for a credential.
type usageLimitPolicy struct {
	// ReservePercent is the share of every window kept free for direct use.
	ReservePercent float64
	// DailyPacing spreads multi-day windows evenly across their days.
	DailyPacing bool
}

func (p usageLimitPolicy) enabled() bool {
	return p.ReservePercent > 0 || p.DailyPacing
}

// usageLimitPolicyForAuth returns the usage limit that applies to auth. Only
// Codex reports the usage windows the limits rely on, so other providers get
// no limit. Credential metadata overrides the global configuration.
func usageLimitPolicyForAuth(auth *Auth, cfg *internalconfig.Config) usageLimitPolicy {
	var policy usageLimitPolicy
	if auth == nil || !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return policy
	}
	if cfg != nil {
		policy.ReservePercent = cfg.QuotaExceeded.CodexReservePercent
		policy.DailyPacing = cfg.QuotaExceeded.CodexDailyPacing
	}
	if override, ok := auth.QuotaReservePercentOverride(); ok {
		policy.ReservePercent = override
	}
	if override, ok := auth.QuotaDailyPacingOverride(); ok {
		policy.DailyPacing = override
	}
	policy.ReservePercent = math.Max(0, math.Min(100, policy.ReservePercent))
	return policy
}

// codexUsageLimitHit reports whether any of the credential's main Codex
// usage windows has hit the policy. Plans differ in which windows they report
// (some have no 5h window), so every window present in the snapshot is checked.
// Windows whose reset time has passed are stale and ignored. When several
// windows trip, the one that keeps the credential paused longest wins.
//
// The reserve trips once the remaining share drops to ReservePercent, and holds
// until the window resets. Daily pacing applies to windows spanning several
// days: the usable share (100 - ReservePercent) is split evenly across the
// window's days, counted from the window start. Unused allowance carries over,
// so by the end of day d of 7 at most d/7 of the usable share may be spent.
// Reaching the allowance pauses the credential until the next day begins.
func codexUsageLimitHit(quota QuotaState, policy usageLimitPolicy, now time.Time) (usageLimitHit, bool) {
	var hit usageLimitHit
	if !policy.enabled() || len(quota.Signals) == 0 {
		return hit, false
	}
	found := false
	consider := func(candidate usageLimitHit) {
		if !candidate.resumeAt.After(now) || (found && !candidate.resumeAt.After(hit.resumeAt)) {
			return
		}
		hit = candidate
		found = true
	}
	for _, slot := range []string{"Primary", "Secondary"} {
		prefix := "X-Codex-" + slot + "-"
		used, err := strconv.ParseFloat(quota.Signals[prefix+"Used-Percent"], 64)
		if err != nil {
			continue
		}
		resetAt := codexWindowResetAt(quota.Signals, prefix, quota.ObservedAt)
		if !resetAt.After(now) {
			continue
		}
		minutes, _ := strconv.Atoi(quota.Signals[prefix+"Window-Minutes"])
		base := usageLimitHit{used: used, reservePercent: policy.ReservePercent, windowMinutes: minutes, resetAt: resetAt}

		if policy.ReservePercent > 0 && 100-used <= policy.ReservePercent {
			reserveHit := base
			reserveHit.kind = usageLimitReserve
			reserveHit.allowedUsed = 100 - policy.ReservePercent
			reserveHit.resumeAt = resetAt
			consider(reserveHit)
		}

		window := time.Duration(minutes) * time.Minute
		if !policy.DailyPacing || window < 2*24*time.Hour {
			continue
		}
		days := window.Hours() / 24
		windowStart := resetAt.Add(-window)
		elapsed := now.Sub(windowStart)
		if elapsed < 0 {
			continue
		}
		day := int(elapsed / (24 * time.Hour))
		allowed := (100 - policy.ReservePercent) * math.Min(1, float64(day+1)/days)
		if used < allowed {
			continue
		}
		paceHit := base
		paceHit.kind = usageLimitPace
		paceHit.allowedUsed = allowed
		paceHit.day = day + 1
		paceHit.days = int(math.Ceil(days))
		paceHit.resumeAt = windowStart.Add(time.Duration(day+1) * 24 * time.Hour)
		if paceHit.resumeAt.After(resetAt) {
			paceHit.resumeAt = resetAt
		}
		consider(paceHit)
	}
	return hit, found
}

func codexWindowResetAt(signals map[string]string, prefix string, observedAt time.Time) time.Time {
	if resetAt, err := strconv.ParseFloat(signals[prefix+"Reset-At"], 64); err == nil && resetAt > 0 {
		return time.Unix(int64(resetAt), 0)
	}
	if resetAfter, err := strconv.ParseFloat(signals[prefix+"Reset-After-Seconds"], 64); err == nil && resetAfter >= 0 && !observedAt.IsZero() {
		return observedAt.Add(time.Duration(resetAfter * float64(time.Second)))
	}
	return time.Time{}
}

func quotaWindowLabel(minutes int) string {
	switch {
	case minutes == 300:
		return "5h"
	case minutes == 7*24*60:
		return "weekly"
	case minutes > 0:
		return fmt.Sprintf("%d-minute", minutes)
	default:
		return "usage"
	}
}

func (h usageLimitHit) message() string {
	resume := h.resumeAt.UTC().Format(time.RFC3339)
	if h.kind == usageLimitPace {
		return fmt.Sprintf("daily pace reached: %.1f%% of the %s window used, %.1f%% allowed through day %d of %d, resumes at %s",
			h.used, quotaWindowLabel(h.windowMinutes), h.allowedUsed, h.day, h.days, resume)
	}
	return fmt.Sprintf("usage reserve reached: %.1f%% left in the %s window (reserve %g%%), resumes at %s",
		100-h.used, quotaWindowLabel(h.windowMinutes), h.reservePercent, resume)
}

// usageLimitHitForAuth evaluates the usage limit for auth with cfg.
func usageLimitHitForAuth(auth *Auth, cfg *internalconfig.Config, now time.Time) (usageLimitHit, bool) {
	if auth == nil || (cfg != nil && cfg.Home.Enabled) {
		return usageLimitHit{}, false
	}
	return codexUsageLimitHit(auth.Quota, usageLimitPolicyForAuth(auth, cfg), now)
}

// applyUsageLimitLocked puts auth into a credential-wide quota cooldown until
// the usage limit lifts. It reports whether the cooldown was applied or
// extended. The caller must hold m.mu.
func (m *Manager) applyUsageLimitLocked(auth *Auth, now time.Time) bool {
	hit, ok := usageLimitHitForAuth(auth, m.runtimeConfigSnapshot(), now)
	if !ok {
		return false
	}
	if auth.Quota.Exceeded && auth.Quota.Reason == "credential_quota" && !auth.Quota.NextRecoverAt.Before(hit.resumeAt) {
		return false
	}
	auth.Unavailable = true
	auth.Quota.Exceeded = true
	auth.Quota.Reason = "credential_quota"
	auth.Quota.NextRecoverAt = hit.resumeAt
	auth.NextRetryAfter = hit.resumeAt
	auth.LastError = &Error{
		Code:       QuotaReserveErrorCode,
		Message:    hit.message(),
		HTTPStatus: http.StatusTooManyRequests,
	}
	log.Infof("usage limit: auth %s paused until %s (%s)", auth.ID, hit.resumeAt.UTC().Format(time.RFC3339), auth.LastError.Message)
	return true
}
