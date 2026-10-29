package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

const (
	bankedResetTickInterval   = time.Minute
	bankedResetStatusInterval = time.Hour
	bankedResetMaxBody        = 1 << 20

	codexResetCreditsURL        = "https://chatgpt.com/backend-api/wham/rate-limit-reset-credits"
	codexResetCreditsConsumeURL = "https://chatgpt.com/backend-api/wham/rate-limit-reset-credits/consume"

	claudeResetGrantStatusURL = "https://api.anthropic.com/api/oauth/usage?cedar_ember=1&skip_spend=1"
	claudeProfileURL          = "https://api.anthropic.com/api/oauth/profile"
	claudeResetGrantProgram   = "cedar_ember"
	claudeOAuthUserAgent      = "claude-cli/2.1.280 (external, cli)"
	claudeOAuthBeta           = "oauth-2025-04-20"
)

var (
	claudeResetGrantIDPattern = regexp.MustCompile(`^[a-z0-9_-]{1,40}$`)
	claudeOrganizationPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// bankedResetState caches when an auth's banked resets were last read and the
// earliest expiry seen, so upstream is only polled hourly until a reset nears expiry.
type bankedResetState struct {
	checkedAt time.Time
	expiresAt time.Time
}

// runBankedResetLoop spends banked usage resets (Codex rate-limit reset credits
// and Claude reset grants) shortly before they expire, so they are not lost
// unused. It is disabled unless quota-exceeded.banked-reset-auto-use-before is set.
func (m *Manager) runBankedResetLoop(ctx context.Context) {
	ticker := time.NewTicker(bankedResetTickInterval)
	defer ticker.Stop()

	states := make(map[string]*bankedResetState)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			m.useExpiringBankedResets(ctx, now, states)
		}
	}
}

func (m *Manager) useExpiringBankedResets(ctx context.Context, now time.Time, states map[string]*bankedResetState) {
	cfg := m.runtimeConfigSnapshot()
	lead := time.Duration(0)
	if cfg != nil {
		lead = cfg.QuotaExceeded.BankedResetAutoUseBefore
	}
	if lead <= 0 {
		clear(states)
		return
	}
	// The loop only wakes once per tick, so a shorter lead could skip past expiry.
	lead = max(lead, bankedResetTickInterval)

	due := make([]*Auth, 0)
	seen := make(map[string]struct{})
	m.mu.RLock()
	for id, auth := range m.auths {
		if !bankedResetEligible(auth) {
			continue
		}
		seen[id] = struct{}{}
		if state := states[id]; state == nil || state.due(now, lead) {
			due = append(due, auth.Clone())
		}
	}
	m.mu.RUnlock()

	for id := range states {
		if _, ok := seen[id]; !ok {
			delete(states, id)
		}
	}
	for _, auth := range due {
		state := states[auth.ID]
		if state == nil {
			state = &bankedResetState{}
			states[auth.ID] = state
		}
		state.checkedAt = now
		var (
			expiresAt time.Time
			err       error
		)
		switch strings.ToLower(auth.Provider) {
		case "codex":
			expiresAt, err = m.useExpiringCodexResetCredit(ctx, auth, now, lead)
		case "claude":
			expiresAt, err = m.useExpiringClaudeResetGrant(ctx, auth, now, lead)
		}
		if err != nil {
			log.Warnf("banked reset: auth %s: %v", auth.ID, err)
			continue
		}
		state.expiresAt = expiresAt
	}
}

// due reports whether the cached status is stale or a known reset is near expiry.
func (s *bankedResetState) due(now time.Time, lead time.Duration) bool {
	if !s.expiresAt.IsZero() && s.expiresAt.Sub(now) <= lead {
		return true
	}
	return s.checkedAt.IsZero() || now.Sub(s.checkedAt) >= bankedResetStatusInterval
}

func bankedResetEligible(auth *Auth) bool {
	if auth == nil || auth.Disabled || auth.AuthKind() == AuthKindAPIKey {
		return false
	}
	switch strings.ToLower(auth.Provider) {
	case "codex", "claude":
		return true
	default:
		return false
	}
}

// useExpiringCodexResetCredit consumes one Codex reset credit when the earliest
// available credit expires within lead. Codex only spends a credit when it
// actually refreshes a usage window, so consuming early is never wasteful.
// It returns the earliest expiry still pending so the caller re-checks in time.
func (m *Manager) useExpiringCodexResetCredit(ctx context.Context, auth *Auth, now time.Time, lead time.Duration) (time.Time, error) {
	headers := codexResetHeaders(auth)
	body, err := m.bankedResetRequest(ctx, auth, http.MethodGet, codexResetCreditsURL, nil, headers)
	if err != nil {
		return time.Time{}, fmt.Errorf("read codex reset credits: %w", err)
	}
	earliest := earliestCodexResetCreditExpiry(body, now)
	if earliest.IsZero() || earliest.Sub(now) > lead {
		return earliest, nil
	}

	payload, _ := json.Marshal(map[string]string{"redeem_request_id": uuid.NewString()})
	if _, err = m.bankedResetRequest(ctx, auth, http.MethodPost, codexResetCreditsConsumeURL, payload, headers); err != nil {
		return earliest, fmt.Errorf("consume codex reset credit: %w", err)
	}
	log.Infof("banked reset: used Codex reset credit for auth %s (expires %s)", auth.ID, earliest.Format(time.RFC3339))
	m.clearCooldownAfterBankedReset(ctx, auth.ID)
	// Re-read on the next tick to pick up the remaining credits.
	return now, nil
}

func codexResetHeaders(auth *Auth) http.Header {
	headers := make(http.Header)
	headers.Set("Accept", "application/json")
	headers.Set("Content-Type", "application/json")
	headers.Set("OpenAI-Beta", "codex-1")
	headers.Set("Originator", "Codex Desktop")
	if auth != nil && auth.Metadata != nil {
		if accountID, ok := auth.Metadata["account_id"].(string); ok && strings.TrimSpace(accountID) != "" {
			headers.Set("Chatgpt-Account-Id", strings.TrimSpace(accountID))
		}
	}
	return headers
}

func earliestCodexResetCreditExpiry(body []byte, now time.Time) time.Time {
	var earliest time.Time
	gjson.GetBytes(body, "credits").ForEach(func(_, credit gjson.Result) bool {
		resetType := firstGJSON(credit, "reset_type", "resetType").String()
		if resetType != "codex_rate_limits" || credit.Get("status").String() != "available" {
			return true
		}
		expiresAt := parseBankedResetTime(firstGJSON(credit, "expires_at", "expiresAt"))
		if expiresAt.IsZero() || !expiresAt.After(now) {
			return true
		}
		if earliest.IsZero() || expiresAt.Before(earliest) {
			earliest = expiresAt
		}
		return true
	})
	return earliest
}

// claudeResetGrant is a spendable grant from the cedar_ember usage block.
type claudeResetGrant struct {
	id               string
	endsAt           time.Time
	useRequiresLimit bool
}

// useExpiringClaudeResetGrant claims the earliest-expiring Claude reset grant
// once it expires within lead. Grants that require the account to be at its
// limit cannot be claimed otherwise and are left to expire.
func (m *Manager) useExpiringClaudeResetGrant(ctx context.Context, auth *Auth, now time.Time, lead time.Duration) (time.Time, error) {
	headers := claudeResetHeaders()
	body, err := m.bankedResetRequest(ctx, auth, http.MethodGet, claudeResetGrantStatusURL, nil, headers)
	if err != nil {
		return time.Time{}, fmt.Errorf("read claude reset grants: %w", err)
	}
	block := gjson.GetBytes(body, "cedar_ember")
	if !block.Get("eligible").Bool() {
		return time.Time{}, nil
	}
	grant, ok := earliestClaudeResetGrant(block, now)
	if !ok || grant.endsAt.Sub(now) > lead {
		return grant.endsAt, nil
	}
	if cooldown := parseBankedResetTime(block.Get("cooldown_until")); cooldown.After(now) {
		log.Debugf("banked reset: Claude reset grants for auth %s are cooling down until %s", auth.ID, cooldown.Format(time.RFC3339))
		return grant.endsAt, nil
	}
	if grant.useRequiresLimit && !block.Get("at_limit").Bool() {
		log.Debugf("banked reset: Claude reset grant %s for auth %s needs the account at its limit; not claimable yet", grant.id, auth.ID)
		return grant.endsAt, nil
	}

	organization, err := m.claudeOrganizationUUID(ctx, auth, headers)
	if err != nil {
		return grant.endsAt, err
	}
	payload, _ := json.Marshal(map[string]string{
		"program":    claudeResetGrantProgram,
		"grant_id":   grant.id,
		"request_id": uuid.NewString(),
	})
	claimURL := "https://api.anthropic.com/api/organizations/" + organization + "/reset_rate_limits"
	body, err = m.bankedResetRequest(ctx, auth, http.MethodPost, claimURL, payload, headers)
	if err != nil {
		return grant.endsAt, fmt.Errorf("claim claude reset grant: %w", err)
	}
	result := gjson.GetBytes(body, "result").String()
	if result != "reset" {
		log.Infof("banked reset: Claude reset grant %s for auth %s not used (result %q)", grant.id, auth.ID, result)
		return grant.endsAt, nil
	}
	log.Infof("banked reset: used Claude reset grant %s for auth %s (expires %s)", grant.id, auth.ID, grant.endsAt.Format(time.RFC3339))
	m.clearCooldownAfterBankedReset(ctx, auth.ID)
	return now, nil
}

func claudeResetHeaders() http.Header {
	headers := make(http.Header)
	headers.Set("Accept", "application/json")
	headers.Set("Content-Type", "application/json")
	headers.Set("User-Agent", claudeOAuthUserAgent)
	headers.Set("anthropic-beta", claudeOAuthBeta)
	return headers
}

// earliestClaudeResetGrant picks the claimable grant that expires first. Grants
// without an end time never expire and are ignored.
func earliestClaudeResetGrant(block gjson.Result, now time.Time) (claudeResetGrant, bool) {
	var best claudeResetGrant
	found := false
	block.Get("grants").ForEach(func(_, raw gjson.Result) bool {
		id := raw.Get("id").String()
		if !claudeResetGrantIDPattern.MatchString(id) || raw.Get("paused").Bool() ||
			!raw.Get("usable_now").Bool() || raw.Get("resets_left").Int() <= 0 {
			return true
		}
		if startsAt := parseBankedResetTime(raw.Get("starts_at")); startsAt.After(now) {
			return true
		}
		endsAt := parseBankedResetTime(raw.Get("ends_at"))
		if endsAt.IsZero() || !endsAt.After(now) {
			return true
		}
		if found && !endsAt.Before(best.endsAt) {
			return true
		}
		requiresLimit := raw.Get("use_requires_limit")
		best = claudeResetGrant{
			id:     id,
			endsAt: endsAt,
			// A grant that does not say otherwise is treated as needing the limit.
			useRequiresLimit: requiresLimit.Type == gjson.Null || requiresLimit.Bool(),
		}
		found = true
		return true
	})
	return best, found
}

func (m *Manager) claudeOrganizationUUID(ctx context.Context, auth *Auth, headers http.Header) (string, error) {
	if auth.Metadata != nil {
		if value, ok := auth.Metadata["organization_uuid"].(string); ok && claudeOrganizationPattern.MatchString(strings.TrimSpace(value)) {
			return strings.ToLower(strings.TrimSpace(value)), nil
		}
	}
	body, err := m.bankedResetRequest(ctx, auth, http.MethodGet, claudeProfileURL, nil, headers)
	if err != nil {
		return "", fmt.Errorf("read claude profile: %w", err)
	}
	value := gjson.GetBytes(body, "organization.uuid").String()
	if !claudeOrganizationPattern.MatchString(value) {
		return "", fmt.Errorf("read claude profile: missing organization uuid")
	}
	return strings.ToLower(value), nil
}

// clearCooldownAfterBankedReset drops the local quota cooldown so the freshly
// reset credential is selectable immediately.
func (m *Manager) clearCooldownAfterBankedReset(ctx context.Context, authID string) {
	if _, _, err := m.ResetQuota(ctx, authID); err != nil {
		log.Warnf("banked reset: failed to clear cooldown for auth %s: %v", authID, err)
	}
}

// bankedResetRequest sends an authenticated request and returns the body of a
// 2xx response; any other status is an error.
func (m *Manager) bankedResetRequest(ctx context.Context, auth *Auth, method, targetURL string, body []byte, headers http.Header) ([]byte, error) {
	req, err := m.NewHttpRequest(ctx, auth, method, targetURL, body, headers)
	if err != nil {
		return nil, err
	}
	resp, err := m.HttpRequest(ctx, auth, req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("banked reset: close response body: %v", errClose)
		}
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, bankedResetMaxBody))
}

func firstGJSON(value gjson.Result, keys ...string) gjson.Result {
	for _, key := range keys {
		if result := value.Get(key); result.Exists() {
			return result
		}
	}
	return gjson.Result{}
}

// parseBankedResetTime accepts RFC3339 strings and unix seconds or milliseconds.
func parseBankedResetTime(value gjson.Result) time.Time {
	switch value.Type {
	case gjson.String:
		text := strings.TrimSpace(value.String())
		if parsed, err := time.Parse(time.RFC3339, text); err == nil {
			return parsed
		}
		if seconds, err := strconv.ParseFloat(text, 64); err == nil {
			return unixBankedResetTime(seconds)
		}
	case gjson.Number:
		return unixBankedResetTime(value.Float())
	}
	return time.Time{}
}

func unixBankedResetTime(value float64) time.Time {
	if value <= 0 {
		return time.Time{}
	}
	if value > 1e12 {
		return time.UnixMilli(int64(value))
	}
	return time.Unix(int64(value), 0)
}
