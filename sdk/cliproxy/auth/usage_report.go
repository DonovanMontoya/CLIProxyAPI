package auth

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// UsageWindowReport is one provider usage window of a credential, or the
// average of that window across a provider's credentials.
type UsageWindowReport struct {
	// Window names the window length, such as "5h" or "7d".
	Window           string  `json:"window"`
	UsedPercent      float64 `json:"used_percent"`
	RemainingPercent float64 `json:"remaining_percent"`
	// ResetsAt is when the window resets. It is omitted when upstream sent no
	// reset time, and once the observed reset time has passed, in which case
	// the window counts as unused.
	ResetsAt   *time.Time `json:"resets_at,omitempty"`
	ObservedAt time.Time  `json:"observed_at"`
}

// UsageProviderReport summarizes the usage windows of one provider's enabled
// credentials. Credentials are listed by position, ordered by ID, so the report
// carries no account details.
type UsageProviderReport struct {
	Provider      string                `json:"provider"`
	Windows       []UsageWindowReport   `json:"windows"`
	PerCredential [][]UsageWindowReport `json:"per_credential"`
}

// UsageReport returns the usage windows last reported by Codex and Claude for
// every enabled credential, built from the quota snapshots the proxy records
// from upstream responses. It makes no upstream requests, so a window is only
// as fresh as the last request that went through its credential.
func (m *Manager) UsageReport(now time.Time) []UsageProviderReport {
	byProvider := make(map[string]*UsageProviderReport)
	auths := m.List()
	sort.Slice(auths, func(i, j int) bool { return auths[i].ID < auths[j].ID })
	for _, auth := range auths {
		provider := usageLimitProvider(auth)
		if provider == "" || auth.Disabled {
			continue
		}
		windows := usageWindows(provider, auth.Quota)
		if len(windows) == 0 {
			continue
		}
		report := byProvider[provider]
		if report == nil {
			report = &UsageProviderReport{Provider: provider}
			byProvider[provider] = report
		}
		credential := make([]UsageWindowReport, 0, len(windows))
		for _, w := range windows {
			entry := UsageWindowReport{Window: usageWindowName(w.minutes), ObservedAt: auth.Quota.ObservedAt}
			if w.resetAt.IsZero() || w.resetAt.After(now) {
				entry.UsedPercent = math.Max(0, math.Min(100, w.used))
			}
			if w.resetAt.After(now) {
				resetAt := w.resetAt
				entry.ResetsAt = &resetAt
			}
			entry.RemainingPercent = 100 - entry.UsedPercent
			credential = append(credential, entry)
		}
		report.PerCredential = append(report.PerCredential, credential)
	}

	reports := make([]UsageProviderReport, 0, len(byProvider))
	for _, report := range byProvider {
		report.Windows = averageUsageWindows(report.PerCredential)
		reports = append(reports, *report)
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].Provider < reports[j].Provider })
	return reports
}

// averageUsageWindows averages each named window across credentials. The
// reset time is the earliest one and the observation time the latest one.
func averageUsageWindows(credentials [][]UsageWindowReport) []UsageWindowReport {
	var order []string
	sums := make(map[string]*UsageWindowReport)
	counts := make(map[string]int)
	for _, windows := range credentials {
		for _, w := range windows {
			sum := sums[w.Window]
			if sum == nil {
				sum = &UsageWindowReport{Window: w.Window}
				sums[w.Window] = sum
				order = append(order, w.Window)
			}
			sum.UsedPercent += w.UsedPercent
			if w.ResetsAt != nil && (sum.ResetsAt == nil || w.ResetsAt.Before(*sum.ResetsAt)) {
				sum.ResetsAt = w.ResetsAt
			}
			if w.ObservedAt.After(sum.ObservedAt) {
				sum.ObservedAt = w.ObservedAt
			}
			counts[w.Window]++
		}
	}
	averaged := make([]UsageWindowReport, 0, len(order))
	for _, name := range order {
		w := *sums[name]
		w.UsedPercent = math.Round(w.UsedPercent/float64(counts[name])*10) / 10
		w.RemainingPercent = math.Round((100-w.UsedPercent)*10) / 10
		averaged = append(averaged, w)
	}
	return averaged
}

// usageWindowName formats a window length as hours or days when it divides
// evenly, for example "5h" or "7d".
func usageWindowName(minutes int) string {
	switch {
	case minutes <= 0:
		return "unknown"
	case minutes%(24*60) == 0:
		return fmt.Sprintf("%dd", minutes/(24*60))
	case minutes%60 == 0:
		return fmt.Sprintf("%dh", minutes/60)
	default:
		return fmt.Sprintf("%dm", minutes)
	}
}
