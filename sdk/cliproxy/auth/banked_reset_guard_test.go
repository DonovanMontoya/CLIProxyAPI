package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBankedResetGuardConcurrentAccountAttempts(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	now := time.Now()
	var winners atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			finish, err := manager.BeginBankedReset("codex", "same-account", now, now.Add(4*time.Minute))
			if err == nil {
				winners.Add(1)
				finish()
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := winners.Load(); got != 1 {
		t.Fatalf("reset winners = %d, want 1", got)
	}
	// Another account can still reset independently.
	finish, err := manager.BeginBankedReset("codex", "other-account", now, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	finish()
}

func TestBankedResetGuardRetainsInFlightBeyondGate(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	now := time.Now()
	finish, err := manager.BeginBankedReset("claude", "ORG", now, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.BeginBankedReset("claude", "org", now.Add(time.Hour), time.Time{}); err == nil {
		t.Fatal("allowed a second reset while the first request was still in flight")
	}
	finish()
	if _, err = manager.BeginBankedReset("claude", "org", now.Add(time.Minute), time.Time{}); err == nil {
		t.Fatal("allowed a duplicate after completion")
	}
	finish, err = manager.BeginBankedReset("claude", "org", now.Add(time.Hour), time.Time{})
	if err != nil {
		t.Fatalf("new gate rejected: %v", err)
	}
	finish()
}

func TestBankedResetGuardRequiresAccountIdentity(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	if _, err := manager.BeginBankedReset("codex", " ", time.Now(), time.Time{}); err == nil {
		t.Fatal("allowed a reset without an account identity")
	}
}

func TestManager_BankedResetConcurrentWorkersAndStaleStatus(t *testing.T) {
	for _, provider := range []string{"codex", "claude"} {
		t.Run(provider, func(t *testing.T) {
			now := time.Now()
			expires := now.Add(3 * time.Minute).UTC().Format(time.RFC3339)
			org := "11111111-2222-3333-4444-555555555555"
			auth := &Auth{ID: "first", Provider: provider, Metadata: map[string]any{"account_id": "acct", "organization_uuid": org}}
			exec := &bankedResetExecutor{provider: provider, routes: map[string]string{}}
			post := codexResetCreditsConsumeURL
			if provider == "codex" {
				exec.routes["GET "+codexResetCreditsURL] = fmt.Sprintf(`{"credits":[{"id":"c1","reset_type":"codex_rate_limits","status":"available","expires_at":%q}]}`, expires)
			} else {
				post = "https://api.anthropic.com/api/organizations/" + org + "/reset_rate_limits"
				exec.routes["GET "+claudeResetGrantStatusURL] = fmt.Sprintf(`{"cedar_ember":{"eligible":true,"at_limit":true,"grants":[{"id":"g1","resets_left":3,"usable_now":true,"use_requires_limit":false,"ends_at":%q}]}}`, expires)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			exec.respond = func(req *http.Request) (*http.Response, error) {
				if req.Method == http.MethodPost {
					close(entered) // A duplicate POST also fails this test immediately.
					<-release
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"result":"reset"}`))}, nil
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(exec.routes["GET "+req.URL.String()]))}, nil
			}
			manager := newBankedResetManager(t, exec, auth, 5*time.Minute)
			duplicate := auth.Clone()
			duplicate.ID = "second-credential-same-account"
			if _, err := manager.Register(context.Background(), duplicate); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				manager.useExpiringBankedResets(context.Background(), now, make(map[string]*bankedResetState))
			}()
			<-entered
			// A new loop with a fresh status cache overlaps the old worker.
			manager.useExpiringBankedResets(context.Background(), now, make(map[string]*bankedResetState))
			close(release)
			<-done
			// The provider still reports the same grant/credit as available.
			manager.useExpiringBankedResets(context.Background(), now.Add(time.Minute), make(map[string]*bankedResetState))
			if got := exec.count("POST " + post); got != 1 {
				t.Fatalf("upstream mutations = %d, want 1", got)
			}
		})
	}
}
