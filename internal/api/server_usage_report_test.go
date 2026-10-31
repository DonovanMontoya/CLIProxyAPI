package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestUsageReportRouteRequiresClientKey(t *testing.T) {
	server := newTestServer(t)
	reset := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	if _, err := server.handlers.AuthManager.Register(context.Background(), &auth.Auth{
		ID:       "claude-a",
		Provider: "claude",
		Quota: auth.QuotaState{ObservedAt: time.Now(), Signals: map[string]string{
			"Anthropic-Ratelimit-Unified-5h-Utilization": "0.25",
			"Anthropic-Ratelimit-Unified-5h-Reset":       reset,
		}},
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	rr := httptest.NewRecorder()
	server.engine.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/usage", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status without key = %d, want %d", rr.Code, http.StatusUnauthorized)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/usage", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr = httptest.NewRecorder()
	server.engine.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Providers []auth.UsageProviderReport `json:"providers"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v body=%s", err, rr.Body.String())
	}
	if len(body.Providers) != 1 || len(body.Providers[0].Windows) != 1 || body.Providers[0].Windows[0].RemainingPercent != 75 {
		t.Fatalf("providers = %+v", body.Providers)
	}
}
