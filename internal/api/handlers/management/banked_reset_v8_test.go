package management

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestAPICallV8BankedResetSharesAutomaticGuard(t *testing.T) {
	for _, provider := range []string{"codex", "claude"} {
		for _, automaticFirst := range []bool{true, false} {
			name := provider + "/dashboard-first"
			if automaticFirst {
				name = provider + "/automatic-first"
			}
			t.Run(name, func(t *testing.T) {
				manager := coreauth.NewManager(nil, nil, nil)
				account := "11111111-2222-3333-4444-555555555555"
				auth, err := manager.Register(context.Background(), &coreauth.Auth{
					ID: "credential", Provider: provider,
					Metadata: map[string]any{"account_id": account, "organization_uuid": account},
				})
				if err != nil {
					t.Fatal(err)
				}
				var calls atomic.Int32
				entered, release := make(chan struct{}), make(chan struct{})
				proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if provider == "codex" && r.Header.Get("Chatgpt-Account-Id") != account {
						t.Error("dashboard request did not select the reserved upstream account")
					}
					close(entered)
					<-release
					_, _ = io.WriteString(w, `{"result":"reset"}`)
				}))
				defer proxy.Close()
				target := "http://chatgpt.com/backend-api/wham/rate-limit-reset-credits/consume"
				if provider == "claude" {
					target = "http://api.anthropic.com/api/organizations/" + account + "/reset_rate_limits"
				}
				payload, err := json.Marshal(map[string]any{
					"auth_index": auth.Index, "method": "POST", "url": target,
					"proxy_url": proxy.URL, "data": `{"request_id":"manual"}`,
				})
				if err != nil {
					t.Fatal(err)
				}
				h := &Handler{authManager: manager}
				router := gin.New()
				router.POST("/", h.APICallV8)
				request := func() *httptest.ResponseRecorder {
					recorder := httptest.NewRecorder()
					req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(payload)))
					req.Header.Set("Content-Type", "application/json")
					router.ServeHTTP(recorder, req)
					return recorder
				}
				now := time.Now()
				if automaticFirst {
					finish, errBegin := manager.BeginBankedReset(provider, account, now, now.Add(4*time.Minute))
					if errBegin != nil {
						t.Fatal(errBegin)
					}
					if got := request(); got.Code != http.StatusConflict {
						t.Errorf("dashboard during automatic reset = %d, want 409", got.Code)
					}
					finish(true)
					if got := request(); got.Code != http.StatusConflict {
						t.Errorf("dashboard after automatic reset = %d, want 409", got.Code)
					}
					close(release)
					if calls.Load() != 0 {
						t.Fatal("duplicate dashboard reset reached upstream")
					}
					return
				}
				done := make(chan *httptest.ResponseRecorder, 1)
				go func() { done <- request() }()
				<-entered
				if finish, errBegin := manager.BeginBankedReset(provider, account, now, now.Add(4*time.Minute)); errBegin == nil {
					finish(true)
					t.Error("automatic reset allowed during dashboard reset")
				}
				if got := request(); got.Code != http.StatusConflict {
					t.Errorf("second dashboard request = %d, want 409", got.Code)
				}
				close(release)
				if got := <-done; got.Code != http.StatusOK {
					t.Fatalf("first dashboard request = %d: %s", got.Code, got.Body.String())
				}
				if got := request(); got.Code != http.StatusConflict {
					t.Errorf("dashboard retry = %d, want 409", got.Code)
				}
				if finish, errBegin := manager.BeginBankedReset(provider, account, now.Add(time.Minute), now.Add(4*time.Minute)); errBegin == nil {
					finish(true)
					t.Error("automatic reset allowed immediately after dashboard reset")
				}
				if got := calls.Load(); got != 1 {
					t.Fatalf("upstream resets = %d, want 1", got)
				}
			})
		}
	}
}

func TestAPICallV8BankedResetRequiresCredential(t *testing.T) {
	h := &Handler{}
	router := gin.New()
	router.POST("/", h.APICallV8)
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"method":"POST","url":"https://chatgpt.com/backend-api/wham/rate-limit-reset-credits/consume"}`))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
}

func TestAPICallV8LocalRejectionDoesNotRetainResetGate(t *testing.T) {
	for _, failure := range []string{"invalid-proxy", "missing-token"} {
		t.Run(failure, func(t *testing.T) {
			manager := coreauth.NewManager(nil, nil, nil)
			auth, err := manager.Register(context.Background(), &coreauth.Auth{
				ID: "credential", Provider: "codex", Metadata: map[string]any{"account_id": "acct"},
			})
			if err != nil {
				t.Fatal(err)
			}
			h := &Handler{authManager: manager}
			router := gin.New()
			router.POST("/", h.APICallV8)
			body := map[string]any{
				"auth_index": auth.Index, "method": "POST",
				"url": "https://chatgpt.com/backend-api/wham/rate-limit-reset-credits/consume",
			}
			if failure == "invalid-proxy" {
				body["proxy_url"] = "://invalid"
			} else {
				body["header"] = map[string]string{"Authorization": "Bearer $TOKEN$"}
			}
			data, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(data)))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("invalid request = %d, want 400: %s", recorder.Code, recorder.Body.String())
			}
			finish, err := manager.BeginBankedReset("codex", "acct", time.Now(), time.Time{})
			if err != nil {
				t.Fatalf("local rejection blocked a subsequent reset: %v", err)
			}
			finish(false)
		})
	}
}

func TestAPICallV8UpstreamErrorsRetainResetGate(t *testing.T) {
	for _, disconnected := range []bool{false, true} {
		t.Run(map[bool]string{false: "upstream-400", true: "lost-response"}[disconnected], func(t *testing.T) {
			manager := coreauth.NewManager(nil, nil, nil)
			auth, err := manager.Register(context.Background(), &coreauth.Auth{
				ID: "credential", Provider: "codex", Metadata: map[string]any{"account_id": "acct"},
			})
			if err != nil {
				t.Fatal(err)
			}
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if disconnected {
					conn, _, errHijack := w.(http.Hijacker).Hijack()
					if errHijack != nil {
						t.Error(errHijack)
						return
					}
					_ = conn.Close()
					return
				}
				w.WriteHeader(http.StatusBadRequest)
			}))
			defer proxy.Close()
			h := &Handler{authManager: manager}
			router := gin.New()
			router.POST("/", h.APICallV8)
			data, err := json.Marshal(map[string]any{
				"auth_index": auth.Index, "method": "POST", "proxy_url": proxy.URL,
				"url": "http://chatgpt.com/backend-api/wham/rate-limit-reset-credits/consume",
			})
			if err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(data)))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(recorder, req)
			want := http.StatusOK
			if disconnected {
				want = http.StatusBadGateway
			}
			if recorder.Code != want {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, want, recorder.Body.String())
			}
			if finish, err := manager.BeginBankedReset("codex", "acct", time.Now(), time.Time{}); err == nil {
				finish(true)
				t.Fatal("upstream outcome did not retain reset reservation")
			}
		})
	}
}
