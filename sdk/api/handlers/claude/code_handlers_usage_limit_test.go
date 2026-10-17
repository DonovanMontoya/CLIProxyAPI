package claude

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	internallogging "github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

type usageLimitTestExecutor struct{}

func (usageLimitTestExecutor) Identifier() string { return "claude" }

func (usageLimitTestExecutor) Execute(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, &coreauth.Error{HTTPStatus: http.StatusInternalServerError, Message: "unexpected upstream call"}
}

func (usageLimitTestExecutor) ExecuteStream(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, &coreauth.Error{HTTPStatus: http.StatusInternalServerError, Message: "unexpected upstream call"}
}

func (usageLimitTestExecutor) Refresh(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	return auth, nil
}

func (usageLimitTestExecutor) CountTokens(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, &coreauth.Error{HTTPStatus: http.StatusNotImplemented, Message: "not implemented"}
}

func (usageLimitTestExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, &coreauth.Error{HTTPStatus: http.StatusNotImplemented, Message: "not implemented"}
}

// A Claude credential held by its usage reserve must be reported to Claude
// clients as an Anthropic rate limit that names its reset and asks not to retry.
func TestWriteClaudeErrorResponseReportsUsageLimitHold(t *testing.T) {
	const authID = "claude-usage-limit-handler"
	const model = "claude-usage-limit-handler-model"
	manager := coreauth.NewManager(nil, nil, nil)
	cfg := &internalconfig.Config{}
	cfg.QuotaExceeded.ClaudeReservePercent = 11
	manager.SetConfig(cfg)
	manager.RegisterExecutor(usageLimitTestExecutor{})
	if _, errRegister := manager.Register(context.Background(), &coreauth.Auth{ID: authID, Provider: "claude", Status: coreauth.StatusActive}); errRegister != nil {
		t.Fatalf("register: %v", errRegister)
	}
	registry.GetGlobalRegistry().RegisterClient(authID, "claude", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(authID) })

	resetAt := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	ctx := internallogging.WithResponseHeadersHolder(context.Background())
	internallogging.SetResponseHeaders(ctx, http.Header{
		"Anthropic-Ratelimit-Unified-5h-Utilization": []string{"0.93"},
		"Anthropic-Ratelimit-Unified-5h-Reset":       []string{strconv.FormatInt(resetAt.Unix(), 10)},
	})
	manager.MarkResult(ctx, coreauth.Result{AuthID: authID, Provider: "claude", Model: model, Success: true})

	_, errExecute := manager.Execute(context.Background(), []string{"claude"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
	if errExecute == nil {
		t.Fatal("request succeeded while the usage reserve holds the only credential")
	}

	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	(&ClaudeCodeAPIHandler{}).WriteErrorResponse(c, &interfaces.ErrorMessage{StatusCode: http.StatusTooManyRequests, Error: errExecute})

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", recorder.Code)
	}
	if got := gjson.GetBytes(recorder.Body.Bytes(), "error.type").String(); got != "rate_limit_error" {
		t.Fatalf("error.type = %q, want rate_limit_error; body=%s", got, recorder.Body.String())
	}
	headers := recorder.Header()
	if headers.Get("X-Should-Retry") != "false" || headers.Get("Anthropic-Ratelimit-Unified-Status") != "rejected" {
		t.Fatalf("headers = %v", headers)
	}
	reset, _ := strconv.ParseInt(headers.Get("Anthropic-Ratelimit-Unified-Reset"), 10, 64)
	if diff := reset - resetAt.Unix(); diff < -2 || diff > 2 {
		t.Fatalf("unified reset = %d, want ~%d", reset, resetAt.Unix())
	}
}
