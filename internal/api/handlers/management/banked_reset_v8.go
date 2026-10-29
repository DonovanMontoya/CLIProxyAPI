package management

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// APICallV8 coordinates dashboard reset mutations with the automatic reset loop.
// The legacy management contract remains unchanged.
func (h *Handler) APICallV8(c *gin.Context) {
	data, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(data))
	var body apiCallRequest
	if json.Unmarshal(data, &body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	provider, account := bankedResetTarget(body)
	if provider == "" {
		h.APICall(c)
		return
	}
	auth := h.authByIndex(firstNonEmptyString(body.AuthIndexSnake, body.AuthIndexCamel, body.AuthIndexPascal))
	if auth == nil || !strings.EqualFold(auth.Provider, provider) || h.authManager == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "reset requires a matching auth_index"})
		return
	}
	if provider == "codex" {
		account, _ = auth.Metadata["account_id"].(string)
		account = strings.TrimSpace(account)
		// Match the actual upstream account; never allow an override to acquire
		// a reservation for a different account than the automatic loop uses.
		for key, value := range body.Header {
			if strings.EqualFold(key, "Chatgpt-Account-Id") && strings.TrimSpace(value) != account {
				c.JSON(http.StatusBadRequest, gin.H{"error": "reset account does not match credential"})
				return
			}
		}
		// Select the same account explicitly even if an older dashboard omitted it.
		if body.Header == nil {
			body.Header = make(map[string]string)
		}
		body.Header["Chatgpt-Account-Id"] = account
		data, err = json.Marshal(body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(data))
	}
	finish, err := h.authManager.BeginBankedReset(provider, account, time.Now(), time.Time{})
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	defer finish()
	h.APICall(c)
}

func bankedResetTarget(body apiCallRequest) (provider, account string) {
	if !strings.EqualFold(strings.TrimSpace(body.Method), http.MethodPost) {
		return "", ""
	}
	u, err := url.Parse(strings.TrimSpace(body.URL))
	if err != nil {
		return "", ""
	}
	p := path.Clean(u.Path)
	switch strings.ToLower(u.Hostname()) {
	case "chatgpt.com":
		if p == "/backend-api/wham/rate-limit-reset-credits/consume" {
			return "codex", ""
		}
	case "api.anthropic.com":
		parts := strings.Split(strings.Trim(p, "/"), "/")
		if len(parts) == 4 && parts[0] == "api" && parts[1] == "organizations" && parts[3] == "reset_rate_limits" {
			return "claude", parts[2]
		}
	}
	return "", ""
}
