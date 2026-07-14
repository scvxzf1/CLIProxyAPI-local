package management

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	log "github.com/sirupsen/logrus"
)

type credentialProbeResult struct {
	Status         string
	Detail         string
	StatusCode     int
	CredentialType string
}

var invalidCredentialMarkers = []string{
	"invalid or expired credentials",
	"x_xai_token_auth=none",
	"no auth context",
	"unauthenticated:bad-credentials",
	"bad-credentials",
	"could not be validated",
	"token_invalidated",
	"token_revoked",
	"refresh token has been revoked",
	"invalid_grant",
	"your authentication token has been invalidated",
	"auth token not found",
	"auth token refresh failed",
}

var quotaOrLimitMarkers = []string{
	"spending-limit",
	"personal-team-blocked",
	"run out of credits",
	"need a grok subscription",
	"add credits",
	"quota",
	"rate limit",
	"rate_limit",
	"usage_limit",
	"insufficient_quota",
	"resource_exhausted",
	"too many requests",
	"free-usage-exhausted",
	"included free usage",
	"rolling 24-hour",
	"subscription:free-usage-exhausted",
}

func probeCredentialContent(ctx context.Context, h *Handler, content []byte, item *credentialImportPreviewItem, timeoutSeconds int) credentialProbeResult {
	if timeoutSeconds < 1 {
		timeoutSeconds = 15
	}
	if ctx == nil {
		ctx = context.Background()
	}
	payload := map[string]any{}
	if item != nil && item.rawPayload != nil {
		payload = item.rawPayload
	}
	if len(payload) == 0 {
		decoded, err := decodeCredentialObject(content)
		if err != nil {
			return credentialProbeResult{Status: "failed", Detail: "测活失败：凭证 JSON 无法解析"}
		}
		payload = decoded
	}

	// Prefer prepared/refreshed content when available.
	if len(content) > 0 {
		if decoded, err := decodeCredentialObject(content); err == nil && len(decoded) > 0 {
			payload = decoded
		}
	}

	provider := strings.ToLower(strings.TrimSpace(importAsString(payload["type"])))
	if provider == "" && item != nil {
		provider = strings.ToLower(strings.TrimSpace(item.Provider))
	}

	// If access token is already expired but refresh_token exists, refresh first.
	// Do not treat local "expired" field alone as dead credential.
	refreshNote := ""
	if shouldRefreshBeforeProbe(payload) {
		updated, note, err := refreshCredentialPayload(ctx, h, payload, timeoutSeconds)
		if err != nil {
			// Refresh revoked/invalid => dead credential.
			return credentialProbeResult{Status: "failed", Detail: "刷新失败：" + shortProbeDetail(err.Error())}
		}
		payload = updated
		refreshNote = note
	}

	result := doCredentialProbe(ctx, h, provider, payload, timeoutSeconds)
	if result.Status == "failed" && strings.TrimSpace(importAsString(payload["refresh_token"])) != "" && !credentialRecentlyRefreshed(payload) && !strings.Contains(result.Detail, "刷新失败") {
		// Access token may be stale even when expired field is missing; try one refresh then re-probe.
		updated, note, err := refreshCredentialPayload(ctx, h, payload, timeoutSeconds)
		if err != nil {
			return credentialProbeResult{Status: "failed", Detail: result.Detail + "；二次刷新失败：" + shortProbeDetail(err.Error()), StatusCode: result.StatusCode}
		}
		payload = updated
		refreshNote = note
		result = doCredentialProbe(ctx, h, provider, payload, timeoutSeconds)
	}
	if refreshNote != "" {
		if result.Detail == "" {
			result.Detail = refreshNote
		} else {
			result.Detail = result.Detail + "；" + refreshNote
		}
	}
	// Keep refreshed payload on item so execute can persist refreshed tokens.
	if item != nil && payload != nil {
		item.rawPayload = payload
		if raw, err := json.MarshalIndent(payload, "", "  "); err == nil {
			item.rawContent = raw
		}
	}
	return result
}

func credentialRecentlyRefreshed(payload map[string]any) bool {
	lastRefresh, ok := parseFlexibleTime(payload["last_refresh"])
	return ok && lastRefresh.After(time.Now().UTC().Add(-time.Minute))
}

func shouldRefreshBeforeProbe(payload map[string]any) bool {
	if strings.TrimSpace(importAsString(payload["refresh_token"])) == "" {
		return false
	}
	exp, ok := parseFlexibleTime(payload["expired"])
	if !ok {
		return false
	}
	// Refresh a bit early to avoid edge races.
	return !exp.After(time.Now().UTC().Add(2 * time.Minute))
}

func doCredentialProbe(ctx context.Context, h *Handler, provider string, payload map[string]any, timeoutSeconds int) credentialProbeResult {
	token := strings.TrimSpace(importAsString(payload["access_token"]))
	if token == "" {
		token = strings.TrimSpace(importAsString(payload["key"]))
	}
	if token == "" {
		return credentialProbeResult{Status: "failed", Detail: "测活失败：缺少 access_token"}
	}

	method, urlStr, headers, body, supported := probeRequestForProvider(provider, payload, token)
	if !supported {
		return credentialProbeResult{Status: "uncertain", Detail: fmt.Sprintf("provider %s 暂不支持额度探测", firstNonEmptyImport(provider, "unknown"))}
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(timeoutCtx, method, urlStr, bodyReader)
	if err != nil {
		return credentialProbeResult{Status: "uncertain", Detail: "测活请求构建失败"}
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{Timeout: time.Duration(timeoutSeconds) * time.Second}
	if h != nil && h.cfg != nil {
		client = util.SetProxy(&h.cfg.SDKConfig, client)
	}
	resp, err := client.Do(req)
	if err != nil {
		status, detail := classifyProbeResponse(0, "", err)
		return credentialProbeResult{Status: status, Detail: detail}
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("credential import: close probe response body error: %v", errClose)
		}
	}()
	rawBody, errRead := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if errRead != nil {
		return credentialProbeResult{Status: "uncertain", Detail: "额度探测响应读取失败", StatusCode: resp.StatusCode}
	}
	bodyText := string(rawBody)
	status, detail := classifyProbeResponse(resp.StatusCode, bodyText, nil)
	credentialType := detectCredentialType(provider, payload, resp.StatusCode, bodyText, resp.Header)
	if credentialType != "unknown" {
		payload["plan_type"] = credentialType
		detail = credentialTypeLabel(credentialType) + "；" + detail
	}
	if provider == "xai" && credentialType == "free" {
		captureXAIFreeUsage(payload, resp.Header, bodyText)
	}
	if status == "healthy" {
		if plan := resp.Header.Get("x-codex-plan-type"); plan != "" {
			detail = detail + "；plan=" + plan
		}
	}
	return credentialProbeResult{Status: status, Detail: detail, StatusCode: resp.StatusCode, CredentialType: credentialType}
}

func detectCredentialType(provider string, payload map[string]any, statusCode int, bodyText string, headers http.Header) string {
	if planType := normalizeCredentialType(importAsString(payload["plan_type"])); planType != "unknown" {
		return planType
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	bodyLower := strings.ToLower(bodyText)
	switch provider {
	case "xai":
		if payload["free_usage"] != nil ||
			strings.Contains(bodyLower, "subscription:free-usage-exhausted") ||
			strings.Contains(bodyLower, "free-usage-exhausted") ||
			(strings.Contains(bodyLower, "included free usage") && strings.Contains(bodyLower, "rolling 24-hour")) ||
			(strings.Contains(bodyLower, "personal-team-blocked") && strings.Contains(bodyLower, "need a grok subscription")) ||
			hasXAIFreeUsageHeaders(headers) {
			return "free"
		}
		if statusCode >= 200 && statusCode < 300 {
			return "subscription"
		}
		if strings.Contains(bodyLower, "spending-limit") || strings.Contains(bodyLower, "run out of credits") {
			return "subscription"
		}
	case "codex":
		if plan := strings.TrimSpace(headers.Get("x-codex-plan-type")); plan != "" {
			if credentialType := normalizeCredentialType(plan); credentialType != "unknown" {
				return credentialType
			}
			return "subscription"
		}
	}
	return "unknown"
}

func normalizeCredentialType(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "free", "basic", "free_tier", "free-tier":
		return "free"
	case "subscription", "paid", "plus", "pro", "team", "business", "enterprise", "supergrok", "premium":
		return "subscription"
	default:
		return "unknown"
	}
}

func credentialTypeLabel(credentialType string) string {
	switch credentialType {
	case "free":
		return "Free 凭证"
	case "subscription":
		return "套餐凭证"
	default:
		return "类型未知"
	}
}

func hasXAIFreeUsageHeaders(headers http.Header) bool {
	if headers == nil {
		return false
	}
	for _, key := range []string{
		"x-ratelimit-limit-tokens",
		"x-ratelimit-remaining-tokens",
		"x-ratelimit-limit-requests",
		"x-ratelimit-remaining-requests",
	} {
		if strings.TrimSpace(headers.Get(key)) != "" {
			return true
		}
	}
	return false
}

func captureXAIFreeUsage(payload map[string]any, headers http.Header, bodyText string) {
	if payload == nil {
		return
	}
	source := "error_body"
	if hasXAIFreeUsageHeaders(headers) {
		source = "response_headers"
	}
	usage := map[string]any{
		"source":      source,
		"window":      "rolling_24h",
		"observed_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	if model := firstNonEmptyImport(
		strings.TrimSpace(importAsString(payload["grok_model_override"])),
		strings.TrimSpace(importAsString(payload["x_grok_model_override"])),
	); model != "" {
		usage["model"] = model
	}
	for header, field := range map[string]string{
		"x-ratelimit-limit-tokens":       "limit_tokens",
		"x-ratelimit-remaining-tokens":   "remaining_tokens",
		"x-ratelimit-limit-requests":     "limit_requests",
		"x-ratelimit-remaining-requests": "remaining_requests",
	} {
		if value, ok := parseProbeHeaderInt(headers, header); ok {
			usage[field] = value
		}
	}
	if compact := shortProbeDetail(bodyText); compact != "" {
		usage["message"] = compact
	}
	payload["free_usage"] = usage
}

func parseProbeHeaderInt(headers http.Header, key string) (int64, bool) {
	if headers == nil {
		return 0, false
	}
	raw := strings.TrimSpace(headers.Get(key))
	if raw == "" {
		return 0, false
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	return value, err == nil
}

func probeRequestForProvider(provider string, payload map[string]any, token string) (method, urlStr string, headers map[string]string, body string, supported bool) {
	switch provider {
	case "xai":
		model := firstNonEmptyImport(
			strings.TrimSpace(importAsString(payload["grok_model_override"])),
			strings.TrimSpace(importAsString(payload["x_grok_model_override"])),
			"grok-4.5-build-free",
		)
		version := firstNonEmptyImport(
			strings.TrimSpace(importAsString(payload["grok_cli_version"])),
			strings.TrimSpace(importAsString(payload["grok_version"])),
			strings.TrimSpace(importAsString(payload["x_grok_client_version"])),
			"0.2.93",
		)
		headers := map[string]string{
			"Authorization":         "Bearer " + token,
			"Content-Type":          "application/json",
			"Accept":                "application/json",
			"X-XAI-Token-Auth":      "xai-grok-cli",
			"x-grok-client-version": version,
			"x-grok-model-override": model,
			"User-Agent":            "xai-grok-workspace/" + version,
		}
		if clientID := firstNonEmptyImport(
			strings.TrimSpace(importAsString(payload["grok_client_identifier"])),
			strings.TrimSpace(importAsString(payload["grok_agent_id"])),
		); clientID != "" {
			headers["x-grok-client-identifier"] = clientID
		}
		probeBody, _ := json.Marshal(map[string]any{
			"model":             model,
			"input":             "ping",
			"max_output_tokens": 1,
			"stream":            false,
		})
		return http.MethodPost, "https://cli-chat-proxy.grok.com/v1/responses", headers, string(probeBody), true
	case "codex":
		model := firstNonEmptyImport(strings.TrimSpace(importAsString(payload["model"])), "gpt-5.3-codex")
		probeBody, _ := json.Marshal(map[string]any{
			"model":        model,
			"instructions": "Return the shortest possible response.",
			"input": []map[string]any{{
				"type":    "message",
				"role":    "user",
				"content": []map[string]string{{"type": "input_text", "text": "ping"}},
			}},
		})
		headers := map[string]string{
			"Authorization": "Bearer " + token,
			"Content-Type":  "application/json",
			"Accept":        "application/json",
			"User-Agent":    "codex-tui/0.135.0",
			"Originator":    "codex-tui",
		}
		if accountID := strings.TrimSpace(importAsString(payload["account_id"])); accountID != "" {
			headers["Chatgpt-Account-Id"] = accountID
		}
		return http.MethodPost, "https://chatgpt.com/backend-api/codex/responses/compact", headers, string(probeBody), true
	default:
		return "", "", nil, "", false
	}
}

func classifyProbeResponse(statusCode int, bodyText string, err error) (string, string) {
	if err != nil {
		detail := shortProbeDetail(err.Error())
		if containsAnyFold(detail, invalidCredentialMarkers) {
			return "failed", "凭证无效：" + detail
		}
		if containsAnyFold(detail, quotaOrLimitMarkers) {
			return "uncertain", "无额度/限流：" + detail
		}
		if detail == "" {
			detail = "探测异常"
		}
		return "uncertain", detail
	}

	code := statusCode
	body := bodyText
	compact := shortProbeDetail(body)

	if code >= 200 && code < 300 {
		return "healthy", fmt.Sprintf("HTTP %d", code)
	}
	// Quota/subscription first so 402/403 spending-limit is not treated as dead credential.
	if code == 402 || code == 429 || containsAnyFold(body, quotaOrLimitMarkers) {
		reason := compact
		if reason == "" {
			reason = fmt.Sprintf("HTTP %d", code)
		}
		return "uncertain", "凭证有效但无额度/受限：" + reason
	}
	if containsAnyFold(body, invalidCredentialMarkers) {
		reason := compact
		if reason == "" {
			reason = fmt.Sprintf("HTTP %d", code)
		}
		return "failed", "凭证无效：" + reason
	}
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		reason := compact
		if reason == "" {
			reason = fmt.Sprintf("HTTP %d", code)
		}
		return "failed", "凭证无效：" + reason
	}
	if code >= 500 || code == 0 {
		reason := compact
		if reason == "" {
			if code == 0 {
				reason = "无响应"
			} else {
				reason = fmt.Sprintf("HTTP %d", code)
			}
		}
		return "uncertain", reason
	}
	reason := compact
	if reason == "" {
		reason = fmt.Sprintf("HTTP %d", code)
	}
	return "uncertain", reason
}

func shortProbeDetail(text string, limits ...int) string {
	limit := 220
	if len(limits) > 0 && limits[0] > 0 {
		limit = limits[0]
	}
	cleaned := strings.Join(strings.Fields(strings.TrimSpace(text)), " ")
	if len(cleaned) <= limit {
		return cleaned
	}
	return cleaned[:limit-1] + "…"
}

func containsAnyFold(text string, markers []string) bool {
	lowered := strings.ToLower(text)
	for _, marker := range markers {
		if marker == "" {
			continue
		}
		if strings.Contains(lowered, strings.ToLower(marker)) {
			return true
		}
	}
	return false
}
