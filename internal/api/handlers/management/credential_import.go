package management

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/xai"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

const (
	importActionImport    = "import"
	importActionSkip      = "skip"
	importActionOverwrite = "overwrite"
	importActionRename    = "rename"

	maxCredentialImportFileBytes = 2 * 1024 * 1024
	maxCredentialImportFiles     = 500
	maxCredentialImportPathDepth = 8
	credentialImportCacheTTL     = 30 * time.Minute
)

var (
	pasteTailSeparator = regexp.MustCompile(`_{2,}|-{4,}`)
	unsafeFileChars    = regexp.MustCompile(`[\\/:*?"<>|\s]+`)
	multiUnderscore    = regexp.MustCompile(`_+`)
)

type credentialImportExisting struct {
	Name      string
	Provider  string
	Email     string
	AccountID string
}

type credentialImportPreviewItem struct {
	SourceName       string         `json:"source_name"`
	TargetName       string         `json:"target_name"`
	Provider         string         `json:"provider"`
	EmailMasked      string         `json:"email_masked"`
	AccountID        string         `json:"account_id"`
	Valid            bool           `json:"valid"`
	DuplicateType    string         `json:"duplicate_type"`
	ExpiredState     string         `json:"expired_state"`
	Warnings         []string       `json:"warnings"`
	Errors           []string       `json:"errors"`
	PlannedAction    string         `json:"planned_action"`
	AvailableActions []string       `json:"available_actions"`
	Summary          string         `json:"summary"`
	email            string         `json:"-"`
	rawPayload       map[string]any `json:"-"`
	rawContent       []byte         `json:"-"`
}

type credentialImportCacheEntry struct {
	created time.Time
	items   map[string]*credentialImportPreviewItem
}

type credentialImportSettings struct {
	RefreshTokens         bool `json:"import_refresh_tokens"`
	RefreshTimeoutSeconds int  `json:"import_refresh_timeout_seconds"`
	ProbeBeforeImport     bool `json:"import_probe_before"`
	ProbeTimeoutSeconds   int  `json:"import_probe_timeout_seconds"`
	ProbeMaxWorkers       int  `json:"import_probe_max_workers"`
	refreshTokensSet      bool
	refreshTimeoutSet     bool
	probeBeforeSet        bool
	probeTimeoutSet       bool
	probeWorkersSet       bool
}

type credentialImportExecuteAction struct {
	SourceName    string `json:"source_name"`
	TargetName    string `json:"target_name"`
	PlannedAction string `json:"planned_action"`
}

type credentialImportExecuteRequest struct {
	PreviewID            string                          `json:"preview_id"`
	Actions              []credentialImportExecuteAction `json:"actions"`
	ImportRefreshTokens  *bool                           `json:"import_refresh_tokens"`
	ImportRefreshTimeout *int                            `json:"import_refresh_timeout_seconds"`
	ImportProbeBefore    *bool                           `json:"import_probe_before"`
	ImportProbeTimeout   *int                            `json:"import_probe_timeout_seconds"`
	ImportProbeWorkers   *int                            `json:"import_probe_max_workers"`
}

type credentialImportPathRequest struct {
	Path string `json:"path"`
}

type credentialImportTextRequest struct {
	Text string `json:"text"`
}

type credentialImportResult struct {
	Name           string `json:"name"`
	Result         string `json:"result"`
	Detail         string `json:"detail"`
	CredentialType string `json:"credential_type"`
}

var (
	credentialImportCacheMu sync.Mutex
	credentialImportCache   = map[string]*credentialImportCacheEntry{}
	credentialImportPrefsMu sync.Mutex
	credentialImportPrefs   = credentialImportSettings{
		RefreshTokens:         true,
		RefreshTimeoutSeconds: 20,
		ProbeBeforeImport:     true,
		ProbeTimeoutSeconds:   15,
		ProbeMaxWorkers:       8,
	}
)

// GetCredentialImportSettings returns import-time defaults for the control panel.
func (h *Handler) GetCredentialImportSettings(c *gin.Context) {
	settings := loadCredentialImportSettings()
	c.JSON(http.StatusOK, serializeCredentialImportSettings(settings))
}

// PutCredentialImportSettings updates import-time defaults for the control panel.
func (h *Handler) PutCredentialImportSettings(c *gin.Context) {
	var payload credentialImportSettings
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	payload.refreshTokensSet = true
	payload.refreshTimeoutSet = true
	payload.probeBeforeSet = true
	payload.probeTimeoutSet = true
	payload.probeWorkersSet = true
	saved := saveCredentialImportSettings(payload)
	c.JSON(http.StatusOK, serializeCredentialImportSettings(saved))
}

// PreviewCredentialImportFiles previews multipart uploaded credential JSON files.
func (h *Handler) PreviewCredentialImportFiles(c *gin.Context) {
	fileItems, err := readCredentialImportMultipart(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(fileItems) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no files uploaded"})
		return
	}
	h.respondCredentialImportPreview(c, fileItems)
}

// PreviewCredentialImportText previews pasted credential text.
func (h *Handler) PreviewCredentialImportText(c *gin.Context) {
	var payload credentialImportTextRequest
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	fileItems, err := parsePasteImportText(payload.Text)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(fileItems) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未识别到有效凭证 JSON"})
		return
	}
	h.respondCredentialImportPreview(c, fileItems)
}

// PreviewCredentialImportPath previews credential JSON from a local absolute path.
func (h *Handler) PreviewCredentialImportPath(c *gin.Context) {
	var payload credentialImportPathRequest
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	fileItems, err := collectLocalImportItems(payload.Path)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.respondCredentialImportPreview(c, fileItems)
}

// ExecuteCredentialImport applies a previously previewed credential import batch.
func (h *Handler) ExecuteCredentialImport(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config unavailable"})
		return
	}
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	var payload credentialImportExecuteRequest
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	previewID := strings.TrimSpace(payload.PreviewID)
	if previewID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "preview_id required"})
		return
	}
	cache := takeCredentialImportPreview(previewID)
	if cache == nil || len(cache.items) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "预检缓存不存在或已过期，请重新预检"})
		return
	}

	settings := loadCredentialImportSettings()
	refreshTokens := settings.RefreshTokens
	if payload.ImportRefreshTokens != nil {
		refreshTokens = *payload.ImportRefreshTokens
	}
	refreshTimeout := settings.RefreshTimeoutSeconds
	if payload.ImportRefreshTimeout != nil {
		refreshTimeout = *payload.ImportRefreshTimeout
	}
	if refreshTimeout < 1 {
		refreshTimeout = 20
	}
	probeBefore := settings.ProbeBeforeImport
	if payload.ImportProbeBefore != nil {
		probeBefore = *payload.ImportProbeBefore
	}
	probeTimeout := settings.ProbeTimeoutSeconds
	if payload.ImportProbeTimeout != nil {
		probeTimeout = *payload.ImportProbeTimeout
	}
	if probeTimeout < 1 {
		probeTimeout = 15
	}
	probeWorkers := settings.ProbeMaxWorkers
	if payload.ImportProbeWorkers != nil {
		probeWorkers = *payload.ImportProbeWorkers
	}
	if probeWorkers < 1 {
		probeWorkers = 8
	}
	if probeWorkers > 32 {
		probeWorkers = 32
	}

	existing := h.listCredentialImportExisting()
	reserved := make(map[string]struct{}, len(existing)+len(payload.Actions))
	for _, item := range existing {
		reserved[item.Name] = struct{}{}
	}

	type preparedItem struct {
		item       *credentialImportPreviewItem
		targetName string
		action     string
	}
	prepared := make([]preparedItem, 0, len(payload.Actions))
	if len(payload.Actions) == 0 {
		keys := make([]string, 0, len(cache.items))
		for key := range cache.items {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			item := cache.items[key]
			payload.Actions = append(payload.Actions, credentialImportExecuteAction{
				SourceName:    item.SourceName,
				TargetName:    item.TargetName,
				PlannedAction: item.PlannedAction,
			})
		}
	}

	for _, action := range payload.Actions {
		source := strings.TrimSpace(action.SourceName)
		item := cache.items[source]
		if item == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("缺少预检缓存：%s，请先 preview", source)})
			return
		}
		planned := strings.TrimSpace(action.PlannedAction)
		if planned == "" {
			planned = item.PlannedAction
		}
		if !importContainsString(item.AvailableActions, planned) {
			if importContainsString(item.AvailableActions, importActionSkip) {
				planned = importActionSkip
			} else {
				planned = item.PlannedAction
			}
		}
		targetName := strings.TrimSpace(action.TargetName)
		if targetName == "" {
			targetName = item.TargetName
		}
		if targetName == "" {
			targetName = item.SourceName
		}
		targetName = filepath.Base(targetName)
		if !strings.HasSuffix(strings.ToLower(targetName), ".json") {
			targetName += ".json"
		}
		if isUnsafeAuthFileName(targetName) {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid target name: %s", targetName)})
			return
		}
		if planned == importActionRename {
			targetName = nextAvailableImportName(targetName, reserved)
		}
		if planned != importActionSkip {
			reserved[targetName] = struct{}{}
		}
		prepared = append(prepared, preparedItem{item: item, targetName: targetName, action: planned})
	}

	ctx := c.Request.Context()
	results := make([]credentialImportResult, 0, len(prepared))
	success, failed, skipped := 0, 0, 0

	type workItem struct {
		idx        int
		row        preparedItem
		content    []byte
		prepDetail string
		probe      credentialProbeResult
	}

	// First pass: honor explicit skips and prepare content for candidates.
	works := make([]workItem, 0, len(prepared))
	for idx, row := range prepared {
		if row.action == importActionSkip {
			skipped++
			results = append(results, credentialImportResult{
				Name:           row.targetName,
				Result:         "跳过",
				Detail:         row.item.Summary,
				CredentialType: detectCredentialType(row.item.Provider, row.item.rawPayload, 0, "", nil),
			})
			continue
		}
		content, detail := prepareImportContent(ctx, h, row.item, refreshTokens, refreshTimeout)
		works = append(works, workItem{
			idx:        idx,
			row:        row,
			content:    content,
			prepDetail: detail,
		})
	}

	// Concurrent liveness/quota probe before writing any credential.
	if probeBefore && len(works) > 0 {
		var wg sync.WaitGroup
		sem := make(chan struct{}, probeWorkers)
		for i := range works {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				works[i].probe = probeCredentialContent(ctx, h, works[i].content, works[i].row.item, probeTimeout)
				if updated := works[i].row.item.rawContent; len(updated) > 0 {
					works[i].content = append([]byte(nil), updated...)
				}
			}(i)
		}
		wg.Wait()
	}

	for _, work := range works {
		detailParts := make([]string, 0, 3)
		credentialType := work.probe.CredentialType
		if credentialType == "" || credentialType == "unknown" {
			credentialType = detectCredentialType(work.row.item.Provider, work.row.item.rawPayload, 0, "", nil)
		}
		if work.prepDetail != "" {
			detailParts = append(detailParts, work.prepDetail)
		}
		if probeBefore {
			detailParts = append(detailParts, "测活:"+work.probe.Detail)
			if work.probe.Status == "failed" {
				skipped++
				results = append(results, credentialImportResult{
					Name:           work.row.targetName,
					Result:         "跳过",
					Detail:         strings.Join(detailParts, "；"),
					CredentialType: credentialType,
				})
				continue
			}
		}
		if err := h.writeAuthFile(ctx, work.row.targetName, work.content); err != nil {
			failed++
			detailParts = append(detailParts, err.Error())
			results = append(results, credentialImportResult{
				Name:           work.row.targetName,
				Result:         "失败",
				Detail:         strings.Join(detailParts, "；"),
				CredentialType: credentialType,
			})
			continue
		}
		success++
		if !probeBefore {
			// keep original detail
		}
		results = append(results, credentialImportResult{
			Name:           work.row.targetName,
			Result:         "成功",
			Detail:         strings.Join(detailParts, "；"),
			CredentialType: credentialType,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"success": success,
		"failed":  failed,
		"skipped": skipped,
		"probed":  probeBefore,
		"results": results,
	})
}

func (h *Handler) respondCredentialImportPreview(c *gin.Context, fileItems []importFileItem) {
	existing := h.listCredentialImportExisting()
	now := time.Now().UTC()
	items := make([]*credentialImportPreviewItem, 0, len(fileItems))
	for _, fileItem := range fileItems {
		items = append(items, previewCredentialImportFile(fileItem.Name, fileItem.Content, existing, now))
	}
	previewID := storeCredentialImportPreview(items)
	serialized := make([]gin.H, 0, len(items))
	for _, item := range items {
		serialized = append(serialized, serializeCredentialImportPreview(item))
	}
	c.JSON(http.StatusOK, gin.H{
		"preview_id": previewID,
		"items":      serialized,
		"total":      len(serialized),
	})
}

func (h *Handler) listCredentialImportExisting() []credentialImportExisting {
	out := make([]credentialImportExisting, 0)
	if h == nil {
		return out
	}
	if h.authManager != nil {
		for _, auth := range h.authManager.List() {
			entry := h.buildAuthFileEntry(auth)
			if entry == nil {
				continue
			}
			name, _ := entry["name"].(string)
			if strings.TrimSpace(name) == "" {
				continue
			}
			provider, _ := entry["type"].(string)
			if provider == "" {
				provider, _ = entry["provider"].(string)
			}
			email, _ := entry["email"].(string)
			accountID := ""
			if account, ok := entry["account"].(string); ok {
				accountID = account
			}
			out = append(out, credentialImportExisting{
				Name:      name,
				Provider:  strings.ToLower(strings.TrimSpace(provider)),
				Email:     strings.TrimSpace(email),
				AccountID: strings.TrimSpace(accountID),
			})
		}
		if len(out) > 0 {
			return out
		}
	}
	if h.cfg == nil || strings.TrimSpace(h.cfg.AuthDir) == "" {
		return out
	}
	entries, err := os.ReadDir(h.cfg.AuthDir)
	if err != nil {
		return out
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".json") {
			continue
		}
		item := credentialImportExisting{Name: name}
		full := filepath.Join(h.cfg.AuthDir, name)
		if data, errRead := os.ReadFile(full); errRead == nil {
			item.Provider = strings.ToLower(strings.TrimSpace(gjson.GetBytes(data, "type").String()))
			item.Email = strings.TrimSpace(gjson.GetBytes(data, "email").String())
			item.AccountID = strings.TrimSpace(gjson.GetBytes(data, "account_id").String())
			if item.AccountID == "" {
				item.AccountID = strings.TrimSpace(gjson.GetBytes(data, "sub").String())
			}
		}
		out = append(out, item)
	}
	return out
}

type importFileItem struct {
	Name    string
	Content []byte
}

func readCredentialImportMultipart(c *gin.Context) ([]importFileItem, error) {
	if c == nil {
		return nil, fmt.Errorf("request unavailable")
	}
	if c.ContentType() != "multipart/form-data" {
		return nil, fmt.Errorf("multipart form required")
	}
	form, err := c.MultipartForm()
	if err != nil {
		return nil, fmt.Errorf("invalid multipart form: %w", err)
	}
	if form == nil || len(form.File) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(form.File))
	for key := range form.File {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	items := make([]importFileItem, 0)
	for _, key := range keys {
		for _, header := range form.File[key] {
			item, errRead := readImportFileHeader(header)
			if errRead != nil {
				return nil, errRead
			}
			if strings.HasSuffix(strings.ToLower(item.Name), ".txt") {
				parsed, errParse := parsePasteImportText(string(item.Content))
				if errParse != nil {
					return nil, fmt.Errorf("%s: %w", item.Name, errParse)
				}
				if len(parsed) == 0 {
					return nil, fmt.Errorf("%s: 未识别到凭证 JSON", item.Name)
				}
				items = append(items, parsed...)
				continue
			}
			items = append(items, item)
		}
	}
	if len(items) > maxCredentialImportFiles {
		return nil, fmt.Errorf("一次最多导入 %d 个文件", maxCredentialImportFiles)
	}
	return items, nil
}

func readImportFileHeader(header *multipart.FileHeader) (importFileItem, error) {
	if header == nil {
		return importFileItem{}, fmt.Errorf("empty file header")
	}
	name := filepath.Base(strings.TrimSpace(header.Filename))
	if name == "" || name == "." || name == string(filepath.Separator) {
		name = "import.json"
	}
	lowerName := strings.ToLower(name)
	if !(strings.HasSuffix(lowerName, ".json") || strings.HasSuffix(lowerName, ".txt")) {
		return importFileItem{}, fmt.Errorf("file must be .json or .txt: %s", name)
	}
	if header.Size > maxCredentialImportFileBytes {
		return importFileItem{}, fmt.Errorf("文件过大（>%d 字节）：%s", maxCredentialImportFileBytes, name)
	}
	src, err := header.Open()
	if err != nil {
		return importFileItem{}, fmt.Errorf("failed to open uploaded file: %w", err)
	}
	defer func() {
		if errClose := src.Close(); errClose != nil {
			log.Errorf("credential import: close uploaded file error: %v", errClose)
		}
	}()
	data, err := io.ReadAll(io.LimitReader(src, maxCredentialImportFileBytes+1))
	if err != nil {
		return importFileItem{}, fmt.Errorf("failed to read uploaded file: %w", err)
	}
	if len(data) > maxCredentialImportFileBytes {
		return importFileItem{}, fmt.Errorf("文件过大（>%d 字节）：%s", maxCredentialImportFileBytes, name)
	}
	return importFileItem{Name: name, Content: data}, nil
}

func parsePasteImportText(text string) ([]importFileItem, error) {
	raw := strings.TrimSpace(strings.TrimPrefix(text, "\ufeff"))
	if raw == "" {
		return nil, fmt.Errorf("粘贴内容为空")
	}
	items := make([]importFileItem, 0)
	reserved := make(map[string]struct{})
	i := 0
	n := len(raw)
	for i < n {
		for i < n && importIsSpace(raw[i]) {
			i++
		}
		if i >= n {
			break
		}
		if raw[i] != '{' {
			next := strings.IndexByte(raw[i:], '{')
			if next < 0 {
				break
			}
			i += next
			continue
		}
		payload, end, err := decodeJSONObjectAt(raw, i)
		if err != nil {
			i++
			continue
		}
		if looksLikeCredentialPayload(payload) {
			normalized := normalizePastedPayload(payload)
			filename := suggestCredentialFilename(normalized, reserved)
			reserved[filename] = struct{}{}
			content, errMarshal := json.MarshalIndent(normalized, "", "  ")
			if errMarshal != nil {
				return nil, fmt.Errorf("序列化凭证失败：%w", errMarshal)
			}
			items = append(items, importFileItem{Name: filename, Content: content})
		}
		i = end
		for i < n && importIsSpace(raw[i]) {
			i++
		}
		if i < n && (raw[i] == '_' || raw[i] == '-') {
			if loc := pasteTailSeparator.FindStringIndex(raw[i:]); loc != nil && loc[0] == 0 {
				i += loc[1]
				for i < n && !importIsSpace(raw[i]) && raw[i] != '{' {
					i++
				}
			}
		}
	}
	return items, nil
}

func decodeJSONObjectAt(raw string, start int) (map[string]any, int, error) {
	decoder := json.NewDecoder(strings.NewReader(raw[start:]))
	decoder.UseNumber()
	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil {
		return nil, start, err
	}
	offset := int(decoder.InputOffset())
	return payload, start + offset, nil
}

func collectLocalImportItems(pathText string) ([]importFileItem, error) {
	raw := strings.TrimSpace(pathText)
	raw = strings.Trim(raw, `"'`)
	if raw == "" {
		return nil, fmt.Errorf("路径为空")
	}
	path := filepath.Clean(raw)
	if strings.HasPrefix(path, "~") {
		home, errHome := os.UserHomeDir()
		if errHome != nil {
			return nil, fmt.Errorf("无法展开 ~：%w", errHome)
		}
		if path == "~" {
			path = home
		} else if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
			path = filepath.Join(home, path[2:])
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("路径不存在：%s", raw)
		}
		return nil, fmt.Errorf("无法访问路径：%s（%v）", raw, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		resolved, errResolve := filepath.EvalSymlinks(path)
		if errResolve != nil {
			return nil, fmt.Errorf("无法解析路径：%s（%v）", raw, errResolve)
		}
		path = resolved
		info, err = os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("无法访问路径：%s（%v）", raw, err)
		}
	}
	if info.IsDir() {
		files := make([]string, 0)
		errWalk := filepath.WalkDir(path, func(current string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				rel, errRel := filepath.Rel(path, current)
				if errRel == nil && rel != "." {
					depth := strings.Count(rel, string(filepath.Separator))
					if depth >= maxCredentialImportPathDepth {
						return filepath.SkipDir
					}
				}
				return nil
			}
			nameLower := strings.ToLower(d.Name())
			if !(strings.HasSuffix(nameLower, ".json") || strings.HasSuffix(nameLower, ".txt")) {
				return nil
			}
			files = append(files, current)
			if len(files) > maxCredentialImportFiles {
				return fmt.Errorf("目录内 JSON 过多（>%d），请缩小范围", maxCredentialImportFiles)
			}
			return nil
		})
		if errWalk != nil {
			return nil, errWalk
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("目录下未找到 .json：%s", path)
		}
		sort.Strings(files)
		items := make([]importFileItem, 0, len(files))
		usedNames := make(map[string]struct{}, len(files))
		for _, filePath := range files {
			item, errRead := readLocalJSONFile(filePath)
			if errRead != nil {
				return nil, errRead
			}
			if strings.HasSuffix(strings.ToLower(item.Name), ".txt") {
				parsed, errParse := parsePasteImportText(string(item.Content))
				if errParse != nil {
					return nil, fmt.Errorf("%s: %w", item.Name, errParse)
				}
				for _, p := range parsed {
					name := p.Name
					if _, exists := usedNames[name]; exists {
						name = nextAvailableImportName(name, usedNames)
						p.Name = name
					}
					usedNames[name] = struct{}{}
					items = append(items, p)
				}
				continue
			}
			name := item.Name
			if _, exists := usedNames[name]; exists {
				rel, errRel := filepath.Rel(path, filePath)
				if errRel != nil {
					rel = filepath.Base(filePath)
				}
				stem := sanitizeFilenamePart(strings.TrimSuffix(rel, filepath.Ext(rel)), 120)
				name = stem + ".json"
				index := 1
				for {
					if _, existsName := usedNames[name]; !existsName {
						break
					}
					name = fmt.Sprintf("%s (%d).json", stem, index)
					index++
				}
				item.Name = name
			}
			usedNames[item.Name] = struct{}{}
			items = append(items, item)
		}
		return items, nil
	}
	item, err := readLocalJSONFile(path)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(strings.ToLower(item.Name), ".txt") {
		parsed, errParse := parsePasteImportText(string(item.Content))
		if errParse != nil {
			return nil, errParse
		}
		if len(parsed) == 0 {
			return nil, fmt.Errorf("txt 中未识别到凭证 JSON：%s", item.Name)
		}
		return parsed, nil
	}
	return []importFileItem{item}, nil
}

func readLocalJSONFile(path string) (importFileItem, error) {
	info, err := os.Stat(path)
	if err != nil {
		return importFileItem{}, fmt.Errorf("无法读取文件：%s（%v）", path, err)
	}
	if !info.Mode().IsRegular() {
		return importFileItem{}, fmt.Errorf("不是文件：%s", path)
	}
	lower := strings.ToLower(path)
	if !(strings.HasSuffix(lower, ".json") || strings.HasSuffix(lower, ".txt")) {
		return importFileItem{}, fmt.Errorf("仅支持 .json/.txt：%s", filepath.Base(path))
	}
	if info.Size() > maxCredentialImportFileBytes {
		return importFileItem{}, fmt.Errorf("文件过大（>%d 字节）：%s", maxCredentialImportFileBytes, filepath.Base(path))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return importFileItem{}, fmt.Errorf("读取失败：%s（%v）", path, err)
	}
	return importFileItem{Name: filepath.Base(path), Content: data}, nil
}

func previewCredentialImportFile(filename string, rawContent []byte, existing []credentialImportExisting, now time.Time) *credentialImportPreviewItem {
	warnings := make([]string, 0)
	errors := make([]string, 0)
	sourceName := filepath.Base(filename)
	if !strings.HasSuffix(strings.ToLower(sourceName), ".json") {
		errors = append(errors, "文件扩展名不是 .json")
	}

	payload := map[string]any{}
	if decoded, err := decodeCredentialObject(rawContent); err != nil {
		errors = append(errors, "JSON 解析失败")
	} else {
		payload = decoded
	}

	provider := strings.ToLower(strings.TrimSpace(importAsString(payload["type"])))
	email := strings.TrimSpace(importAsString(payload["email"]))
	accountID := strings.TrimSpace(importAsString(payload["account_id"]))
	if accountID == "" {
		accountID = strings.TrimSpace(importAsString(payload["sub"]))
	}
	expiresAt, expiresOK := parseFlexibleTime(payload["expired"])
	lastRefresh, lastRefreshOK := parseFlexibleTime(payload["last_refresh"])

	if len(payload) > 0 && provider == "" {
		errors = append(errors, "缺少 type 字段")
	}

	required := requiredFieldsByProvider(provider)
	missing := make([]string, 0)
	for _, field := range required {
		if strings.TrimSpace(importAsString(payload[field])) == "" {
			missing = append(missing, field)
		}
	}
	if len(missing) > 0 {
		label := provider
		if label == "" {
			label = "凭证"
		}
		errors = append(errors, fmt.Sprintf("%s 缺少字段：%s", label, strings.Join(missing, ", ")))
	} else if provider != "" && len(required) == 0 {
		if strings.TrimSpace(importAsString(payload["access_token"])) == "" && strings.TrimSpace(importAsString(payload["key"])) == "" {
			errors = append(errors, fmt.Sprintf("未知 provider「%s」缺少 access_token", provider))
		}
	}

	if provider == "codex" || provider == "xai" {
		if rawID := strings.TrimSpace(importAsString(payload["id_token"])); rawID != "" && strings.Count(rawID, ".") != 2 {
			warnings = append(warnings, "id_token 不是标准三段 JWT")
		}
		if rawAccess := strings.TrimSpace(importAsString(payload["access_token"])); rawAccess != "" && strings.Count(rawAccess, ".") != 2 {
			warnings = append(warnings, "access_token 不是标准三段 JWT")
		}
	}

	if payload["expired"] != nil && importAsString(payload["expired"]) != "" && !expiresOK {
		errors = append(errors, "过期时间格式非法")
	}
	if payload["last_refresh"] != nil && importAsString(payload["last_refresh"]) != "" && !lastRefreshOK {
		warnings = append(warnings, "上次刷新时间格式非法")
	}

	expiredState := "unknown"
	if expiresOK {
		expiredState = "valid"
		if !expiresAt.After(now) {
			expiredState = "expired"
			warnings = append(warnings, "凭证已过期")
		} else if !expiresAt.After(now.Add(24 * time.Hour)) {
			expiredState = "expiring"
			warnings = append(warnings, "凭证将在 24 小时内过期")
		}
	}
	if lastRefreshOK && expiresOK && lastRefresh.After(expiresAt) {
		warnings = append(warnings, "上次刷新时间晚于过期时间")
	}

	hasRefreshToken := strings.TrimSpace(importAsString(payload["refresh_token"])) != ""
	if expiredState == "expired" && hasRefreshToken {
		warnings = append(warnings, "含 refresh_token，确认导入后将尝试刷新")
	}

	targetName := sourceName
	duplicateType := classifyImportDuplicate(targetName, provider, email, accountID, existing)
	switch duplicateType {
	case "name":
		warnings = append(warnings, "与现有文件同名")
	case "":
	default:
		warnings = append(warnings, "与现有凭证重复")
	}

	valid := len(errors) == 0
	available := []string{importActionSkip}
	planned := importActionSkip
	switch {
	case duplicateType == "name":
		available = []string{importActionSkip, importActionOverwrite, importActionRename}
		planned = importActionSkip
	case duplicateType != "":
		available = []string{importActionSkip, importActionImport}
		planned = importActionSkip
	case valid && expiredState == "expired":
		available = []string{importActionSkip, importActionImport}
		if hasRefreshToken {
			planned = importActionImport
		} else {
			planned = importActionSkip
		}
	case valid:
		available = []string{importActionImport, importActionSkip}
		planned = importActionImport
	default:
		available = []string{importActionSkip}
		planned = importActionSkip
	}

	item := &credentialImportPreviewItem{
		SourceName:       sourceName,
		TargetName:       targetName,
		Provider:         firstNonEmptyImport(provider, "unknown"),
		EmailMasked:      importMaskEmail(email),
		AccountID:        accountID,
		Valid:            valid,
		DuplicateType:    duplicateType,
		ExpiredState:     expiredState,
		Warnings:         warnings,
		Errors:           errors,
		PlannedAction:    planned,
		AvailableActions: available,
		email:            email,
		rawPayload:       payload,
		rawContent:       append([]byte(nil), rawContent...),
	}
	item.Summary = buildImportPreviewSummary(item)
	return item
}

func prepareImportContent(ctx context.Context, h *Handler, item *credentialImportPreviewItem, refreshTokens bool, timeoutSeconds int) ([]byte, string) {
	if item == nil {
		return nil, "空预检项"
	}
	if !refreshTokens {
		return item.rawContent, "已导入"
	}
	payload := item.rawPayload
	if payload == nil {
		decoded, err := decodeCredentialObject(item.rawContent)
		if err != nil {
			return item.rawContent, "已导入（无法解析 JSON，跳过刷新）"
		}
		payload = decoded
	}
	if strings.TrimSpace(importAsString(payload["refresh_token"])) == "" {
		return item.rawContent, "已导入（无 refresh_token）"
	}
	updated, note, err := refreshCredentialPayload(ctx, h, payload, timeoutSeconds)
	if err != nil {
		// Keep original content; probe stage will refresh again and skip if still dead.
		return item.rawContent, fmt.Sprintf("预刷新失败：%v", err)
	}
	// Update in-memory payload so subsequent probe uses refreshed token.
	item.rawPayload = updated
	content, errMarshal := json.MarshalIndent(updated, "", "  ")
	if errMarshal != nil {
		return item.rawContent, "已导入（刷新结果序列化失败，保留原内容）"
	}
	return content, fmt.Sprintf("已导入（%s）", note)
}

func refreshCredentialPayload(ctx context.Context, h *Handler, payload map[string]any, timeoutSeconds int) (map[string]any, string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeoutSeconds < 1 {
		timeoutSeconds = 20
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	provider := strings.ToLower(strings.TrimSpace(importAsString(payload["type"])))
	refreshToken := strings.TrimSpace(importAsString(payload["refresh_token"]))
	if refreshToken == "" {
		return payload, "无 refresh_token，跳过刷新", nil
	}

	updated := importCloneMap(payload)
	switch provider {
	case "xai":
		auth := xai.NewXAIAuth(h.cfg)
		tokenEndpoint := strings.TrimSpace(importAsString(payload["token_endpoint"]))
		tokenData, err := auth.RefreshTokens(timeoutCtx, refreshToken, tokenEndpoint)
		if err != nil {
			return nil, "", err
		}
		if tokenData.AccessToken != "" {
			updated["access_token"] = tokenData.AccessToken
		}
		if tokenData.RefreshToken != "" {
			updated["refresh_token"] = tokenData.RefreshToken
		}
		if tokenData.IDToken != "" {
			updated["id_token"] = tokenData.IDToken
		}
		if tokenData.TokenType != "" {
			updated["token_type"] = tokenData.TokenType
		}
		if tokenData.ExpiresIn > 0 {
			updated["expires_in"] = tokenData.ExpiresIn
		}
		if tokenData.Expire != "" {
			updated["expired"] = tokenData.Expire
		}
		if tokenData.Email != "" {
			updated["email"] = tokenData.Email
		}
		if tokenData.Subject != "" {
			updated["sub"] = tokenData.Subject
		}
		if tokenEndpoint != "" {
			updated["token_endpoint"] = tokenEndpoint
		}
		updated["last_refresh"] = time.Now().UTC().Format(time.RFC3339)
		return updated, "已刷新 token", nil
	case "codex":
		auth := codex.NewCodexAuth(h.cfg)
		tokenData, err := auth.RefreshTokens(timeoutCtx, refreshToken)
		if err != nil {
			return nil, "", err
		}
		if tokenData != nil {
			if tokenData.AccessToken != "" {
				updated["access_token"] = tokenData.AccessToken
			}
			if tokenData.RefreshToken != "" {
				updated["refresh_token"] = tokenData.RefreshToken
			}
			if tokenData.IDToken != "" {
				updated["id_token"] = tokenData.IDToken
			}
			if tokenData.AccountID != "" {
				updated["account_id"] = tokenData.AccountID
			}
			if tokenData.Email != "" {
				updated["email"] = tokenData.Email
			}
			if tokenData.Expire != "" {
				updated["expired"] = tokenData.Expire
			}
		}
		updated["last_refresh"] = time.Now().UTC().Format(time.RFC3339)
		return updated, "已刷新 token", nil
	default:
		return payload, "provider 不支持导入前刷新，跳过", nil
	}
}

func storeCredentialImportPreview(items []*credentialImportPreviewItem) string {
	purgeCredentialImportPreview()
	id := uuid.NewString()
	cache := &credentialImportCacheEntry{
		created: time.Now(),
		items:   make(map[string]*credentialImportPreviewItem, len(items)),
	}
	for _, item := range items {
		if item == nil {
			continue
		}
		cache.items[item.SourceName] = item
	}
	credentialImportCacheMu.Lock()
	credentialImportCache[id] = cache
	credentialImportCacheMu.Unlock()
	return id
}

func takeCredentialImportPreview(id string) *credentialImportCacheEntry {
	purgeCredentialImportPreview()
	credentialImportCacheMu.Lock()
	defer credentialImportCacheMu.Unlock()
	entry := credentialImportCache[id]
	delete(credentialImportCache, id)
	if entry == nil {
		return nil
	}
	if time.Since(entry.created) > credentialImportCacheTTL {
		return nil
	}
	return entry
}

func purgeCredentialImportPreview() {
	credentialImportCacheMu.Lock()
	defer credentialImportCacheMu.Unlock()
	now := time.Now()
	for id, entry := range credentialImportCache {
		if entry == nil || now.Sub(entry.created) > credentialImportCacheTTL {
			delete(credentialImportCache, id)
		}
	}
}

func loadCredentialImportSettings() credentialImportSettings {
	credentialImportPrefsMu.Lock()
	defer credentialImportPrefsMu.Unlock()
	return credentialImportPrefs
}

func saveCredentialImportSettings(next credentialImportSettings) credentialImportSettings {
	credentialImportPrefsMu.Lock()
	defer credentialImportPrefsMu.Unlock()
	if next.refreshTokensSet {
		credentialImportPrefs.RefreshTokens = next.RefreshTokens
	}
	if next.refreshTimeoutSet {
		timeout := next.RefreshTimeoutSeconds
		if timeout < 1 {
			timeout = 20
		}
		credentialImportPrefs.RefreshTimeoutSeconds = timeout
	}
	if next.probeBeforeSet {
		credentialImportPrefs.ProbeBeforeImport = next.ProbeBeforeImport
	}
	if next.probeTimeoutSet {
		timeout := next.ProbeTimeoutSeconds
		if timeout < 1 {
			timeout = 15
		}
		credentialImportPrefs.ProbeTimeoutSeconds = timeout
	}
	if next.probeWorkersSet {
		workers := next.ProbeMaxWorkers
		if workers < 1 {
			workers = 8
		}
		if workers > 32 {
			workers = 32
		}
		credentialImportPrefs.ProbeMaxWorkers = workers
	}
	return credentialImportPrefs
}

func serializeCredentialImportSettings(settings credentialImportSettings) gin.H {
	return gin.H{
		"import_refresh_tokens":          settings.RefreshTokens,
		"import_refresh_timeout_seconds": settings.RefreshTimeoutSeconds,
		"import_probe_before":            settings.ProbeBeforeImport,
		"import_probe_timeout_seconds":   settings.ProbeTimeoutSeconds,
		"import_probe_max_workers":       settings.ProbeMaxWorkers,
	}
}

func serializeCredentialImportPreview(item *credentialImportPreviewItem) gin.H {
	if item == nil {
		return gin.H{}
	}
	return gin.H{
		"source_name":       item.SourceName,
		"target_name":       item.TargetName,
		"provider":          item.Provider,
		"email_masked":      item.EmailMasked,
		"account_id":        item.AccountID,
		"valid":             item.Valid,
		"duplicate_type":    item.DuplicateType,
		"expired_state":     item.ExpiredState,
		"warnings":          item.Warnings,
		"errors":            item.Errors,
		"planned_action":    item.PlannedAction,
		"available_actions": item.AvailableActions,
		"summary":           item.Summary,
	}
}

func buildImportPreviewSummary(item *credentialImportPreviewItem) string {
	if item == nil {
		return ""
	}
	parts := make([]string, 0, 4)
	if !item.Valid {
		parts = append(parts, "无效")
	}
	if item.DuplicateType != "" {
		parts = append(parts, "重复:"+item.DuplicateType)
	}
	if item.ExpiredState == "expired" {
		parts = append(parts, "已过期")
	}
	if len(item.Errors) > 0 {
		parts = append(parts, strings.Join(item.Errors, "; "))
	} else if len(item.Warnings) > 0 {
		parts = append(parts, strings.Join(item.Warnings, "; "))
	}
	if len(parts) == 0 {
		return "可导入"
	}
	return strings.Join(parts, " / ")
}

func classifyImportDuplicate(targetName, provider, email, accountID string, existing []credentialImportExisting) string {
	for _, item := range existing {
		if item.Name == targetName {
			return "name"
		}
	}
	if provider != "" && email != "" {
		for _, item := range existing {
			if item.Provider == provider && strings.EqualFold(item.Email, email) {
				return "provider_email"
			}
		}
	}
	if provider != "" && accountID != "" {
		for _, item := range existing {
			if item.Provider == provider && item.AccountID != "" && item.AccountID == accountID {
				return "provider_account_id"
			}
		}
	}
	return ""
}

func requiredFieldsByProvider(provider string) []string {
	switch provider {
	case "codex":
		return []string{"access_token", "refresh_token", "id_token", "email", "expired"}
	case "xai":
		return []string{"access_token", "refresh_token", "email", "expired"}
	default:
		return nil
	}
}

func suggestCredentialFilename(payload map[string]any, reserved map[string]struct{}) string {
	provider := strings.ToLower(strings.TrimSpace(importAsString(payload["type"])))
	if provider == "" {
		provider = "cred"
	}
	email := strings.TrimSpace(importAsString(payload["email"]))
	accountID := strings.TrimSpace(importAsString(payload["account_id"]))
	if accountID == "" {
		accountID = strings.TrimSpace(importAsString(payload["sub"]))
	}
	var stem string
	switch {
	case email != "":
		stem = provider + "-" + sanitizeFilenamePart(email, 80)
	case accountID != "":
		stem = provider + "-" + sanitizeFilenamePart(accountID, 80)
	default:
		stem = provider + "-import"
	}
	candidate := stem + ".json"
	if _, exists := reserved[candidate]; !exists {
		return candidate
	}
	index := 1
	for {
		candidate = fmt.Sprintf("%s (%d).json", stem, index)
		if _, exists := reserved[candidate]; !exists {
			return candidate
		}
		index++
	}
}

func sanitizeFilenamePart(value string, maxLen int) string {
	text := strings.TrimSpace(value)
	text = unsafeFileChars.ReplaceAllString(text, "_")
	text = multiUnderscore.ReplaceAllString(text, "_")
	text = strings.Trim(text, "._")
	if text == "" {
		return "unknown"
	}
	if maxLen > 0 && len(text) > maxLen {
		text = text[:maxLen]
	}
	return text
}

func looksLikeCredentialPayload(payload map[string]any) bool {
	if payload == nil {
		return false
	}
	if strings.TrimSpace(importAsString(payload["type"])) != "" {
		return true
	}
	if strings.TrimSpace(importAsString(payload["access_token"])) != "" {
		return true
	}
	if strings.TrimSpace(importAsString(payload["refresh_token"])) != "" {
		return true
	}
	if strings.TrimSpace(importAsString(payload["key"])) != "" {
		return true
	}
	return false
}

func normalizePastedPayload(payload map[string]any) map[string]any {
	doc := importCloneMap(payload)
	provider := strings.ToLower(strings.TrimSpace(importAsString(doc["type"])))
	baseURL := strings.ToLower(strings.TrimSpace(importAsString(doc["base_url"])))
	tokenEndpoint := strings.ToLower(strings.TrimSpace(importAsString(doc["token_endpoint"])))
	if provider == "" {
		if strings.Contains(baseURL, "x.ai") || strings.Contains(tokenEndpoint, "x.ai") {
			provider = "xai"
		} else {
			provider = "unknown"
		}
		doc["type"] = provider
	} else {
		doc["type"] = provider
	}
	if strings.TrimSpace(importAsString(doc["access_token"])) == "" && strings.TrimSpace(importAsString(doc["key"])) != "" {
		doc["access_token"] = strings.TrimSpace(importAsString(doc["key"]))
	}
	if provider == "xai" {
		if _, ok := doc["auth_kind"]; !ok {
			doc["auth_kind"] = "oauth"
		}
		if _, ok := doc["token_type"]; !ok {
			doc["token_type"] = "Bearer"
		}
		if strings.TrimSpace(importAsString(doc["base_url"])) == "" {
			doc["base_url"] = "https://api.x.ai/v1"
		}
		if _, ok := doc["disabled"]; !ok {
			doc["disabled"] = false
		}
	}
	return doc
}

func nextAvailableImportName(name string, reserved map[string]struct{}) string {
	if _, exists := reserved[name]; !exists {
		return name
	}
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	index := 1
	for {
		candidate := fmt.Sprintf("%s (%d)%s", stem, index, ext)
		if _, exists := reserved[candidate]; !exists {
			return candidate
		}
		index++
	}
}

func decodeCredentialObject(raw []byte) (map[string]any, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty json")
	}
	var payload map[string]any
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func parseFlexibleTime(value any) (time.Time, bool) {
	switch v := value.(type) {
	case nil:
		return time.Time{}, false
	case time.Time:
		return v.UTC(), true
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return unixToTime(i), true
		}
		if f, err := v.Float64(); err == nil {
			return time.Unix(int64(f), 0).UTC(), true
		}
	case float64:
		return time.Unix(int64(v), 0).UTC(), true
	case int64:
		return unixToTime(v), true
	case int:
		return unixToTime(int64(v)), true
	case string:
		text := strings.TrimSpace(v)
		if text == "" {
			return time.Time{}, false
		}
		layouts := []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02T15:04:05Z07:00",
			"2006-01-02 15:04:05",
			"2006-01-02",
		}
		for _, layout := range layouts {
			if parsed, err := time.Parse(layout, text); err == nil {
				return parsed.UTC(), true
			}
		}
		if parsed, err := time.ParseInLocation("2006-01-02 15:04:05", text, time.Local); err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

func unixToTime(v int64) time.Time {
	if v > 1_000_000_000_000 {
		return time.UnixMilli(v).UTC()
	}
	return time.Unix(v, 0).UTC()
}

func importMaskEmail(email string) string {
	email = strings.TrimSpace(email)
	if email == "" {
		return ""
	}
	at := strings.LastIndex(email, "@")
	if at <= 1 {
		return email
	}
	name := email[:at]
	domain := email[at:]
	if len(name) <= 2 {
		return name[:1] + "*" + domain
	}
	return name[:1] + strings.Repeat("*", len(name)-2) + name[len(name)-1:] + domain
}

func importAsString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case fmt.Stringer:
		return t.String()
	default:
		return fmt.Sprint(t)
	}
}

func firstNonEmptyImport(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func importContainsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func importCloneMap(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func importIsSpace(b byte) bool {
	return b == ' ' || b == '\n' || b == '\r' || b == '\t' || b == '\f' || b == '\v'
}
