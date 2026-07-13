// Package usagekeeper embeds and reverse-proxies the CPA Usage Keeper sidecar.
package usagekeeper

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	log "github.com/sirupsen/logrus"
)

const (
	// PublicPath is the browser path used by the management UI iframe.
	PublicPath = "/usage-keeper/"
	// defaultListenAddr is the loopback address for the sidecar process.
	defaultListenAddr = "127.0.0.1:18080"
)

// Manager owns the optional embedded CPA Usage Keeper process and reverse proxy.
type Manager struct {
	mu sync.Mutex

	cfg            config.UsageKeeperConfig
	configFilePath string
	cpaBaseURL     string

	cmd        *exec.Cmd
	cmdCancel  context.CancelFunc
	proxy      *httputil.ReverseProxy
	targetURL  *url.URL
	listenAddr string
	running    bool

	runtimeManagementKey string
	appliedManagementKey string
}

// New creates a usage-keeper manager bound to the current CPA config path.
func New(configFilePath string) *Manager {
	return &Manager{configFilePath: strings.TrimSpace(configFilePath)}
}

// Apply updates sidecar configuration and starts/stops the process as needed.
func (m *Manager) Apply(cfg *config.Config, cpaBaseURL string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cpaBaseURL = strings.TrimSpace(cpaBaseURL)
	if cfg == nil {
		m.stopLocked()
		m.cfg = config.UsageKeeperConfig{}
		return
	}
	next := cfg.UsageKeeper
	m.cfg = next
	if !next.Enabled {
		m.stopLocked()
		return
	}
	if err := m.ensureRunningLocked(); err != nil {
		log.WithError(err).Warn("usage-keeper sidecar is not available")
		m.stopLocked()
	}
}

// SetRuntimeManagementKey stores a plaintext management key captured from an
// authenticated management request so the sidecar can start without a config form.
func (m *Manager) SetRuntimeManagementKey(key string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runtimeManagementKey = strings.TrimSpace(key)
}

// Enabled reports whether the sidecar is configured and currently running.
func (m *Manager) Enabled() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Enabled && m.running && m.proxy != nil
}

// EnsureWithKey stores a runtime management key and starts the sidecar when enabled.
func (m *Manager) EnsureWithKey(cfg *config.Config, cpaBaseURL, managementKey string) error {
	if m == nil {
		return fmt.Errorf("usage-keeper manager unavailable")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if cfg != nil {
		m.cfg = cfg.UsageKeeper
	}
	m.cpaBaseURL = strings.TrimSpace(cpaBaseURL)
	if key := strings.TrimSpace(managementKey); key != "" {
		m.runtimeManagementKey = key
	}
	if !m.cfg.Enabled {
		m.stopLocked()
		return fmt.Errorf("usage-keeper is disabled")
	}
	// Restart when the CPA management key changes so Keeper login/service key stay in sync.
	if m.running && m.runtimeManagementKey != "" && m.runtimeManagementKey != m.appliedManagementKey {
		m.stopLocked()
	}
	return m.ensureRunningLocked()
}

// Status returns a small JSON-friendly snapshot for the management UI.
func (m *Manager) Status() map[string]any {
	if m == nil {
		return map[string]any{"enabled": false, "running": false}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]any{
		"enabled":     m.cfg.Enabled,
		"running":     m.running,
		"public_path": PublicPath,
		"listen_addr": m.listenAddr,
		"work_dir":    m.workDirLocked(),
		"binary":      m.resolveBinaryLocked(),
	}
}

// ServeHTTP reverse-proxies browser traffic to the embedded sidecar.
func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if m == nil {
		http.NotFound(w, r)
		return
	}
	m.mu.Lock()
	proxy := m.proxy
	enabled := m.cfg.Enabled && m.running && proxy != nil
	m.mu.Unlock()
	if !enabled {
		http.Error(w, "usage-keeper is not enabled or not running", http.StatusServiceUnavailable)
		return
	}
	proxy.ServeHTTP(w, r)
}

// Stop terminates the sidecar process.
func (m *Manager) Stop() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
}

func (m *Manager) ensureRunningLocked() error {
	binary := m.resolveBinaryLocked()
	if binary == "" {
		return fmt.Errorf("cpa-usage-keeper binary not found; place it at %s or set usage-keeper.binary", m.defaultBinaryPathLocked())
	}
	listenAddr := strings.TrimSpace(m.cfg.ListenAddr)
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return fmt.Errorf("invalid usage-keeper.listen-addr %q: %w", listenAddr, err)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	// Keep the sidecar loopback-only for safety; public access goes through CPA reverse proxy.
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return fmt.Errorf("usage-keeper.listen-addr must be loopback, got %q", listenAddr)
	}
	listenAddr = net.JoinHostPort(host, port)
	managementKey := strings.TrimSpace(m.runtimeManagementKey)
	if managementKey == "" {
		managementKey = resolveManagementKey(m.cfg.ManagementKey)
	}
	if managementKey == "" {
		return fmt.Errorf("usage-keeper management key is empty; open management UI once so CPA can reuse the current management key, or set usage-keeper.management-key / CPA_USAGE_KEEPER_MANAGEMENT_KEY / MANAGEMENT_PASSWORD")
	}
	cpaBaseURL := strings.TrimSpace(m.cpaBaseURL)
	if cpaBaseURL == "" {
		cpaBaseURL = "http://127.0.0.1:" + strconv.Itoa(defaultCPAPort(m.configFilePath))
	}
	workDir := m.workDirLocked()
	if err = os.MkdirAll(workDir, 0o755); err != nil {
		return fmt.Errorf("create usage-keeper work dir: %w", err)
	}

	// Restart when process is missing, listen address changed, or management key changed.
	if m.running && m.cmd != nil && m.cmd.Process != nil && m.listenAddr == listenAddr && m.appliedManagementKey == managementKey {
		if m.cmd.ProcessState == nil {
			return nil
		}
	}
	m.stopLocked()

	target, err := url.Parse("http://" + listenAddr)
	if err != nil {
		return err
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	defaultDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		defaultDirector(req)
		// Keep the public /usage-keeper prefix. The sidecar is started with
		// APP_BASE_PATH=/usage-keeper so browser API calls like
		// /usage-keeper/api/v1/... match the embedded dashboard origin.
		if req.URL.Path == "" {
			req.URL.Path = "/"
		}
		req.Host = target.Host
		// Tell Keeper this request is from CPAMC embed mode.
		req.Header.Set("X-CPA-Usage-Keeper-Embed", "cpamc")
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.WithError(err).Warn("usage-keeper reverse proxy error")
		http.Error(w, "usage-keeper upstream unavailable", http.StatusBadGateway)
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Allow same-origin iframe embedding through CPA.
		resp.Header.Del("X-Frame-Options")
		// Keep CSP from upstream if present; browser still loads via same origin.
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary)
	cmd.Dir = workDir
	cmd.Env = m.buildEnvLocked(cpaBaseURL, managementKey, listenAddr, workDir)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("start usage-keeper: %w", err)
	}

	m.cmd = cmd
	m.cmdCancel = cancel
	m.proxy = proxy
	m.targetURL = target
	m.listenAddr = listenAddr
	m.running = true

	go func(process *exec.Cmd, cancelFn context.CancelFunc) {
		errWait := process.Wait()
		cancelFn()
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.cmd == process {
			m.running = false
			m.cmd = nil
			m.cmdCancel = nil
			if errWait != nil {
				log.WithError(errWait).Warn("usage-keeper sidecar exited")
			} else {
				log.Info("usage-keeper sidecar exited")
			}
		}
	}(cmd, cancel)

	if err = waitReady("http://"+listenAddr+"/healthz", 15*time.Second); err != nil {
		m.stopLocked()
		return fmt.Errorf("usage-keeper health check failed: %w", err)
	}
	m.appliedManagementKey = managementKey
	log.Infof("usage-keeper sidecar started on %s (public path %s)", listenAddr, PublicPath)
	return nil
}

func (m *Manager) stopLocked() {
	if m.cmdCancel != nil {
		m.cmdCancel()
		m.cmdCancel = nil
	}
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
	}
	m.cmd = nil
	m.proxy = nil
	m.targetURL = nil
	m.listenAddr = ""
	m.running = false
	m.appliedManagementKey = ""
}

func (m *Manager) buildEnvLocked(cpaBaseURL, managementKey, listenAddr, workDir string) []string {
	host, port, _ := net.SplitHostPort(listenAddr)
	if host == "" {
		host = "127.0.0.1"
	}
	envMap := map[string]string{}
	for _, entry := range os.Environ() {
		if idx := strings.IndexByte(entry, '='); idx > 0 {
			envMap[entry[:idx]] = entry[idx+1:]
		}
	}
	envMap["CPA_BASE_URL"] = strings.TrimRight(cpaBaseURL, "/")
	envMap["CPA_MANAGEMENT_KEY"] = managementKey
	envMap["APP_PORT"] = port
	// Serve Keeper under the reverse-proxy public prefix so frontend API
	// calls stay on /usage-keeper/api/v1 instead of /api/v1.
	envMap["APP_BASE_PATH"] = strings.TrimRight(PublicPath, "/")
	envMap["WORK_DIR"] = workDir
	envMap["CPA_PUBLIC_URL"] = strings.TrimRight(cpaBaseURL, "/")
	// Automatically sync credentials with the current CPA management key:
	// 1) CPA_MANAGEMENT_KEY always follows the live management key (set above)
	// 2) When dashboard auth is enabled, LOGIN_PASSWORD defaults to the same key
	//    unless usage-keeper.login-password is explicitly configured.
	if m.cfg.AuthEnabled {
		envMap["AUTH_ENABLED"] = "true"
		if strings.TrimSpace(m.cfg.LoginPassword) != "" {
			envMap["LOGIN_PASSWORD"] = strings.TrimSpace(m.cfg.LoginPassword)
		} else {
			envMap["LOGIN_PASSWORD"] = managementKey
		}
	} else {
		// Embedded same-origin mode: skip a second dashboard password prompt.
		envMap["AUTH_ENABLED"] = "false"
	}
	// Redis usage queue shares the CPA HTTP/RESP listener.
	if u, err := url.Parse(cpaBaseURL); err == nil && u.Host != "" {
		envMap["REDIS_QUEUE_ADDR"] = u.Host
	}
	for key, value := range m.cfg.ExtraEnv {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		envMap[key] = value
	}
	out := make([]string, 0, len(envMap))
	for key, value := range envMap {
		out = append(out, key+"="+value)
	}
	return out
}

func (m *Manager) workDirLocked() string {
	if strings.TrimSpace(m.cfg.WorkDir) != "" {
		return expandPath(m.cfg.WorkDir)
	}
	return filepath.Join(configDir(m.configFilePath), "usage-keeper-data")
}

func (m *Manager) defaultBinaryPathLocked() string {
	return filepath.Join(configDir(m.configFilePath), "usage-keeper", "cpa-usage-keeper")
}

func (m *Manager) resolveBinaryLocked() string {
	candidates := []string{}
	if strings.TrimSpace(m.cfg.Binary) != "" {
		candidates = append(candidates, expandPath(m.cfg.Binary))
	}
	candidates = append(candidates,
		m.defaultBinaryPathLocked(),
		filepath.Join(configDir(m.configFilePath), "cpa-usage-keeper"),
		filepath.Join(".", "usage-keeper", "cpa-usage-keeper"),
		filepath.Join(".", "cpa-usage-keeper"),
	)
	if path, err := exec.LookPath("cpa-usage-keeper"); err == nil {
		candidates = append(candidates, path)
	}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() {
			continue
		}
		return candidate
	}
	return ""
}

func resolveManagementKey(configured string) string {
	if key := strings.TrimSpace(configured); key != "" {
		return key
	}
	if key := strings.TrimSpace(os.Getenv("CPA_USAGE_KEEPER_MANAGEMENT_KEY")); key != "" {
		return key
	}
	if key := strings.TrimSpace(os.Getenv("MANAGEMENT_PASSWORD")); key != "" {
		return key
	}
	return ""
}

func stripPublicPrefix(path string) string {
	prefix := strings.TrimRight(PublicPath, "/")
	if path == prefix {
		return "/"
	}
	if strings.HasPrefix(path, prefix+"/") {
		return path[len(prefix):]
	}
	return path
}

func waitReady(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				return nil
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(250 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("timeout")
	}
	return lastErr
}

func configDir(configFilePath string) string {
	if strings.TrimSpace(configFilePath) == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "."
		}
		return cwd
	}
	return filepath.Dir(configFilePath)
}

func expandPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if strings.HasPrefix(path, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			if path == "~" {
				return home
			}
			if strings.HasPrefix(path, "~/") {
				return filepath.Join(home, path[2:])
			}
		}
	}
	if filepath.IsAbs(path) {
		return path
	}
	cwd, err := os.Getwd()
	if err != nil {
		return path
	}
	return filepath.Join(cwd, path)
}

func defaultCPAPort(configFilePath string) int {
	_ = configFilePath
	return 8317
}
