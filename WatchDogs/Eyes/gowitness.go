package eyes

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	db "watchdogs/DB"
)

type PowerConfig struct {
	Enabled       bool     `json:"enabled"`
	Concurrency   int      `json:"concurrency"`
	Timeout       int      `json:"timeout_seconds"`
	Format        string   `json:"format"`
	OutputDir     string   `json:"output_dir"`
	AllowedPorts  []string `json:"allowed_ports"`
	IgnoredPorts  []string `json:"ignored_ports"`
	SkipStyles        bool `json:"skip_styles"`
	SkipResources     bool `json:"skip_resources"`
	IncludeJS         bool `json:"include_js"`
	IncludeCSS        bool `json:"include_css"`
	DisableColor      bool `json:"disable_color"`
	DisableJavaScript bool `json:"disable_javascript"`
	DisableSecurity   bool `json:"disable_security"`
	FastMode          bool `json:"fast_mode"`
}

var (
	logLineRegex = regexp.MustCompile(`target=(?P<url>[^\s]+)`)
)

func loadPowerConfig() (*PowerConfig, error) {
	paths := []string{"power.json", "Eyes/power.json"}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		paths = append(paths,
			filepath.Join(dir, "power.json"),
			filepath.Join(dir, "Eyes", "power.json"))
	}

	for _, path := range paths {
		file, err := os.Open(path)
		if err == nil {
			defer file.Close()
			cfg := &PowerConfig{}
			if err := json.NewDecoder(file).Decode(cfg); err != nil {
				return nil, fmt.Errorf("failed to decode %s: %w", path, err)
			}
			return cfg, nil
		}
	}
	return nil, fmt.Errorf("no power.json or Eyes/power.json found in search paths: %v", paths)
}

func CaptureScreenshots(ctx context.Context, rootDomain string, targets []string) error {
	start := time.Now()
	cfg, err := loadPowerConfig()
	if err != nil {
		fmt.Printf(" ⚠️ [Eyes] Config error (%v), using defaults\n", err)
		cfg = &PowerConfig{Concurrency: 10, Timeout: 10, OutputDir: "Eyes/Screenshot"}
	}

	if !cfg.Enabled {
		fmt.Println(" 📸 [Eyes] Screenshot capture is disabled in power.json.")
		return nil
	}

	fmt.Printf(" 📸 [Eyes] Starting screenshot capture for %s (%d URLs)...\n", rootDomain, len(targets))

	chunkSize := 50
	var chunks [][]string
	for i := 0; i < len(targets); i += chunkSize {
		end := i + chunkSize
		if end > len(targets) {
			end = len(targets)
		}
		chunks = append(chunks, targets[i:end])
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(chunks))

	for _, chunk := range chunks {
		wg.Add(1)
		go func(urls []string) {
			defer wg.Done()
			if err := captureChunk(ctx, *cfg, rootDomain, urls); err != nil {
				errChan <- err
			}
		}(chunk)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		fmt.Printf(" ⚠️ [Eyes] Chunk error: %v\n", err)
	}

	fmt.Printf(" ✅ [Eyes] Complete in %v\n", time.Since(start))
	return nil
}

func captureChunk(ctx context.Context, cfg PowerConfig, rootDomain string, targets []string) error {
	tmpFile, err := os.CreateTemp("", "gowit-targets-.txt")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	for _, u := range targets {
		fmt.Fprintln(tmpFile, u)
	}
	tmpFile.Close()

	jsonlPath := filepath.Join(os.TempDir(),
		fmt.Sprintf("gowit-%s-%d.jsonl", rootDomain, time.Now().UnixNano()))
	defer os.Remove(jsonlPath)

	outputDir := cfg.OutputDir
	if !filepath.IsAbs(outputDir) {
		if wd, err := os.Getwd(); err == nil {
			outputDir = filepath.Join(wd, outputDir)
		}
	}
	os.MkdirAll(outputDir, 0o755)

	args := []string{
		"scan", "file",
		"-f", tmpPath,
		"--screenshot-path", outputDir,
		"--threads", strconv.Itoa(cfg.Concurrency),
		"--timeout", strconv.Itoa(cfg.Timeout),
		"--write-jsonl-file", jsonlPath,
	}

	if cfg.SkipResources {
		args = append(args, "--skip-resources")
	}
	if cfg.SkipStyles {
		args = append(args, "--skip-styles")
	}
	if cfg.IncludeJS {
		args = append(args, "--include-js")
	}
	if cfg.IncludeCSS {
		args = append(args, "--include-css")
	}
	if cfg.DisableColor {
		args = append(args, "--disable-color")
	}
	if cfg.DisableJavaScript {
		args = append(args, "--disable-javascript")
	}
	if cfg.DisableSecurity {
		args = append(args, "--disable-security")
	}
	if cfg.FastMode {
		args = append(args, "--fast-mode")
	}

	cmd := exec.CommandContext(ctx, "gowitness", args...)
	cmd.Dir = outputDir
	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	if _, statErr := os.Stat(jsonlPath); statErr == nil {
		if err := parseJSONLResults(jsonlPath, rootDomain); err != nil {
			fmt.Printf(" ⚠️ [Eyes] JSONL parse failed, trying log fallback: %v\n", err)
			parseLogOutput(outputStr, rootDomain)
		}
	} else {
		fmt.Printf(" ℹ️ [Eyes] No JSONL file found (%s), parsing log output...\n", jsonlPath)
		parseLogOutput(outputStr, rootDomain)
	}

	return err
}

func parseJSONLResults(jsonlPath, rootDomain string) error {
	file, err := os.Open(jsonlPath)
	if err != nil {
		return fmt.Errorf("failed to open JSONL: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	updated := 0
	skipped := 0
	failed := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}

		urlVal, ok := raw["url"].(string)
		if !ok {
			continue
		}

		screenshotPath, _ := raw["screenshot_path"].(string)
		screenshotHash, _ := raw["screenshot_hash"].(string)

		subdomain := extractSubdomainFromURL(urlVal, rootDomain)
		if subdomain == "" {
			skipped++
			continue
		}

		if screenshotPath != "" {
			if err := db.UpdateScreenshotDataBySubdomain(rootDomain, subdomain, screenshotPath, screenshotHash); err != nil {
				failed++
			} else {
				updated++
			}
		} else {
			skipped++
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading JSONL file: %w", err)
	}

	if updated > 0 || skipped > 0 || failed > 0 {
		fmt.Printf(" 📊 [Eyes] JSONL parsed: %d updated, %d skipped, %d failed\n", updated, skipped, failed)
	}
	return nil
}

func parseLogOutput(output string, rootDomain string) {
	lines := strings.Split(output, "\n")
	updated := 0
	skipped := 0
	failed := 0

	for _, line := range lines {
		if !strings.Contains(line, "target=") {
			continue
		}

		matches := logLineRegex.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}

		urlVal := matches[1]

		subdomain := extractSubdomainFromURL(urlVal, rootDomain)
		if subdomain == "" {
			skipped++
			continue
		}

		parsedURL, err := url.Parse(urlVal)
		if err != nil {
			skipped++
			continue
		}
		hostPort := parsedURL.Host
		filename := strings.ReplaceAll(strings.ReplaceAll(hostPort, ":", "_"), ".", "_") + ".png"
		defaultScreenshotPath := filepath.Join("Eyes", "Screenshot", filename)

		if _, err := os.Stat(defaultScreenshotPath); err == nil {
			if err := db.UpdateScreenshotDataBySubdomain(rootDomain, subdomain, defaultScreenshotPath, ""); err != nil {
				failed++
			} else {
				updated++
			}
		} else {
			skipped++
		}
	}

	if updated > 0 || skipped > 0 || failed > 0 {
		fmt.Printf(" 📊 [Eyes] Log fallback parsed: %d updated, %d skipped (missing file/path), %d failed\n", updated, skipped, failed)
	}
}

func extractSubdomainFromURL(rawURL, rootDomain string) string {
	if rawURL == "" || rootDomain == "" {
		return ""
	}
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := parsedURL.Hostname()
	if host == "" {
		return ""
	}
	lowerRoot := strings.ToLower(rootDomain)
	if !strings.HasSuffix(strings.ToLower(host), "."+lowerRoot) && strings.ToLower(host) != lowerRoot {
		return ""
	}
	return host
}

// RunScreenshotCapture is the entrypoint called by main.go.
// It fetches live hosts from the DB and delegates to CaptureScreenshots.
func RunScreenshotCapture(ctx context.Context, rootDomain string) error {
	liveHosts, err := db.GetDistinctSubdomainsByRootDomain(rootDomain)
	if err != nil {
		return fmt.Errorf("failed to fetch live hosts for screenshot: %w", err)
	}
	if len(liveHosts) == 0 {
		fmt.Printf(" ℹ️ [Eyes] No live hosts in DB for %s, skipping screenshots.\n", rootDomain)
		return nil
	}
	return CaptureScreenshots(ctx, rootDomain, liveHosts)
}
