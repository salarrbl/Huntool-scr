package kit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	// Import the db package to access NucleiFinding
	db "watchdogs/DB"
)

// ToolConfig represents the configuration for a single tool loaded from JSON.
// NOTE: Removed the 'Execute' field permanently.
type ToolConfig struct {
	Name           string   `json:"name"`              // Name of the tool (e.g., "Subfinder")
	Command        string   `json:"command"`           // Command to execute (e.g., "subfinder")
	Args           []string `json:"args"`              // Arguments for the command (e.g., ["-d", "{{target}}"])
	TimeoutSeconds int      `json:"timeout_seconds"`   // Timeout for the command execution in seconds
	Priority       int      `json:"priority"`          // Priority level for execution order
	Enabled        bool     `json:"enabled"`           // Whether the tool is enabled
	Retries        int      `json:"retries"`           // Number of times to retry the tool if it fails
	// Removed: Execute        int       `json:"execute"`
}

// TaskResult holds the outcome of a single tool execution attempt.
type TaskResult struct {
	Name      string        `json:"name" bson:"tool_name"`
	Target    string        `json:"target" bson:"target"`
	Success   bool          `json:"success" bson:"success"`
	Output    string        `json:"output" bson:"output"`
	Error     string        `json:"error" bson:"error_msg"`
	Duration  time.Duration `json:"duration" bson:"duration"`
	Timestamp time.Time     `json:"timestamp" bson:"timestamp"`
	Retries   int           `json:"retries" bson:"retries"` // Number of attempts made
	Priority  int           `json:"priority" bson:"priority"`
}

// Runner manages the execution of a tool against a specific target.
type Runner struct {
	MaxConcurrency int
	Tools          []ToolConfig
	Target         string
}

// LoadTools reads the configuration file and returns a list of enabled ToolConfigs.
func LoadTools(configPath string) ([]ToolConfig, error) {
	if configPath == "" {
		_, filename, _, _ := runtime.Caller(0)
		dir := filepath.Dir(filename)
		configPath = filepath.Join(dir, "tools.json")
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}
	var tools []ToolConfig
	if err := json.Unmarshal(data, &tools); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	var enabled []ToolConfig
	for _, t := range tools {
		if t.Enabled {
			if t.Retries <= 0 {
				t.Retries = 2 // Default retries if not set or invalid
			}
			// Permanently removed Execute field handling
			enabled = append(enabled, t)
		}
	}
	// Sort by priority to ensure correct execution order in RunPrioritySuite
	sort.Slice(enabled, func(i, j int) bool {
		return enabled[i].Priority < enabled[j].Priority
	})
	return enabled, nil
}

// RunParallelDiscoveryTools runs all tools configured with priority 0 concurrently across root domains.
// It expects tools listed here to output a list of subdomains (one per line).
// It now also saves the raw results of each discovery tool to the 'subdomains' collection with the correct provider name.
func RunParallelDiscoveryTools(ctx context.Context, roots []string, configPath string, maxConcurrency int) ([]string, error) {
	tools, err := LoadTools(configPath)
	if err != nil {
		return nil, fmt.Errorf("loading discovery tools: %w", err)
	}
	var discoveryTools []ToolConfig
	for _, t := range tools {
		if t.Priority == 0 && t.Enabled { // Select tools with priority 0
			if t.Retries <= 0 {
				t.Retries = 2
			}
			// Permanently removed Execute field handling
			discoveryTools = append(discoveryTools, t)
		}
	}

	if len(discoveryTools) == 0 {
		return nil, fmt.Errorf("no discovery tools (priority 0) found in config %s", configPath)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var allSubs []string
	semaphore := make(chan struct{}, maxConcurrency)

	for _, root := range roots {
		for _, tool := range discoveryTools { // Run each discovery tool for the root
			wg.Add(1)
			go func(r string, t ToolConfig) {
				defer wg.Done()
				select {
				case semaphore <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-semaphore }()
				if ctx.Err() != nil {
					return
				}
				fmt.Printf("\033[34m    ▶️ [%s]\033[0m Scanning \033[1m%s\033[0m...\n", strings.TrimSpace(t.Name), r)
				// Create a runner instance for this specific tool execution
				runner := &Runner{Target: r, Tools: []ToolConfig{t}}
				// Execute the tool with its specified number of retries
				res := runner.executeToolWithRetry(ctx, t)
				if res.Success {
					// Parse output assuming it is a list of subdomains
					subs := ParseSubdomainListOutput(res.Output)
					fmt.Printf("\033[32m      ✅ [%s]\033[0m Found \033[1m%d\033[0m subdomains for \033[1m%s\033[0m\n", strings.TrimSpace(t.Name), len(subs), r)

					// --- NEW: Save raw results from this specific discovery tool to DB ---
					// Use the tool's Name field as the provider
					providerName := strings.TrimSpace(t.Name)
					if providerName != "" {
						if err := db.BulkUpsertSubdomainsForDiscovery(r, providerName, subs); err != nil {
							fmt.Printf("\033[91m      ❌ [%s]\033[0m Failed to save raw results to DB: %v\n", providerName, err)
							// Consider if you want to return the error or just log it and continue
						} else {
							fmt.Printf("\033[32m        💾 [%s]\033[0m Saved \033[1m%d\033[0m raw subdomains to 'subdomains' collection (provider: %s)\n", providerName, len(subs), providerName)
						}
					}
					// -----------------------------

					mu.Lock()
					allSubs = append(allSubs, subs...)
					mu.Unlock()
				} else {
					fmt.Printf("\033[91m    ❌ [%s]\033[0m Failed for \033[1m%s\033[0m: %s\n", strings.TrimSpace(t.Name), r, res.Error)
				}
			}(root, tool) // Capture loop variables
		}
	}
	wg.Wait()

	// Optional: Remove duplicates from the combined list after all tools finish
	seen := make(map[string]bool)
	var uniqueSubs []string
	for _, sub := range allSubs {
		if !seen[sub] {
			seen[sub] = true
			uniqueSubs = append(uniqueSubs, sub)
		}
	}

	return uniqueSubs, nil
}

// RunPrioritySuite executes tools grouped by priority level concurrently.
func RunPrioritySuite(ctx context.Context, target string, configPath string, maxConcurrency int) ([]TaskResult, error) {
	tools, err := LoadTools(configPath)
	if err != nil {
		return nil, err
	}
	var allResults []TaskResult
	priorityGroups := make(map[int][]ToolConfig)
	for _, t := range tools {
		// Exclude tools with priority 0 (handled separately by RunParallelDiscoveryTools)
		if t.Priority == 0 {
			continue
		}
		priorityGroups[t.Priority] = append(priorityGroups[t.Priority], t)
	}
	var priorities []int
	for p := range priorityGroups {
		priorities = append(priorities, p)
	}
	sort.Ints(priorities)
	for _, p := range priorities {
		group := priorityGroups[p]
		fmt.Printf("\033[33m⚡ Executing Priority Level %d\033[0m (\033[1m%d\033[0m tools)...\n", p, len(group))
		results, err := runConcurrentGroup(ctx, target, group, maxConcurrency)
		if err != nil {
			return allResults, err
		}
		allResults = append(allResults, results...)
		if ctx.Err() != nil {
			return allResults, ctx.Err()
		}
	}
	return allResults, nil
}

// runConcurrentGroup executes a group of tools with the same priority concurrently.
func runConcurrentGroup(ctx context.Context, target string, tools []ToolConfig, maxConcurrency int) ([]TaskResult, error) {
	var wg sync.WaitGroup
	results := make([]TaskResult, 0, len(tools)) // Pre-allocate slice
	resultChan := make(chan TaskResult, len(tools))
	semaphore := make(chan struct{}, maxConcurrency) // Limit concurrent executions
	for _, tool := range tools {
		wg.Add(1)
		go func(t ToolConfig) {
			defer wg.Done()
			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-semaphore }()
			if ctx.Err() != nil {
				return
			}
			// Execute the tool with its specified number of retries
			res := executeToolWithRetryStatic(ctx, target, t)
			resultChan <- res
		}(tool)
	}
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for res := range resultChan {
		results = append(results, res)
	}
	return results, nil
}

// executeToolWithRetryStatic is a wrapper to call the method on a Runner instance.
func executeToolWithRetryStatic(parentCtx context.Context, target string, tool ToolConfig) TaskResult {
	r := Runner{Target: target}
	return r.executeToolWithRetry(parentCtx, tool)
}

// executeToolWithRetry handles the retry logic for a single tool execution.
// Now executes the tool EXACTLY ONCE per retry attempt.
func (r *Runner) executeToolWithRetry(parentCtx context.Context, tool ToolConfig) TaskResult {
	var lastResult TaskResult
	for attempt := 1; attempt <= tool.Retries; attempt++ {
		fmt.Printf("\033[36m    🔄 [%s]\033[0m Attempt \033[1m%d/%d\033[0m\n", strings.TrimSpace(tool.Name), attempt, tool.Retries)
		// Execute the tool ONCE per attempt
		result := r.executeTool(parentCtx, tool, attempt)
		if result.Success {
			// If successful on any attempt, return immediately
			fmt.Printf("\033[32m      ✅ [%s]\033[0m Succeeded on attempt \033[1m%d\033[0m.\n", strings.TrimSpace(tool.Name), attempt)
			return result
		}
		lastResult = result // Store the failure result
		errMsg := result.Error
		if errMsg == "" {
			errMsg = "non-zero exit code (no error message)"
		}
		fmt.Printf("\033[91m      ❌ [%s]\033[0m Attempt \033[1m%d\033[0m failed: %s\n", strings.TrimSpace(tool.Name), attempt, errMsg)
		if result.Output != "" {
			out := strings.TrimSpace(result.Output)
			if len(out) > 300 {
				out = out[:300] + "..."
			}
			fmt.Printf("\033[91m      📋 Output snippet: %s\033[0m\n", out)
		}
		if attempt < tool.Retries {
			// Simple backoff: wait longer after each failed attempt
			backoff := time.Duration(attempt) * 500 * time.Millisecond
			fmt.Printf("\033[33m    ⏳ [%s]\033[0m Retrying in \033[1m%v\033[0m...\n", strings.TrimSpace(tool.Name), backoff)
			time.Sleep(backoff)
		} else {
			fmt.Printf("\033[91m    🛑 [%s]\033[0m All \033[1m%d\033[0m attempts failed.\n", strings.TrimSpace(tool.Name), tool.Retries)
		}
	}
	// If all retries are exhausted, return the last failure result
	return lastResult
}

// executeTool performs the actual execution of a tool command.
func (r *Runner) executeTool(parentCtx context.Context, tool ToolConfig, attempt int) TaskResult {
	start := time.Now()
	// Prepare arguments, replacing placeholders
	finalArgs := make([]string, len(tool.Args))
	for i, arg := range tool.Args {
		finalArgs[i] = strings.ReplaceAll(strings.TrimSpace(arg), "{{target}}", r.Target)
	}
	// Set up the command with timeout
	ctx, cancel := context.WithTimeout(parentCtx, time.Duration(tool.TimeoutSeconds)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, strings.TrimSpace(tool.Command), finalArgs...)

	// Propagate environment variables to subprocess
	cmd.Env = os.Environ()

	// Execute the command
	output, err := cmd.CombinedOutput()
	duration := time.Since(start)

	// CRITICAL FIX: If timeout killed the process, we still have partial output.
	// Don't throw it away — Naabu produces valid JSON lines even when interrupted.
	wasTimeout := ctx.Err() == context.DeadlineExceeded

	// Prepare the result object
	result := TaskResult{
		Name:      strings.TrimSpace(tool.Name),
		Target:    r.Target,
		Success:   err == nil && !wasTimeout,
		Output:    string(output),
		Duration:  duration,
		Timestamp: time.Now(),
		Retries:   attempt,
		Priority:  tool.Priority,
	}

	if err != nil {
		if wasTimeout {
			result.Error = fmt.Sprintf("timeout after %ds (partial output preserved: %d bytes)", tool.TimeoutSeconds, len(output))
			// CRITICAL: Mark as success if we got meaningful output
			// Naabu outputs valid JSON lines even when killed by timeout
			if len(output) > 100 {
				result.Success = true
				fmt.Printf("\033[33m    ⚠️ [%s]\033[0m Timed out but saved \033[1m%d bytes\033[0m of partial output\n", strings.TrimSpace(tool.Name), len(output))
			}
		} else {
			result.Error = err.Error()
		}
	}

	return result
}

// Strict DNS label validator: [a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?
var validLabelRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// isValidSubdomainBasic performs a strict check suitable for parsing tool output lines.
// Rejects IPs, HTML tags, JSON fragments, URLs with paths, and error messages.
func isValidSubdomainBasic(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}

	// Quick reject of obvious error/log lines
	lowerS := strings.ToLower(s)
	if strings.Contains(lowerS, "error") || strings.Contains(lowerS, "connection") ||
		strings.Contains(lowerS, "timeout") || strings.Contains(lowerS, "pool") ||
		strings.Contains(lowerS, "network") || strings.Contains(lowerS, "could not") ||
		strings.Contains(lowerS, "failed") || strings.Contains(lowerS, "invalid") ||
		strings.Contains(lowerS, "warning") || strings.Contains(lowerS, "fatal") ||
		strings.Contains(lowerS, "panic") || strings.Contains(lowerS, "traceback") ||
		strings.Contains(lowerS, "<html") || strings.Contains(lowerS, "<body") ||
		strings.Contains(lowerS, "<div") || strings.Contains(lowerS, "<span") ||
		strings.Contains(lowerS, "<script") || strings.Contains(lowerS, "<!doctype") ||
		strings.Contains(lowerS, "{\\") || strings.Contains(lowerS, "[\\") {
		return false
	}

	// Reject IPs
	if net.ParseIP(s) != nil {
		return false
	}

	// Must have at least one dot
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}

	// Validate each label strictly
	for _, part := range parts {
		if part == "" || strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
		if !validLabelRegex.MatchString(part) {
			return false
		}
	}
	return true
}

// ParseSubdomainListOutput parses output where each line is potentially a subdomain.
// Extracts hosts from URLs, strips ports, validates strictly, and deduplicates.
func ParseSubdomainListOutput(output string) []string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	seen := make(map[string]bool)
	var subs []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines, comments, or warning/error lines starting with [
		if line == "" || strings.HasPrefix(line, "[") || strings.HasPrefix(line, "#") {
			continue
		}

		// Try to extract host from URL-like lines
		host := line
		if strings.Contains(line, "://") {
			if u, err := url.Parse(line); err == nil && u.Host != "" {
				host = u.Host
			}
		}
		// Strip port if present
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}

		if isValidSubdomainBasic(host) && !seen[host] {
			seen[host] = true
			subs = append(subs, host)
		}
	}
	return subs
}

// ParseSubfinderOutput now calls the generic parser
func ParseSubfinderOutput(output string) []string {
	return ParseSubdomainListOutput(output)
}

// ExtractSubdomainsFromResult extracts subdomains from a successful TaskResult.
// This is a convenience wrapper for Subfinder output specifically.
func ExtractSubdomainsFromResult(result *TaskResult) []string {
	if result == nil || !result.Success {
		return []string{}
	}
	return ParseSubfinderOutput(result.Output)
}

// CountLines counts non-empty lines in a string output.
func CountLines(output string) int {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	count := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

// NaabuJSONResult represents a single JSON line output from Naabu.
// This matches the structure described in https://github.com/projectdiscovery/naabu#json-output
type NaabuJSONResult struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	TLS      bool   `json:"tls,omitempty"`
	IP       string `json:"ip"`
	Source   string `json:"source,omitempty"`
}

// ParseNaabuOutput parses the JSON Lines output from the 'naabu' command.
// Each line is expected to be a valid JSON object representing an open port.
func ParseNaabuOutput(output string) map[string][]string {
	portsMap := make(map[string][]string)
	scanner := bufio.NewScanner(strings.NewReader(output))
	buf := make([]byte, 0, 64*1024) // 64KB initial buffer
	scanner.Buffer(buf, 1024*1024)  // 1MB max token size
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var res NaabuJSONResult
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			// CRITICAL FIX: If line looks like partial JSON, try to salvage
			// Last line of killed process might be truncated
			if strings.HasPrefix(line, `{"host"`) {
				// Try to find the closing brace and fix
				fixed := line + "}"
				if err := json.Unmarshal([]byte(fixed), &res); err == nil {
					// Salvaged!
				} else {
					continue // Truly unparseable
				}
			} else {
				continue
			}
		}

		// Use the host field from the JSON result as the key
		host := strings.TrimSpace(res.Host)
		port := fmt.Sprintf("%d", res.Port) // Convert port number to string

		if host != "" && port != "" && port != "0" {
			// Append the port to the list for the corresponding host
			portsMap[host] = append(portsMap[host], port)
		}
	}

	if err := scanner.Err(); err != nil {
		// Log potential scanner errors
		log.Printf("Scanner error while parsing Naabu output: %v", err)
	}

	return portsMap
}

// ParseHttprobeOutput parses the output from httprobe, returning a list of URLs.
func ParseHttprobeOutput(output string) []string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var urls []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && strings.Contains(line, "http") && !strings.HasPrefix(line, "[") {
			urls = append(urls, line)
		}
	}
	return urls
}

// ParseCspreconOutput parses the output from Csprecon, returning a list of domains.
func ParseCspreconOutput(output string) []string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var domains []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		domains = append(domains, line)
	}
	return domains
}

// NucleiResult represents a single finding from Nuclei JSON output, includes Host
type NucleiResult struct {
	TemplateID    string `json:"template-id"`
	Type          string `json:"type"`
	Name          string `json:"name"`
	Severity      string `json:"severity"`
	URL           string `json:"url"`
	Host          string `json:"host"` // Added Host field
	MatcherName   string `json:"matcher-name,omitempty"`
	ExtractorName string `json:"extractor-name,omitempty"`
	Request       string `json:"request,omitempty"`
	Response      string `json:"response,omitempty"`
	// Add other fields as needed
}

// ParseNucleiOutput parses Nuclei's JSONL output into []db.NucleiFinding
func ParseNucleiOutput(output string) []db.NucleiFinding {
	var findings []db.NucleiFinding
	scanner := bufio.NewScanner(strings.NewReader(output))
	buf := make([]byte, 0, 64*1024) // 64KB initial buffer
	scanner.Buffer(buf, 1024*1024)  // 1MB max token size
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var res NucleiResult
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			continue
		}
		// Map NucleiResult fields to db.NucleiFinding, using res.Host
		findings = append(findings, db.NucleiFinding{
			TemplateID:    res.TemplateID,
			Type:          res.Type,
			Name:          res.Name,
			Severity:      res.Severity,
			URL:           res.URL,
			Host:          res.Host, // Assign the Host field
			MatcherName:   res.MatcherName,
			ExtractorName: res.ExtractorName,
			Request:       res.Request,
			Response:      res.Response,
		})
	}
	return findings
}
