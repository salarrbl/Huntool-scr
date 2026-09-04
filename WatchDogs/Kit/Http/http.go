package httppkg

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	dbPkg "watchdogs/DB"
	"watchdogs/Kit"
)

// HTTPXResult represents httpx JSON output
type HTTPXResult struct {
	URL           string   `json:"url"`
	Input         string   `json:"input"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title"`
	ContentLength int      `json:"content_length"`
	Technologies  []string `json:"tech,omitempty"`
	CDN           bool     `json:"cdn,omitempty"`
	CDNName       string   `json:"cdn_name,omitempty"`
}

// DNSXResult represents dnsx JSON output
type DNSXResult struct {
	Host  string   `json:"host"`
	A     []string `json:"a"`
	CNAME []string `json:"cname,omitempty"`
}

// NucleiResult represents nuclei JSON output
type NucleiResult struct {
	TemplateID    string `json:"template-id"`
	Type          string `json:"type"`
	Name          string `json:"name"`
	Severity      string `json:"severity"`
	URL           string `json:"url"`
	Host          string `json:"host"`
	MatcherName   string `json:"matcher-name,omitempty"`
	ExtractorName string `json:"extractor-name,omitempty"`
	Request       string `json:"request,omitempty"`
	Response      string `json:"response,omitempty"`
}

const chunkSize = 10000

// RunEnrichment orchestrates dnsx → httpx → csprecon → nuclei.
// Each tool runs in sequential 10,000-subdomain chunks.
func RunEnrichment(ctx context.Context, rootDomain string, rawSubs []string) ([]string, error) {
	if len(rawSubs) == 0 {
		return nil, nil
	}

	// ── Phase 1: DNSx ── resolve all subs in chunks
	fmt.Println("   🔍 [dnsx] Resolving subdomains...")
	resolved, unresolved, err := runDNSXAllChunks(ctx, rootDomain, rawSubs, "")
	if err != nil {
		fmt.Printf("   ⚠️ [dnsx] Failed: %v\n", err)
		return nil, fmt.Errorf("dnsx phase failed: %w", err)
	}
	if len(unresolved) > 0 {
		var vhRecords []dbPkg.VirtualHostRecord
		for _, sub := range unresolved {
			vhRecords = append(vhRecords, dbPkg.VirtualHostRecord{
				RootDomain:   rootDomain,
				Subdomain:    sub,
				DiscoveredAt: time.Now(),
				UpdatedAt:    time.Now(),
			})
		}
		if err := dbPkg.InsertVirtualHosts(vhRecords); err != nil {
			fmt.Printf("   ⚠️ [dnsx] Failed to save %d unresolved to virtual_host: %v\n", len(unresolved), err)
		} else {
			fmt.Printf("   💾 [dnsx] Saved %d unresolved hosts to virtual_host\n", len(unresolved))
		}
	}
	fmt.Printf("   ✅ [dnsx] %d resolved, %d unresolved\n", len(resolved), len(unresolved))

	if len(resolved) == 0 {
		fmt.Printf("   🚨 [dnsx] 0 resolved out of %d. Skipping HTTP probing.\n", len(rawSubs))
		return nil, nil
	}

	// ── Phase 2: HTTPx ── probe resolved hosts in chunks
	var liveHosts []string
	totalChunks := (len(resolved) + chunkSize - 1) / chunkSize
	for i := 0; i < len(resolved); i += chunkSize {
		if ctx.Err() != nil {
			return liveHosts, ctx.Err()
		}
		end := i + chunkSize
		if end > len(resolved) {
			end = len(resolved)
		}
		chunk := resolved[i:end]

		fmt.Printf("      🔍 [httpx] chunk %d/%d (%d hosts)\n",
			(i/chunkSize)+1, totalChunks, len(chunk))

		chunkCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		chunkLive, err := RunHTTPSuite(chunkCtx, rootDomain, chunk, "", 50)
		cancel()

		if err != nil {
			fmt.Printf("      ⚠️ [httpx] chunk %d failed: %v\n", (i/chunkSize)+1, err)
		} else {
			fmt.Printf("      ✅ [httpx] chunk %d: %d live\n", (i/chunkSize)+1, len(chunkLive))
			liveHosts = append(liveHosts, chunkLive...)
		}
	}
	fmt.Printf("   ✅ [httpx] Total live hosts: %d\n", len(liveHosts))

	// ── Phase 3: CSPRecon ── run on all original subs in chunks
	fmt.Println("   🔍 [csprecon] Running CSP reconnaissance...")
	cspCfg, _ := getToolConfig("", "csprecon")
	if cspCfg != nil && cspCfg.Enabled {
		seen := make(map[string]bool)
		var allCSP []string
		totalChunks = (len(rawSubs) + chunkSize - 1) / chunkSize
		for i := 0; i < len(rawSubs); i += chunkSize {
			if ctx.Err() != nil {
				return liveHosts, ctx.Err()
			}
			end := i + chunkSize
			if end > len(rawSubs) {
				end = len(rawSubs)
			}
			chunk := rawSubs[i:end]

			chunkCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
			doms, err := runCSPReconSingle(chunkCtx, chunk, cspCfg)
			cancel()

			if err != nil {
				fmt.Printf("      ⚠️ [csprecon] chunk %d/%d failed: %v\n", (i/chunkSize)+1, totalChunks, err)
			} else {
				for _, d := range doms {
					if !seen[d] {
						seen[d] = true
						allCSP = append(allCSP, d)
					}
				}
				fmt.Printf("      ✅ [csprecon] chunk %d/%d: %d domains\n", (i/chunkSize)+1, totalChunks, len(doms))
			}
		}
		if len(allCSP) > 0 {
			fmt.Printf("   ✅ [csprecon] Total unique CSP domains: %d\n", len(allCSP))
			if err := dbPkg.BulkUpsertSubdomainsForDiscovery(rootDomain, "csprecon", allCSP); err != nil {
				fmt.Printf("   ⚠️ [csprecon] Failed to save CSP domains: %v\n", err)
			}
		}
	}

	// ── Phase 4: Nuclei ── scan live hosts in chunks
	if len(liveHosts) > 0 {
		fmt.Println("   🔍 [nuclei] Scanning for vulnerabilities...")
		nucCfg, _ := getToolConfig("", "nuclei")
		if nucCfg != nil && nucCfg.Enabled {
			totalChunks := (len(liveHosts) + chunkSize - 1) / chunkSize
			for i := 0; i < len(liveHosts); i += chunkSize {
				if ctx.Err() != nil {
					return liveHosts, ctx.Err()
				}
				end := i + chunkSize
				if end > len(liveHosts) {
					end = len(liveHosts)
				}
				chunk := liveHosts[i:end]

				fmt.Printf("      🔍 [nuclei] chunk %d/%d (%d URLs)\n",
					(i/chunkSize)+1, totalChunks, len(chunk))

				chunkCtx, cancel := context.WithTimeout(ctx, 60*time.Minute)
				err := runNucleiSingle(chunkCtx, rootDomain, chunk, nucCfg)
				cancel()

				if err != nil {
					fmt.Printf("      ⚠️ [nuclei] chunk %d failed: %v\n", (i/chunkSize)+1, err)
				} else {
					fmt.Printf("      ✅ [nuclei] chunk %d complete\n", (i/chunkSize)+1)
				}
			}
			fmt.Println("   ✅ [nuclei] All chunks complete")
		}
	}

	return liveHosts, nil
}

// RunHTTPSuite executes httpx for ONE chunk of targets. Streams results to DB.
// Uses a fixed 50-worker pool to prevent goroutine explosion at 1M+ scale.
func RunHTTPSuite(ctx context.Context, rootDomain string, targets []string, configPath string, maxConcurrency int) ([]string, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	httpxConfig, err := getToolConfig(configPath, "httpx")
	if err != nil || httpxConfig == nil || !httpxConfig.Enabled {
		return nil, fmt.Errorf("httpx not configured or disabled")
	}

	tmpFile, err := os.CreateTemp("", "watchdogs-httpx-*.txt")
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	for _, t := range targets {
		fmt.Fprintln(tmpFile, t)
	}
	tmpFile.Close()

	args := make([]string, len(httpxConfig.Args))
	copy(args, httpxConfig.Args)
	for i, arg := range args {
		if strings.Contains(arg, "{{target}}") {
			args[i] = strings.ReplaceAll(arg, "{{target}}", tmpFile.Name())
		}
	}

	cmd := exec.CommandContext(ctx, httpxConfig.Command, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("getting stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting httpx command: %w", err)
	}

	// CRITICAL FIX: Read ALL output BEFORE calling cmd.Wait().
	// cmd.Wait() closes the pipe, which causes "file already closed" if scanner is still reading.
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // 1MB max line

	var allLines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			allLines = append(allLines, line)
		}
	}
	scanErr := scanner.Err()

	// NOW it's safe to wait for the command to finish
	cmdErr := cmd.Wait()

	if scanErr != nil {
		log.Printf("Warning: httpx scanner error: %v", scanErr)
	}
	if cmdErr != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			log.Printf("httpx command '%s %s' finished with error: %v", httpxConfig.Command, strings.Join(args, " "), cmdErr)
		}
	}

	// Process all collected lines
	var liveHosts []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Process in batches to avoid goroutine explosion
	const batchSize = 500
	for i := 0; i < len(allLines); i += batchSize {
		end := i + batchSize
		if end > len(allLines) {
			end = len(allLines)
		}
		batch := allLines[i:end]

		wg.Add(1)
		go func(lines []string) {
			defer wg.Done()
			for _, line := range lines {
				var result HTTPXResult
				if err := json.Unmarshal([]byte(line), &result); err != nil {
					log.Printf("Warning: Could not unmarshal httpx output line: %s, error: %v", line, err)
					continue
				}
				if result.URL == "" {
					continue
				}

				subdomain := dbPkg.ExtractSubdomain(result.URL, rootDomain)
				technologies := result.Technologies
				if technologies == nil {
					technologies = []string{}
				}

				cdn := ""
				if result.CDN {
					cdn = result.CDNName
				}
				record := dbPkg.HTTPRecord{
					RootDomain:    rootDomain,
					Subdomain:     subdomain,
					StatusCode:    result.StatusCode,
					ContentLength: result.ContentLength,
					Title:         result.Title,
					Technologies:  technologies,
					CDN:           cdn,
					ProbeType:     "httpx",
					DiscoveredAt:  time.Now(),
				}

				if err := dbPkg.UpsertHTTPRecord(record); err != nil {
					log.Printf("Warning: Could not save httpx result for %s: %v", result.URL, err)
				}

				mu.Lock()
				liveHosts = append(liveHosts, result.URL)
				mu.Unlock()
			}
		}(batch)
	}
	wg.Wait()

	return liveHosts, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// DNSx helpers
// ─────────────────────────────────────────────────────────────────────────────

func runDNSXAllChunks(ctx context.Context, rootDomain string, targets []string, configPath string) (resolved []string, unresolved []string, err error) {
	cfg, err := getToolConfig(configPath, "dnsx")
	if err != nil || cfg == nil || !cfg.Enabled {
		return nil, nil, fmt.Errorf("dnsx not configured")
	}

	var allResolved []string
	var allUnresolved []string
	chunkCount := (len(targets) + chunkSize - 1) / chunkSize
	failedChunks := 0

	for i := 0; i < len(targets); i += chunkSize {
		if ctx.Err() != nil {
			return allResolved, allUnresolved, ctx.Err()
		}

		end := i + chunkSize
		if end > len(targets) {
			end = len(targets)
		}
		chunk := targets[i:end]

		chunkCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		r, u, e := runDNSXSingle(chunkCtx, chunk, cfg)
		cancel()

		if e != nil {
			failedChunks++
			fmt.Printf("      ⚠️ [dnsx] chunk %d/%d failed: %v\n", (i/chunkSize)+1, chunkCount, e)
			allUnresolved = append(allUnresolved, chunk...)
		} else {
			allResolved = append(allResolved, r...)
			allUnresolved = append(allUnresolved, u...)
			fmt.Printf("      ✅ [dnsx] chunk %d/%d: %d resolved, %d unresolved\n",
				(i/chunkSize)+1, chunkCount, len(r), len(u))
		}
	}

	if failedChunks == chunkCount && chunkCount > 0 {
		return allResolved, allUnresolved, fmt.Errorf("all %d dnsx chunks failed", chunkCount)
	}
	if len(allResolved) == 0 && len(allUnresolved) > 0 {
		fmt.Printf("   ⚠️ [dnsx] WARNING: 0 hosts resolved out of %d. Check DNS connectivity and input quality.\n", len(targets))
	}

	return allResolved, allUnresolved, nil
}

func runDNSXSingle(ctx context.Context, targets []string, cfg *kit.ToolConfig) (resolved []string, unresolved []string, err error) {
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}

	tmpFile, err := os.CreateTemp("", "watchdogs-dnsx-*.txt")
	if err != nil {
		return nil, nil, err
	}
	defer os.Remove(tmpFile.Name())

	for _, t := range targets {
		fmt.Fprintln(tmpFile, t)
	}
	tmpFile.Close()

	args := make([]string, len(cfg.Args))
	copy(args, cfg.Args)
	for i, arg := range args {
		args[i] = strings.ReplaceAll(arg, "{{target}}", tmpFile.Name())
	}

	cmd := exec.CommandContext(ctx, cfg.Command, args...)
	output, err := cmd.CombinedOutput()

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var res DNSXResult
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			continue
		}
		host := strings.TrimSpace(res.Host)
		if host == "" {
			continue
		}
		seen[host] = true
		if len(res.A) > 0 || len(res.CNAME) > 0 {
			resolved = append(resolved, host)
		} else {
			unresolved = append(unresolved, host)
		}
	}

	// Targets not in output = unresolved
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if !seen[t] {
			unresolved = append(unresolved, t)
		}
	}

	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, fmt.Errorf("dnsx cancelled: %w", ctx.Err())
		}
		// dnsx may exit non-zero; if we got partial data, don't fail
		if len(resolved)+len(unresolved) == 0 {
			return nil, nil, fmt.Errorf("dnsx failed: %w", err)
		}
	}

	return resolved, unresolved, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// CSPRecon helper
// ─────────────────────────────────────────────────────────────────────────────

func runCSPReconSingle(ctx context.Context, targets []string, cfg *kit.ToolConfig) ([]string, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	tmpFile, err := os.CreateTemp("", "watchdogs-csp-*.txt")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())

	for _, t := range targets {
		fmt.Fprintln(tmpFile, t)
	}
	tmpFile.Close()

	args := make([]string, len(cfg.Args))
	copy(args, cfg.Args)
	for i, arg := range args {
		args[i] = strings.ReplaceAll(arg, "{{target}}", tmpFile.Name())
	}

	cmd := exec.CommandContext(ctx, cfg.Command, args...)
	output, err := cmd.CombinedOutput()

	var domains []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "[") && !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}

	return domains, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Nuclei helper
// ─────────────────────────────────────────────────────────────────────────────

func runNucleiSingle(ctx context.Context, rootDomain string, targets []string, cfg *kit.ToolConfig) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	tmpFile, err := os.CreateTemp("", "watchdogs-nuclei-*.txt")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	for _, t := range targets {
		fmt.Fprintln(tmpFile, t)
	}
	tmpFile.Close()

	args := make([]string, len(cfg.Args))
	copy(args, cfg.Args)
	for i, arg := range args {
		args[i] = strings.ReplaceAll(arg, "{{target}}", tmpFile.Name())
	}

	cmd := exec.CommandContext(ctx, cfg.Command, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	resultsChan := make(chan NucleiResult, 10000)
	errChan := make(chan error, 1)

	// Reader
	go func() {
		defer close(resultsChan)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var res NucleiResult
			if err := json.Unmarshal([]byte(line), &res); err != nil {
				continue
			}
			if res.URL != "" {
				resultsChan <- res
			}
		}
		if err := scanner.Err(); err != nil {
			select {
			case errChan <- fmt.Errorf("nuclei scanner: %w", err):
			default:
			}
		}
	}()

	// Processor + DB writer with fixed 50-worker pool
	const dbWorkers = 50
	go func() {
		var workerWg sync.WaitGroup
		for i := 0; i < dbWorkers; i++ {
			workerWg.Add(1)
			go func() {
				defer workerWg.Done()
				for r := range resultsChan {
					subdomain := dbPkg.ExtractSubdomain(r.URL, rootDomain)

					finding := dbPkg.NucleiFinding{
						TemplateID:    r.TemplateID,
						Type:          r.Type,
						Name:          r.Name,
						Severity:      r.Severity,
						URL:           r.URL,
						Host:          r.Host,
						MatcherName:   r.MatcherName,
						ExtractorName: r.ExtractorName,
						Request:       r.Request,
						Response:      r.Response,
					}

					if err := dbPkg.UpdateNucleiFindingsForSubdomain(rootDomain, subdomain, []dbPkg.NucleiFinding{finding}); err != nil {
						log.Printf("Warning: nuclei DB save failed for %s: %v", r.URL, err)
					}
				}
			}()
		}
		workerWg.Wait()
		close(errChan)
	}()

	cmdErr := cmd.Wait()
	procErr := <-errChan

	if cmdErr != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			log.Printf("nuclei command error: %v", cmdErr)
		}
	}

	return procErr
}

// ─────────────────────────────────────────────────────────────────────────────
// Config helper
// ─────────────────────────────────────────────────────────────────────────────

func getToolConfig(configPath string, toolName string) (*kit.ToolConfig, error) {
	if configPath == "" {
		_, filename, _, _ := runtime.Caller(0)
		dir := filepath.Dir(filename)
		configPath = filepath.Join(dir, "http-kit.json")
	}

	tools, err := kit.LoadTools(configPath)
	if err != nil {
		return nil, err
	}

	for _, t := range tools {
		if strings.EqualFold(strings.TrimSpace(t.Name), toolName) && t.Enabled {
			c := t
			return &c, nil
		}
	}
	return nil, fmt.Errorf("%s not found or disabled in %s", toolName, configPath)
}
