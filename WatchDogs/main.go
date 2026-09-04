package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	apiPkg "watchdogs/Api"
	db "watchdogs/DB"
	eyes "watchdogs/Eyes"
	kit "watchdogs/Kit"
	httppkg "watchdogs/Kit/Http"
	gungnir "watchdogs/Kit/gungnir"
	cmdPkg "watchdogs/cmd"

	"github.com/fsnotify/fsnotify"
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

type TargetConfig = db.TargetConfig

func extractRootDomains(domains []string) []string {
	var roots []string
	seen := make(map[string]bool)
	re := regexp.MustCompile(`^(?:\*\.?)?([a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})*)$`)
	for _, pattern := range domains {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		// ONLY scan wildcard patterns — skip anything that does not start with *
		if !strings.HasPrefix(pattern, "*") {
			continue
		}
		matches := re.FindStringSubmatch(pattern)
		if len(matches) >= 2 {
			root := matches[1]
			if !strings.Contains(root, "*") && !seen[root] {
				seen[root] = true
				roots = append(roots, root)
				continue
			}
		}
		root := strings.TrimPrefix(pattern, "*.")
		root = strings.TrimPrefix(root, "*")
		root = strings.TrimPrefix(root, ".")
		if strings.Contains(root, ".") && !strings.Contains(root, "*") && !seen[root] {
			seen[root] = true
			roots = append(roots, root)
		}
	}
	return roots
}

func trimSlice(slice []string) []string {
	var trimmed []string
	for _, s := range slice {
		s = strings.TrimSpace(s)
		if s != "" {
			trimmed = append(trimmed, s)
		}
	}
	return trimmed
}

func loadTargets() ([]TargetConfig, error) {
	var targets []TargetConfig
	
	// First, try to load from MongoDB
	dbTargets, err := db.GetAllTargetsFromTargets()
	if err == nil && len(dbTargets) > 0 {
		fmt.Printf("📥 Loaded %d target(s) from MongoDB\n", len(dbTargets))
		targets = dbTargets
	} else {
		fmt.Printf("⚠️ MongoDB targets empty or error: %v\n", err)
	}
	
	// Fallback: load from breads.json if MongoDB is empty
	if len(targets) == 0 {
		configPath := filepath.Join("Breads", "breads.json")
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			execPath, err := os.Executable()
			if err == nil {
				dir := filepath.Dir(execPath)
				configPath = filepath.Join(dir, "Breads", "breads.json")
			}
		}
		file, err := os.Open(configPath)
		if err == nil {
			defer file.Close()
			bytes, err := io.ReadAll(file)
			if err == nil && len(bytes) > 0 {
				if err := json.Unmarshal(bytes, &targets); err == nil {
					fmt.Printf("📥 Loaded %d target(s) from breads.json (fallback)\n", len(targets))
				}
			}
		}
	}

	for i := range targets {
		targets[i].Domain = strings.TrimSpace(targets[i].Domain)
		targets[i].InScope = trimSlice(targets[i].InScope)
		targets[i].OutOfScope = trimSlice(targets[i].OutOfScope)
	}

	return targets, nil
}

func getKitConfigPath() string {
	configPath := filepath.Join("Kit", "tools.json")
	if _, err := os.Stat(configPath); err == nil {
		return configPath
	}
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	return filepath.Join(dir, "tools.json")
}

// extractHostFromURL strips scheme/path from URLs, returning bare hostname.
// Naabu requires hostnames/IPs, NOT full URLs like https://sub.domain.com.
func extractHostFromURL(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	if strings.Contains(input, "://") {
		if u, err := url.Parse(input); err == nil && u.Host != "" {
			host := u.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				return h
			}
			return host
		}
	}
	if h, _, err := net.SplitHostPort(input); err == nil {
		return h
	}
	return input
}

func runScanCycle(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("❌ PANIC RECOVERED in runScanCycle: %v\n", r)
		}
	}()
	fmt.Println("─────────────────────────────────────────────")
	fmt.Println("🚀 Starting God-Mode Scan Cycle")
	fmt.Println("─────────────────────────────────────────────")
	targets, err := loadTargets()
	if err != nil {
		fmt.Printf("❌ Load targets: %v\n", err)
		return
	}
	if len(targets) == 0 {
		fmt.Println("❌ No targets in Breads/breads.json\n")
		return
	}
	fmt.Printf("🎯 Scanning %d target(s)\n", len(targets))
	configPath := getKitConfigPath()

	for _, t := range targets {
		if ctx.Err() != nil {
			fmt.Println("⚠️ Shutdown requested, stopping scan cycle.")
			return
		}

		domain := strings.TrimSpace(t.Domain)
		if domain == "" {
			continue
		}

		// CRITICAL FIX: No global timeout. Each phase gets its own.
		targetCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		fmt.Printf("\n🎯 Processing: %s\n", domain)

		if err := db.UpsertTarget(t); err != nil {
			fmt.Printf(" ⚠️ Failed to upsert target %s in DB: %v\n", domain, err)
		} else {
			fmt.Printf(" 💾 Target config saved for %s in DB\n", domain)
		}

		// ── PHASE 1: DISCOVERY ──
		startDisc := time.Now()
		scanRoots := extractRootDomains(t.InScope)
		if len(scanRoots) == 0 {
			fmt.Printf(" ℹ️ No valid domain patterns in in_scope, skipping scan for %s\n", domain)
			cancel()
			continue
		}
		fmt.Printf(" 📋 Found %d scannable root domain(s): %v\n", len(scanRoots), scanRoots)

		// Discovery gets its OWN 4-hour timeout
		discCtx, discCancel := context.WithTimeout(targetCtx, 4*time.Hour)
		rawSubs, err := kit.RunParallelDiscoveryTools(discCtx, scanRoots, configPath, 10)
		discCancel()

		if err != nil {
			fmt.Printf(" ⚠️ Parallel Discovery Tools failed: %v\n", err)
		}
		fmt.Printf(" ⏱️ Discovery completed in %v\n", time.Since(startDisc))
		fmt.Printf(" 📥 Raw subdomains in RAM (from discovery tools): %d\n", len(rawSubs))

		// ── PHASE 2: ENRICHMENT ──
		var liveHosts []string
		if len(rawSubs) > 0 {
			fmt.Println(" 🔍 [2/4] Running DNSx, HTTP Probing & CSPRecon...")
			startEnrich := time.Now()

			// Enrichment gets its OWN 6-hour timeout
			enrichCtx, enrichCancel := context.WithTimeout(targetCtx, 6*time.Hour)
			liveHostsFromEnrichment, err := httppkg.RunEnrichment(enrichCtx, domain, rawSubs)
			enrichCancel()

			if err != nil {
				fmt.Printf(" ⚠️ Enrichment failed: %v\n", err)
			} else {
				fmt.Printf(" ✅ Enrichment completed in %v\n", time.Since(startEnrich))
				liveHosts = liveHostsFromEnrichment
			}
		}

		// ── PHASE 3: NAABU PORT SCAN ──
		fmt.Println(" 🔍 [3/4] Checking for live hosts from DB for port scan...")
		startNaabu := time.Now()

		var naabuTargets []string
		liveHostsFromDB, err := db.GetDistinctSubdomainsByRootDomain(domain)
		if err != nil {
			fmt.Printf("⚠️ Failed to fetch live hosts for Naabu from DB for %s: %v\n", domain, err)
		} else {
			fmt.Printf("📋 Retrieved %d live hosts from DB for Naabu scan on %s\n", len(liveHostsFromDB), domain)
			seen := make(map[string]bool)
			for _, h := range liveHosts {
				// CRITICAL FIX: httpx returns full URLs, Naabu needs bare hostnames
				host := extractHostFromURL(h)
				if host != "" && !seen[host] {
					seen[host] = true
					naabuTargets = append(naabuTargets, host)
				}
			}
			for _, h := range liveHostsFromDB {
				h = strings.TrimSpace(h)
				if h != "" && !seen[h] {
					seen[h] = true
					naabuTargets = append(naabuTargets, h)
				}
			}
		}

		if len(naabuTargets) == 0 {
			fmt.Println("ℹ️ No live hosts for Naabu, skipping.")
		} else {
			fmt.Printf("🔍 [3/4] Running Naabu on %d LIVE hosts for %s...\n", len(naabuTargets), domain)

			// Naabu gets its OWN 3-hour timeout
			naabuCtx, naabuCancel := context.WithTimeout(targetCtx, 3*time.Hour)
			defer naabuCancel()

			tmpFileNaabu, tmpErr := os.CreateTemp("", "watchdogs-naabu-*.txt")
			if tmpErr != nil {
				fmt.Printf("❌ Temp file creation failed for Naabu: %v\n", tmpErr)
				fmt.Println("⚠️ Skipping Naabu due to temp file error.")
			} else {
				defer os.Remove(tmpFileNaabu.Name())

				for _, h := range naabuTargets {
					tmpFileNaabu.WriteString(h + "\n")
				}
				tmpFileNaabu.Close()

				naabuResults, err := kit.RunPrioritySuite(naabuCtx, tmpFileNaabu.Name(), configPath, 50)
				if err != nil {
					fmt.Printf("⚠️ Naabu suite failed for %s: %v\n", domain, err)
				} else {
					portsMap := make(map[string][]string)
					totalParsed := 0
					for _, res := range naabuResults {
						if strings.EqualFold(strings.TrimSpace(res.Name), "naabu") {
							// CRITICAL FIX: Parse output even if marked "failed" due to timeout
							// The output contains valid JSON lines from partial scan
							if res.Success || len(res.Output) > 100 {
								parsedPortsMap := kit.ParseNaabuOutput(res.Output)
								if len(parsedPortsMap) > 0 {
									for host, ports := range parsedPortsMap {
										if db.IsInScope(host, &t) {
											portsMap[host] = append(portsMap[host], ports...)
											totalParsed++
										} else {
											fmt.Printf("   [+] Filtering out Naabu result for out-of-scope host: %s\n", host)
										}
									}
								}
							}
							if !res.Success {
								fmt.Printf("   ⚠️ Naabu had issues but parsed %d hosts from partial output\n", totalParsed)
								if res.Error != "" {
									fmt.Printf("   📋 Error: %s\n", res.Error)
								}
							}
						}
					}

					if len(portsMap) > 0 {
						if err := db.UpdateNaabuPorts(domain, portsMap); err != nil {
							fmt.Printf("⚠️ Failed to save Naabu ports to http for %s: %v\n", domain, err)
						} else {
							fmt.Printf("✅ Naabu saved ports to 'http' for %d subdomains of %s in %v\n", len(portsMap), domain, time.Since(startNaabu))
						}
					} else if totalParsed == 0 {
						fmt.Printf("ℹ️ Naabu returned no parsable results or ports for %s.\n", domain)
					}
				}
			}
		}

		// ── PHASE 4: SCREENSHOTS ──
		fmt.Println(" 👁️ [4/4] Running Screenshot Capture...")
		startShots := time.Now()
		shotCtx, shotCancel := context.WithTimeout(targetCtx, 2*time.Hour)
		if err := eyes.RunScreenshotCapture(shotCtx, domain); err != nil {
			fmt.Printf(" ⚠️ Screenshots failed: %v\n", err)
		} else {
			fmt.Printf(" ✅ Screenshots complete in %v\n", time.Since(startShots))
		}
		shotCancel()

		cleanSubs := make(map[string]bool)
		for _, host := range liveHosts {
			host = strings.TrimSpace(host)
			if host != "" {
				cleanSubs[host] = true
			}
		}
		fmt.Printf(" 🏁 Target %s complete | %d total validated subdomains processed\n", domain, len(cleanSubs))

		cancel()
	}

	fmt.Println("─────────────────────────────────────────────")
	fmt.Println("[+] Scan Cycle Complete")
	fmt.Println("─────────────────────────────────────────────")
}

func waitForCTLogList(ctx context.Context, timeout time.Duration) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "GET", "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json", nil)
		if err != nil {
			return false
		}

		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return true
		}
		if resp != nil {
			resp.Body.Close()
		}

		select {
		case <-ctx.Done():
			return false
		case <-time.After(2 * time.Second):
		}
	}
}

func StartDaemon(ctx context.Context) {
	fmt.Println("🛡️ Watchdogs Daemon Initializing...")
	db.ConnectDB()
	defer func() {
		db.DisconnectDB()
	}()

	// Startup DB health check
	if err := db.CheckDBHealth(); err != nil {
		log.Printf("🚨🚨🚨 CRITICAL DB ISSUE ON STARTUP: %v", err)
		log.Printf("🚨🚨🚨 MongoDB storage appears NON-PERSISTENT. Data will be LOST on restart!")
		log.Printf("🚨🚨🚨 If using Docker: mount a volume with -v /host/data:/data/db")
		log.Printf("🚨🚨🚨 If using cloud VPS: ensure /var/lib/mongodb is on persistent disk")
	} else {
		log.Println("✅ DB health check passed on startup")
	}
	db.EnsureCollections()
	if err := db.WriteStartupToken(); err != nil {
		log.Printf("⚠️ Failed to write startup token: %v", err)
	}

	// Background DB guardian - detects wiped collections and recreates them
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := db.CheckDBHealth(); err != nil {
					log.Printf("🚨🚨🚨 DB GUARDIAN ALERT: %v", err)
					log.Printf("🚨🚨🚨 ATTEMPTING EMERGENCY RECOVERY...")
					db.EnsureCollections()
				}
				if err := db.VerifyStartupToken(); err != nil {
					log.Printf("🚨🚨🚨 DB WIPE DETECTED: %v", err)
				}
				if err := db.UpsertSystemHeartbeat(); err != nil {
					log.Printf("⚠️ Failed to write DB heartbeat: %v", err)
				}
			}
		}
	}()

	fmt.Println("\n⚔️ Launching Gungnir Dynamic Monitor...")
	gungnirRootFile := filepath.Join("Kit", "gungnir", "hot-breads")

	if _, err := os.Stat(gungnirRootFile); os.IsNotExist(err) {
		fmt.Printf("❌ Gungnir root domain file does not exist: %s\n", gungnirRootFile)
		fmt.Println("   Please ensure the file 'Kit/gungnir/hot-breads' exists with domains, one per line.")
		fmt.Println("   ⚠️ WARNING: Gungnir will NOT be launched as the required 'hot-breads' file is missing.")
	} else {
		gungnirCtx, cancelGungnir := context.WithCancel(ctx)
		go func() {
			defer cancelGungnir()
			backoff := 1 * time.Second
			for {
				select {
				case <-gungnirCtx.Done():
					fmt.Println("   🛑 Gungnir restart loop shutting down.")
					return
				default:
				}

				if !waitForCTLogList(gungnirCtx, 30*time.Second) {
					if gungnirCtx.Err() != nil {
						return
					}
					fmt.Printf("   ⚠️ gstatic CT log list unreachable. Retrying in %v...\n", backoff)
					select {
					case <-gungnirCtx.Done():
						return
					case <-time.After(backoff):
					}
					if backoff < 30*time.Second {
						backoff *= 2
					}
					continue
				}

				backoff = 1 * time.Second
				fmt.Println("   🚀 Starting Gungnir monitor...")
				done := make(chan struct{})
				go func() {
					gungnir.MonitorDynamic(gungnirCtx, gungnirRootFile)
					close(done)
				}()

				select {
				case <-gungnirCtx.Done():
					<-done
					return
				case <-done:
					fmt.Printf("   ⚠️ Gungnir exited. Restarting in %v...\n", backoff)
					select {
					case <-gungnirCtx.Done():
						return
					case <-time.After(backoff):
					}
					if backoff < 30*time.Second {
						backoff *= 2
					}
				}
			}
		}()
	}

	fmt.Println("\n⚡ Running initial scan cycle...")
	runScanCycle(ctx)

	fmt.Println("\n🔍 Starting file watcher")
	configPath := filepath.Join("Breads", "breads.json")

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		execPath, err := os.Executable()
		if err == nil {
			dir := filepath.Dir(execPath)
			configPath = filepath.Join(dir, "Breads", "breads.json")
		}
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Printf("❌ Error creating file watcher: %v\n", err)
		return
	}
	defer watcher.Close()

	dir := filepath.Dir(configPath)
	if err := watcher.Add(dir); err != nil {
		fmt.Printf("❌ Error adding directory to watcher: %v\n", err)
		return
	}

	lastKnownTargets := make(map[string]bool)
	initialTargets, err := loadTargets()
	if err != nil {
		fmt.Printf("⚠️ Warning: Could not load initial targets for tracking: %v\n", err)
	} else {
		for _, t := range initialTargets {
			lastKnownTargets[t.Domain] = true
		}
		fmt.Printf("Initialized target tracker with %d domains: %v\n", len(lastKnownTargets), lastKnownTargets)
	}

	periodicCheckTicker := time.NewTicker(5 * time.Minute)
	defer periodicCheckTicker.Stop()

	newTargetPending := false

	fmt.Println("\n🚀 Daemon entering perpetual monitoring mode... (Press Ctrl+C to stop)")

	for {
		select {
		case <-ctx.Done():
			fmt.Printf("\n⚠️ Received shutdown signal, exiting gracefully...\n")
			return
		case event, ok := <-watcher.Events:
			if !ok {
				fmt.Println("File watcher channel closed.")
				return
			}
			if event.Name == configPath && (event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create) {
				fmt.Printf("📁 Detected change in %s\n", filepath.Base(configPath))
				currentTargets, err := loadTargets()
				if err != nil {
					fmt.Printf("⚠️ Error reloading targets after file change: %v\n", err)
					continue
				}
				var newDomains []string
				currentMap := make(map[string]bool)
				for _, t := range currentTargets {
					domain := t.Domain
					currentMap[domain] = true
					if !lastKnownTargets[domain] {
						newDomains = append(newDomains, domain)
					}
				}

				if len(newDomains) > 0 {
					fmt.Printf("🎉 New targets detected: %v\n", newDomains)
					newTargetPending = true
				} else {
					fmt.Printf("ℹ️ No *new* targets detected (current targets: %v)\n", currentMap)
				}
				lastKnownTargets = currentMap
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				fmt.Println("File watcher errors channel closed.")
				return
			}
			fmt.Printf("⚠️ File watcher error: %v\n", err)
		case <-periodicCheckTicker.C:
			currentTargets, err := loadTargets()
			if err != nil {
				fmt.Printf("⚠️ Error reloading targets during periodic check: %v\n", err)
				continue
			}
			var newDomainsDuringPeriodic []string
			currentMap := make(map[string]bool)
			for _, t := range currentTargets {
				domain := t.Domain
				currentMap[domain] = true
				if !lastKnownTargets[domain] {
					newDomainsDuringPeriodic = append(newDomainsDuringPeriodic, domain)
				}
			}
			if len(newDomainsDuringPeriodic) > 0 {
				fmt.Printf("🎉 New targets detected during periodic check: %v\n", newDomainsDuringPeriodic)
				newTargetPending = true
			}
			lastKnownTargets = currentMap
		}

		if newTargetPending {
			fmt.Println("🔄 Triggering scan cycle for new targets...")
			newTargetPending = false
			triggerCtx, cancelTrigger := context.WithCancel(ctx)
			runScanCycle(triggerCtx)
			cancelTrigger()
		}
	}
}

var gungnirCmd = &cobra.Command{
	Use:   "gungnir",
	Short: "List subdomains discovered by Gungnir",
	Long:  `Fetches and prints all subdomains from the 'hot-breads' collection in the database.`,
	Run: func(cmd *cobra.Command, args []string) {
		db.ConnectDB()
		defer db.DisconnectDB()
		hotBreadsRecords, err := db.GetAllHotBreadsSubdomains()
		if err != nil {
			log.Printf("❌ Error fetching subdomains from 'hot-breads' collection: %v", err)
			return
		}
		for _, record := range hotBreadsRecords {
			fmt.Println(record.Subdomain)
		}
	},
}

func main() {
	if err := godotenv.Load(); err != nil {
		if !os.IsNotExist(err) {
			log.Printf("⚠️ Error loading .env file: %v", err)
		}
	}

	apiConfig, err := apiPkg.LoadConfig()
	if err != nil {
		log.Fatalf("❌ Failed to load API configuration: %v", err)
	}

	apiServer := apiPkg.NewServer(apiConfig)
	apiWasStarted := false

	if apiConfig.Enabled {
		if err := apiServer.Start(); err != nil {
			log.Printf("⚠️ API server failed to start: %v", err)
		} else {
			apiWasStarted = true
		}
	}

	cmdPkg.SetDaemonStartFunc(StartDaemon)

	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt signal, stopping...")
		cancel()
	}()

	defer func() {
		if apiWasStarted {
			log.Println("[MAIN] Shutting down API server...")
			apiServer.Stop()
		}
	}()

	if err := cmdPkg.Execute(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
