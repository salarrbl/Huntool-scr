package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"watchdogs/Kit/xss"

	"github.com/spf13/cobra"
)

var xssCmd = &cobra.Command{
	Use:   "xss",
	Short: "Reflected XSS discovery and verification",
	Long:  `Runs parameter discovery, URL generation, and optional Nuclei verification for reflected XSS. Based on Rebel Methodology V1.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 && targetFile == "" {
			fmt.Fprintf(os.Stderr, "Usage: watchdogs xss <target-or-url-file> [flags]\n")
			os.Exit(1)
		}

		runXSSWorkflow(cmd.Context(), args)
	},
}

var runNuclei bool
var strategy string
var strategyValue string
var templatePath string
var targetFile string
var concurrency int
var maxParams int
var outputDir string
var verbose bool

func runXSSWorkflow(ctx context.Context, args []string) {
	fmt.Println("🔍 Starting XSS workflow (Rebel Methodology V1)...")

	// Parse strategy
	var strat xss.Strategy
	switch strings.ToLower(strategy) {
	case "normal":
		strat = xss.StrategyNormal
	case "combine":
		strat = xss.StrategyCombine
	case "ignore":
		strat = xss.StrategyIgnore
	case "all":
		strat = xss.StrategyAll
	default:
		strat = xss.StrategyCombine
	}

	// Parse mutation mode
	var mutMode xss.MutationMode
	switch strings.ToLower(strategyValue) {
	case "replace":
		mutMode = xss.MutationReplace
	case "suffix":
		mutMode = xss.MutationSuffix
	case "prefix":
		mutMode = xss.MutationPrefix
	default:
		mutMode = xss.MutationReplace
	}

	// Load wordlist
	wordlist := xss.HighYieldWordlist
	if targetFile != "" {
		loaded, err := xss.LoadWordlist(targetFile)
		if err == nil && len(loaded) > 0 {
			wordlist = loaded
			fmt.Printf("📝 Loaded %d parameters from %s\n", len(wordlist), targetFile)
		}
	}

	// Collect URLs from various sources
	var urls []string
	if len(args) > 0 {
		for _, arg := range args {
			if isFile(arg) {
				fileURLs, err := readURLsFromFile(arg)
				if err != nil {
					fmt.Printf("⚠️  Error reading %s: %v\n", arg, err)
					continue
				}
				urls = append(urls, fileURLs...)
			} else {
				// Assume it's a domain - fetch URLs via gau/wayback
				fmt.Printf("🔗 Fetching URLs for %s...\n", arg)
				domainURLs := fetchURLsForDomain(arg)
				urls = append(urls, domainURLs...)
			}
		}
	}

	if len(urls) == 0 {
		fmt.Println("❌ No URLs to process")
		return
	}

	fmt.Printf("📥 Collected %d URLs\n", len(urls))

	// Filter URLs (remove static assets)
	filteredURLs := filterURLs(urls)
	fmt.Printf("🧹 After filtering: %d URLs\n", len(filteredURLs))

	// Discover parameters
	fmt.Println("🔍 Discovering parameters...")
	params := xss.DiscoverParams(filteredURLs, wordlist, strat, maxParams)
	fmt.Printf("📋 Discovered %d parameters\n", len(params))

	// Detect encodings
	fmt.Println("🔍 Detecting encoding patterns...")
	encodings := xss.DetectEncodings(params, filteredURLs)
	if len(encodings) > 0 {
		fmt.Printf("🔐 Found %d encoded parameters:\n", len(encodings))
		for _, enc := range encodings {
			fmt.Printf("   %s=%s (%s) → %s\n", enc.Param, enc.Value, enc.Encoding, enc.Decoded)
		}
	}

	// Generate XSS test URLs
	fmt.Println("🧪 Generating XSS test URLs...")
	payloads := xss.Payloads
	testURLs := xss.GenerateXSSURLs("", params, payloads, strat, mutMode)
	if len(testURLs) == 0 {
		// Generate per base URL
		for _, baseURL := range filteredURLs {
			urls := xss.GenerateXSSURLs(baseURL, params, payloads, strat, mutMode)
			testURLs = append(testURLs, urls...)
		}
	}
	fmt.Printf("🎯 Generated %d test URLs\n", len(testURLs))

	// Save output
	if outputDir != "" {
		os.MkdirAll(outputDir, 0755)
		saveURLs(filepath.Join(outputDir, "xss_urls.txt"), testURLs)
		saveParams(filepath.Join(outputDir, "params.txt"), params)
		fmt.Printf("💾 Saved to %s/\n", outputDir)
	}

	// Run Nuclei if requested
	if runNuclei {
		fmt.Println("☢️  Running Nuclei verification...")
		runNucleiScan(outputDir, templatePath)
	}

	// Summary
	summary := xss.Summary{
		TotalURLs:      len(filteredURLs),
		TotalGenerated: len(testURLs),
		EncodedParams:  len(encodings),
		Strategy:       strategy,
		MutationMode:   strategyValue,
	}
	fmt.Println("\n" + summary.String())
	fmt.Println("✅ XSS workflow complete")
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func readURLsFromFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var urls []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}
	return urls, nil
}

func filterURLs(urls []string) []string {
	excludeExt := []string{".png", ".jpg", ".jpeg", ".gif", ".css", ".js", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".svg", ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3", ".webp", ".avif"}
	var filtered []string
	for _, u := range urls {
		skip := false
		for _, ext := range excludeExt {
			if strings.HasSuffix(strings.ToLower(u), ext) {
				skip = true
				break
			}
		}
		if !skip {
			filtered = append(filtered, u)
		}
	}
	return filtered
}

func fetchURLsForDomain(domain string) []string {
	fmt.Printf("   🔍 Fetching URLs via gau/waybackurls for %s...\n", domain)

	var allURLs []string

	// Try waybackurls first
	waybackURLs := runWaybackurls(domain)
	if len(waybackURLs) > 0 {
		fmt.Printf("      waybackurls: %d URLs\n", len(waybackURLs))
		allURLs = append(allURLs, waybackURLs...)
	}

	// Try gau
	gauURLs := runGau(domain)
	if len(gauURLs) > 0 {
		fmt.Printf("      gau: %d URLs\n", len(gauURLs))
		allURLs = append(allURLs, gauURLs...)
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, u := range allURLs {
		if !seen[u] {
			seen[u] = true
			unique = append(unique, u)
		}
	}

	fmt.Printf("   ✅ Total unique URLs: %d\n", len(unique))
	if len(unique) == 0 {
		// Fallback
		return []string{fmt.Sprintf("https://%s/", domain)}
	}
	return unique
}

func runWaybackurls(domain string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "waybackurls", domain)
	cmd.Env = append(os.Environ(), "PATH="+os.Getenv("PATH")+":/home/qarqa/go/bin")
	output, err := cmd.Output()
	if err != nil {
		if verbose {
			fmt.Printf("      ⚠️  waybackurls error: %v\n", err)
		}
		return nil
	}

	var urls []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			urls = append(urls, line)
		}
	}
	return urls
}

func runGau(domain string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "gau", "--subs", domain)
	cmd.Env = append(os.Environ(), "PATH="+os.Getenv("PATH")+":/home/qarqa/go/bin")
	output, err := cmd.Output()
	if err != nil {
		if verbose {
			fmt.Printf("      ⚠️  gau error: %v\n", err)
		}
		return nil
	}

	var urls []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			urls = append(urls, line)
		}
	}
	return urls
}

func saveURLs(path string, urls []string) {
	f, _ := os.Create(path)
	defer f.Close()
	for _, u := range urls {
		f.WriteString(u + "\n")
	}
}

func saveParams(path string, params []string) {
	f, _ := os.Create(path)
	defer f.Close()
	for _, p := range params {
		f.WriteString(p + "\n")
	}
}

func runNucleiScan(outputDir, templatePath string) {
	urlFile := filepath.Join(outputDir, "xss_urls.txt")
	if _, err := os.Stat(urlFile); os.IsNotExist(err) {
		fmt.Println("   ⚠️  No URL file found for Nuclei scan")
		return
	}

	// Use default template if not specified
	if templatePath == "" {
		templatePath = filepath.Join("Kit", "xss", "templates", "xss-detect.yaml")
	}

	fmt.Printf("   ☢️  Running Nuclei with template: %s\n", templatePath)
	fmt.Printf("   📄 Target URLs: %s\n", urlFile)

	// Run nuclei
	args := []string{
		"-l", urlFile,
		"-t", templatePath,
		"-o", filepath.Join(outputDir, "nuclei-results.txt"),
		"-jsonl", // JSONL output for parsing
		"-silent",
		"-rate-limit", "50",
		"-concurrency", "20",
		"-timeout", "10",
		"-retries", "1",
	}

	cmd := exec.Command("nuclei", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("   ⚠️  Nuclei scan completed with issues: %v\n", err)
	} else {
		fmt.Println("   ✅ Nuclei scan completed")
	}

	// Parse and display results
	resultsFile := filepath.Join(outputDir, "nuclei-results.txt")
	if data, err := os.ReadFile(resultsFile); err == nil && len(data) > 0 {
		fmt.Println("\n   📋 Nuclei Findings:")
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) != "" {
				fmt.Printf("      %s\n", line)
			}
		}
	}
}

func init() {
	xssCmd.Flags().BoolVar(&runNuclei, "nuclei", false, "Run Nuclei scan on generated URLs")
	xssCmd.Flags().StringVar(&strategy, "strategy", "combine", "Strategy: normal, combine, ignore, all")
	xssCmd.Flags().StringVar(&strategyValue, "strategy_value", "replace", "Mutation mode: replace, suffix, prefix")
	xssCmd.Flags().StringVar(&templatePath, "t", "", "Path to Nuclei YAML template")
	xssCmd.Flags().StringVar(&targetFile, "f", "", "File containing targets/parameters (one per line)")
	xssCmd.Flags().IntVar(&concurrency, "c", 20, "Concurrency level for workers")
	xssCmd.Flags().IntVar(&maxParams, "mp", 25, "Max parameters per generated URL chunk")
	xssCmd.Flags().StringVar(&outputDir, "o", "tmp", "Output directory")
	xssCmd.Flags().BoolVar(&verbose, "v", false, "Verbose debug output")
}