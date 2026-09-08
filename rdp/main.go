package main

import (
	"bufio"
	"fmt"
	"math/big"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CIDR represents a parsed CIDR range
type CIDR struct {
	IP   net.IP
	Mask int
}

// ScanResult holds the result of a scan
type ScanResult struct {
	IP     string
	Open   bool
}

func main() {
	// Parse CLI args
	inputFile := ""
	outputFile := "rdp_live.txt"
	concurrency := 100
	timeout := 2 * time.Second
	maxCIDR := 0 // 0 = no limit, skip CIDRs smaller than this (e.g., 20 skips /20 and larger networks)

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-o", "--output":
			if i+1 < len(args) {
				outputFile = args[i+1]
				i++
			}
		case "-c", "--concurrency":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 {
					concurrency = n
				}
				i++
			}
		case "-t", "--timeout":
			if i+1 < len(args) {
				if d, err := time.ParseDuration(args[i+1]); err == nil {
					timeout = d
				}
				i++
			}
		case "--max-cidr":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil && n >= 0 && n <= 32 {
					maxCIDR = n
				}
				i++
			}
		case "-h", "--help":
			printUsage()
			return
		default:
			if !strings.HasPrefix(args[i], "-") && inputFile == "" {
				inputFile = args[i]
			}
		}
	}

	if inputFile == "" {
		printUsage()
		os.Exit(1)
	}

	// Read and parse CIDRs
	fmt.Println("[*] Loading CIDRs...")
	cidrs, err := readCIDRs(inputFile, maxCIDR)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[*] Parsed %d CIDR ranges (after filtering)\n", len(cidrs))

	// Expand to unique IPs with progress
	fmt.Println("[*] Expanding ranges...")
	ips := expandCIDRs(cidrs)
	fmt.Printf("[+] %d unique IPs\n", len(ips))

	if len(ips) == 0 {
		fmt.Println("[!] No valid IPs to scan")
		os.Exit(0)
	}

	// Sort IPs for consistent output
	sort.Strings(ips)

	// Scan
	fmt.Printf("[*] Scanning TCP/3389 (concurrency: %d, timeout: %s)...\n", concurrency, timeout)
	results := scanIPs(ips, concurrency, timeout)

	// Filter open and print
	var openIPs []string
	openCount := 0
	for _, r := range results {
		if r.Open {
			openIPs = append(openIPs, r.IP)
			openCount++
			fmt.Printf("[+] %s:3389 OPEN\n", r.IP)
		}
	}

	fmt.Printf("[+] Scan complete\n")
	fmt.Printf("[+] %d RDP host(s) found\n", openCount)

	// Save results
	if openCount > 0 {
		if err := saveResults(openIPs, outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving results: %v\n", err)
		} else {
			fmt.Printf("[+] Results saved to: %s\n", outputFile)
		}
	} else {
		fmt.Println("[!] No open RDP hosts found")
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `rdp-scan - Lightweight RDP exposure scanner

Usage: rdp-scan <input> [options]

Arguments:
  <input>           Path to file containing CIDR ranges

Options:
  -o, --output      Output file for found hosts (default: rdp_live.txt)
  -c, --concurrency Number of concurrent TCP checks (default: 100)
  -t, --timeout     TCP connection timeout (default: 2s, e.g., 500ms, 2s)
  --max-cidr        Skip CIDRs smaller than this prefix (e.g., 20 skips /20 and larger networks)
  -h, --help        Show this help message

Input file format:
  One CIDR per line, e.g.:
    1.0.1.0/24
    1.0.2.0/23
    
  Lines starting with # are comments.
  Blank lines are ignored.
  Malformed entries are skipped with a warning.

Examples:
  rdp-scan ranges.txt
  rdp-scan ranges.txt -o results.txt -c 200
  rdp-scan ranges.txt -c 50 -t 1s
  rdp-scan ranges.txt --max-cidr 24
`)
}

func readCIDRs(filename string, maxCIDR int) ([]CIDR, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cidrs []CIDR
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and blank lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if cidr, ok := parseCIDR(line); ok {
			// Skip large CIDRs if maxCIDR is set
			if maxCIDR > 0 && cidr.Mask < maxCIDR {
				totalIPs := uint64(1) << uint(32-cidr.Mask)
				fmt.Fprintf(os.Stderr, "[!] Skipping %s/%d (%d IPs) - use --max-cidr to change threshold\n", 
					cidr.IP.String(), cidr.Mask, totalIPs)
				continue
			}
			cidrs = append(cidrs, cidr)
		} else {
			fmt.Fprintf(os.Stderr, "[!] Skipping malformed CIDR: %s\n", line)
		}
	}
	return cidrs, scanner.Err()
}

func parseCIDR(s string) (CIDR, bool) {
	s = strings.TrimSpace(s)
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return CIDR{}, false
	}
	ip := net.ParseIP(parts[0])
	if ip == nil {
		return CIDR{}, false
	}
	mask, err := strconv.Atoi(parts[1])
	if err != nil || mask < 0 || mask > 32 {
		return CIDR{}, false
	}
	// Only support IPv4
	if ip.To4() == nil {
		return CIDR{}, false
	}
	return CIDR{IP: ip.To4(), Mask: mask}, true
}

// expandCIDRs expands CIDR ranges to unique IP addresses
func expandCIDRs(cidrs []CIDR) []string {
	// Use a map for deduplication
	ipSet := make(map[string]struct{})
	
	totalIPs := 0
	for _, cidr := range cidrs {
		start := ipToBigInt(cidr.IP)
		hostBits := 32 - cidr.Mask
		count := uint64(1) << uint(hostBits)
		
		current := new(big.Int).Set(start)
		one := big.NewInt(1)
		
		for i := uint64(0); i < count; i++ {
			ipStr := bigIntToIP(current)
			ipSet[ipStr] = struct{}{}
			current.Add(current, one)
		}
		totalIPs += int(count)
		
		if len(ipSet)%100000 == 0 {
			fmt.Fprintf(os.Stderr, "[*] Expanding... %d unique IPs so far\n", len(ipSet))
		}
	}
	
	// Convert map to sorted slice
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	
	fmt.Fprintf(os.Stderr, "[*] Expanded %d total IPs from %d CIDRs\n", totalIPs, len(cidrs))
	return ips
}

func ipToBigInt(ip net.IP) *big.Int {
	ip = ip.To4()
	if ip == nil {
		return big.NewInt(0)
	}
	return big.NewInt(0).SetBytes(ip)
}

func bigIntToIP(n *big.Int) string {
	bytes := n.Bytes()
	// Pad to 4 bytes
	if len(bytes) < 4 {
		padded := make([]byte, 4)
		copy(padded[4-len(bytes):], bytes)
		bytes = padded
	}
	return fmt.Sprintf("%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3])
}

func scanIPs(ips []string, concurrency int, timeout time.Duration) []ScanResult {
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make([]ScanResult, len(ips))
	var processed atomic.Int64
	total := int64(len(ips))

	// Create semaphore for bounded concurrency
	sem := make(chan struct{}, concurrency)

	for i, ip := range ips {
		wg.Add(1)
		go func(idx int, ipAddr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := ScanResult{IP: ipAddr}
			addr := net.JoinHostPort(ipAddr, "3389")
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				conn.Close()
				result.Open = true
			}

			mu.Lock()
			results[idx] = result
			mu.Unlock()

			processed.Add(1)
			// Print progress every 500 or at completion
			if processed.Load()%500 == 0 || processed.Load() == total {
				fmt.Printf("[*] Progress: %d/%d (%.1f%%)\n", 
					processed.Load(), total, float64(processed.Load())/float64(total)*100)
			}
		}(i, ip)
	}

	wg.Wait()
	return results
}

func saveResults(ips []string, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, ip := range ips {
		fmt.Fprintln(writer, ip)
	}
	return writer.Flush()
}
