package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"watchdogs/colors"

	apiPkg "watchdogs/Api"
)

// fetchAPI is the core function that replaces local DB calls.
func fetchAPI(path string) ([]byte, error) {
	cfg, err := apiPkg.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("config error: %w", err)
	}

	addr := cfg.VPSAddress
	if addr == "" {
		addr = "localhost"
	}

	url := fmt.Sprintf("http://%s:%d%s", addr, cfg.Port, path)

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	if cfg.APIKey != "" {
		req.Header.Set("X-API-Key", cfg.APIKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connection failed to %s: %w", addr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server error %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// printList formats a JSON array of strings into newline-separated output
func printList(data []byte) {
	var items []string
	if err := json.Unmarshal(data, &items); err == nil {
		for _, item := range items {
			fmt.Println(item)
		}
	}
}

// printListColored formats a JSON array of strings with Catppuccin colors
func printListColored(data []byte) {
	var items []string
	if err := json.Unmarshal(data, &items); err == nil {
		for _, item := range items {
			fmt.Println(colors.Colorize(colors.Lavender, item))
		}
	}
}

// printJSONRaw formats complex JSON objects for detailed views
func printJSONRaw(data []byte) {
	var items []interface{}
	if err := json.Unmarshal(data, &items); err == nil {
		jsonBytes, _ := json.MarshalIndent(items, "", "  ")
		fmt.Println(string(jsonBytes))
	}
}

// printJSONRawColored formats complex JSON objects with syntax highlighting
func printJSONRawColored(data []byte) {
	var items []interface{}
	if err := json.Unmarshal(data, &items); err == nil {
		jsonBytes, _ := json.MarshalIndent(items, "", "  ")
		fmt.Println(colorizeJSON(string(jsonBytes)))
	}
}

// colorizeJSON applies Catppuccin colors to JSON output
func colorizeJSON(input string) string {
	lines := []rune(input)
	var result []rune
	inString := false
	for i := 0; i < len(lines); i++ {
		ch := lines[i]
		if ch == '"' && (i == 0 || lines[i-1] != '\\') {
			if !inString {
				inString = true
				result = append(result, []rune(colors.Green)...)
				result = append(result, ch)
			} else {
				result = append(result, ch)
				result = append(result, []rune(colors.Reset)...)
				inString = false
			}
		} else {
			result = append(result, ch)
		}
	}
	return string(result) + colors.Reset
}
