package gungnir

import (
	"encoding/json"
	"os"
)

// MonitorConfig defines what Gungnir watches.
type MonitorConfig struct {
	Target string `json:"target"` // e.g., "example.com" (Used to potentially generate the input file for Gungnir)
	// Note: Removed MonitorInterval as Gungnir handles its own timing with -f
	Checks []Check `json:"checks"` // List of checks to perform (though for Gungnir, this might just be one "subdomain" check type)
}

// Check defines a specific monitoring action.
type Check struct {
	Type       string `json:"type"`       // Should be "subdomain" for the Gungnir command
	Parameters string `json:"parameters"` // Additional parameters for the 'gungnir' command (e.g., "-silent", "-j")
}

// LoadConfig loads the Gungnir configuration from a JSON file.
func LoadConfig(configPath string) ([]MonitorConfig, error) {
	var configs []MonitorConfig
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &configs); err != nil {
		return nil, err
	}
	// Validation could be added here if needed (e.g., check if Type is "subdomain")
	return configs, nil
}
