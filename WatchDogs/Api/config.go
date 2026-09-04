package api

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds the API server configuration loaded from api-config.json
type Config struct {
	Enabled    bool   `json:"enabled"`
	Port       int    `json:"port"`
	DBURI      string `json:"db_uri"`
	VPSAddress string `json:"vps_address"`
	APIKey     string `json:"api_key"`
	LogPath    string `json:"log_path,omitempty"`
}

var ConfigFilePath = filepath.Join("Api", "api-config.json")

func LoadConfig() (*Config, error) {
	file, err := os.Open(ConfigFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{Enabled: false}, nil // Return default config if file doesn't exist
		}
		return nil, fmt.Errorf("opening config file '%s': %w", ConfigFilePath, err)
	}
	defer file.Close()

	var config Config
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		return nil, fmt.Errorf("decoding config file '%s': %w", ConfigFilePath, err)
	}

	// Set default log path if not specified
	if config.LogPath == "" {
		config.LogPath = filepath.Join("Logs", "api.log")
	}

	return &config, nil
}
