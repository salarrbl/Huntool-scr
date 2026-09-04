package daemonpkg // Renamed from 'main'

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Status represents the current state of the daemon.
type Status struct {
	Status      string    `json:"status"`
	Message     string    `json:"message,omitempty"`
	LastRun     time.Time `json:"last_run,omitempty"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
}

// StatusManager handles reading, writing, and updating the daemon status file.
type StatusManager struct {
	filePath string
	mutex    sync.RWMutex
}

// NewStatusManager creates a new StatusManager instance.
func NewStatusManager(filePath string) *StatusManager {
	return &StatusManager{
		filePath: filePath,
	}
}

// UpdateStatus updates the daemon status in the JSON file.
func (sm *StatusManager) UpdateStatus(status, message string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	currentStatus := Status{
		Status:  status,
		Message: message,
	}

	if status == "completed" {
		currentStatus.LastSuccess = time.Now()
	} else if status == "failed" {
		currentStatus.LastError = message
	}
	currentStatus.LastRun = time.Now()

	data, err := json.MarshalIndent(currentStatus, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal status: %w", err)
	}

	return os.WriteFile(sm.filePath, data, 0644)
}

// ReadStatus reads the current daemon status from the JSON file.
func (sm *StatusManager) ReadStatus() (*Status, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	data, err := os.ReadFile(sm.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return &Status{Status: "unknown"}, nil
		}
		return nil, fmt.Errorf("read status file: %w", err)
	}

	var status Status
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, fmt.Errorf("unmarshal status: %w", err)
	}
	return &status, nil
}

