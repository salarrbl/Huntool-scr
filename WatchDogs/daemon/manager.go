package daemonpkg

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	// Remove direct imports of watchdogs packages here as they are not used directly in manager.go
	// The RunScanCycle function is passed in via NewManager/Initialize.
	// db "watchdogs/DB"
	// eyes "watchdogs/Eyes"
	// httppkg "watchdogs/Kit/Http"
	// kit "watchdogs/Kit"
)

// PIDManager handles writing and reading the daemon's Process ID.
type PIDManager struct {
	filePath string
}

func NewPIDManager(filePath string) *PIDManager {
	return &PIDManager{filePath: filePath}
}

func (p *PIDManager) WritePID() error {
	pid := os.Getpid()
	return os.WriteFile(p.filePath, []byte(fmt.Sprintf("%d", pid)), 0644)
}

func (p *PIDManager) ReadPID() (int, error) {
	data, err := os.ReadFile(p.filePath)
	if err != nil {
		return 0, err
	}
	var pid int
	fmt.Sscanf(string(data), "%d", &pid)
	return pid, nil
}

func (p *PIDManager) RemovePID() error {
	return os.Remove(p.filePath)
}

// StatusManager handles reading, writing, and updating the daemon status file.
// (Assuming status.go is already defined correctly)
// type StatusManager struct { ... }

// Manager coordinates the daemon's lifecycle, state persistence, and core logic execution.
type Manager struct {
	statusManager    *StatusManager
	pidManager       *PIDManager
	dbURI            string
	dbName           string
	// Function pointer to the main scan cycle logic
	runScanCycleFunc func(ctx context.Context) error
}

// NewManager creates a new Manager instance, accepting the scan function.
func NewManager(statusFile, pidFile, dbURI, dbName string, runScanCycleFunc func(ctx context.Context) error) *Manager {
	return &Manager{
		statusManager:    NewStatusManager(statusFile),
		pidManager:       NewPIDManager(pidFile),
		dbURI:            dbURI,
		dbName:           dbName,
		runScanCycleFunc: runScanCycleFunc, // Store the function pointer
	}
}

// runMainLogic executes the core scanning logic using the stored function pointer.
func (m *Manager) runMainLogic(ctx context.Context) error {
	// Call the function passed from main, which includes DB operations
	return m.runScanCycleFunc(ctx)
}

// Start begins the daemon's operation.
func (m *Manager) Start(ctx context.Context) error {
	log.Println("[DAEMON] Starting daemon...")

	// Write PID first
	if err := m.pidManager.WritePID(); err != nil {
		return fmt.Errorf("failed to write PID: %w", err)
	}
	defer func() {
		if rmErr := m.pidManager.RemovePID(); rmErr != nil {
			log.Printf("Warning: failed to remove PID file: %v", rmErr)
		}
	}()

	// Update status to starting
	m.statusManager.UpdateStatus("starting", "Daemon is starting up")

	// Simulate startup tasks if needed...

	// Update status to running
	m.statusManager.UpdateStatus("running", "Daemon is running and monitoring")

	// Run the main loop (which includes file watching and scan triggering)
	// This assumes the main daemon logic (like file watching) is handled elsewhere
	// or integrated into the Manager's Start method.
	// For now, we'll simulate a loop that periodically calls runMainLogic
	// based on triggers (like file changes, timers) managed externally or within runMainLogic itself.

	ticker := time.NewTicker(30 * time.Second) // Example ticker
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[DAEMON] Received stop signal, shutting down...")
			m.statusManager.UpdateStatus("stopping", "Daemon is shutting down")
			return nil // Exit the loop and function
		case <-ticker.C:
			// Example: Run scan cycle periodically (replace with file watch trigger)
			log.Println("[DAEMON] Periodic check initiated...")
			err := m.runMainLogic(ctx)
			if err != nil {
				log.Printf("[DAEMON] Scan cycle failed: %v", err)
				// Consider updating status with error details
				m.statusManager.UpdateStatus("error", fmt.Sprintf("Last scan failed: %v", err))
			} else {
				log.Println("[DAEMON] Scan cycle completed successfully")
				// Update status to running or idle, depending on interpretation
				m.statusManager.UpdateStatus("running", "Daemon is running and monitoring")
			}
		}
	}
}

// Stop signals the daemon to stop gracefully.
func (m *Manager) Stop() {
	log.Println("[DAEMON] Stop requested, signaling...")
	// Typically, you'd send a signal to the main goroutine running Start()
	// or close a context used within Start().
	// This is often handled by the caller of Manager.Start using context cancellation.
}
