package gungnir

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath" // Added for file path manipulation
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify" // Added for file watching
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	dbPkg "watchdogs/DB"
)

// HotBreadResult represents a single result entry for our DB.
type HotBreadResult struct {
	Subdomain  string    `bson:"subdomain" json:"subdomain"`
	RootDomain string    `bson:"root_domain" json:"root_domain"`
	Source     string    `bson:"source" json:"source"`
	Timestamp  time.Time `bson:"timestamp" json:"timestamp"`
}

// BatchNotifier manages collecting new discoveries and sending them in batches.
type BatchNotifier struct {
	batchSize   int
	flushTicker *time.Ticker
	batchMutex  sync.Mutex
	batch       []string
	stopCh      chan struct{}
	wg          sync.WaitGroup
}

// NewBatchNotifier creates a new BatchNotifier.
func NewBatchNotifier(batchSize int, flushInterval time.Duration) *BatchNotifier {
	bn := &BatchNotifier{
		batchSize:   batchSize,
		flushTicker: time.NewTicker(flushInterval),
		batch:       make([]string, 0, batchSize),
		stopCh:      make(chan struct{}),
	}
	bn.wg.Add(1)
	go bn.flushLoop() // Start the background flush loop
	return bn
}

// Add adds a new subdomain to the batch. It triggers a flush if the batch is full.
func (bn *BatchNotifier) Add(subdomain string) {
	bn.batchMutex.Lock()
	defer bn.batchMutex.Unlock()
	bn.batch = append(bn.batch, subdomain)

	if len(bn.batch) >= bn.batchSize {
		bn.flush() // Flush the full batch
	}
}

// Stop stops the notifier and flushes any remaining items.
func (bn *BatchNotifier) Stop() {
	close(bn.stopCh)
	bn.flushTicker.Stop()
	bn.wg.Wait() // Wait for the flushLoop goroutine to finish
}

// flushLoop handles the timer-based flushing.
func (bn *BatchNotifier) flushLoop() {
	defer bn.wg.Done()
	for {
		select {
		case <-bn.stopCh:
			bn.batchMutex.Lock()
			bn.flush() // Final flush
			bn.batchMutex.Unlock()
			return // Exit the loop and goroutine
		case <-bn.flushTicker.C:
			bn.batchMutex.Lock()
			bn.flush() // Flush due to timer
			bn.batchMutex.Unlock()
		}
	}
}

// flush sends the current batch as a single notification if it's not empty.
func (bn *BatchNotifier) flush() {
	if len(bn.batch) == 0 {
		return // Nothing to flush
	}
	// Create the message from the current batch
	message := formatBatchMessage(bn.batch)
	// Send the notification
	sendNtfyNotification(message)
	// Clear the batch after sending
	bn.batch = bn.batch[:0] // Re-slice to zero length, keeping capacity
}

// formatBatchMessage formats the slice of subdomains into a single message string.
func formatBatchMessage(subdomains []string) string {
	if len(subdomains) == 0 {
		return ""
	}
	if len(subdomains) == 1 {
		return fmt.Sprintf("God Found new Breads:\n\n%s", subdomains[0]) // Add blank line after header
	}
	// Join subdomains with double newlines for separation
	// This creates a visually distinct list in the notification.
	joinedSubs := strings.Join(subdomains, "\n\n") // Double newline between subdomains
	return fmt.Sprintf("God Found new Breads (%d):\n\n%s", len(subdomains), joinedSubs)
}

// runGungnirProcess encapsulates the logic for running a single gungnir process,
// monitoring its output, and handling its lifecycle.
func runGungnirProcess(ctx context.Context, rootDomainsFilePath string, batchNotifier *BatchNotifier) {
	log.Printf("🛡️ Gungnir Process Initializing for file: %s", rootDomainsFilePath)

	if rootDomainsFilePath == "" || dbPkg.Client == nil {
		log.Println("❌ Gungnir: Invalid file or DB.")
		return
	}

	if _, err := os.Stat(rootDomainsFilePath); os.IsNotExist(err) {
		log.Printf("❌ Gungnir file missing: %s", rootDomainsFilePath)
		return
	}

	cmd := exec.CommandContext(ctx, "gungnir", "-r", rootDomainsFilePath, "-f") // Plain text output
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe() // Capture stderr

	if err := cmd.Start(); err != nil {
		log.Printf("❌ Gungnir failed to start: %v", err)
		return
	}

	pid := cmd.Process.Pid
	log.Printf("🏃 Gungnir started (PID: %d)", pid)

	// Handle stderr
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			if line != "" { // Only log if there's content
				log.Printf("[Gungnir-ERR-%d] %s", pid, line)
			}
		}
	}()

	// Handle stdout (parse results - derive root domain, check local dupe, upsert, queue notification)
	go func() {
		scanner := bufio.NewScanner(stdout)
		processedThisRun := make(map[string]bool) // Track subdomains processed in *this* gungnir run

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || ctx.Err() != nil {
				continue
			}

			subdomain := line
			rootDomain := extractRootDomain(subdomain)

			if subdomain != "" && rootDomain != "" {
				key := fmt.Sprintf("%s|%s", subdomain, rootDomain)

				// Check if this combination was already processed in this specific gungnir run
				if processedThisRun[key] {
					continue // Skip duplicate line within the same gungnir process run
				}

				processedThisRun[key] = true // Mark as processed for this run

				result := HotBreadResult{
					Subdomain:  subdomain,
					RootDomain: rootDomain,
					Source:     "gungnir",
					Timestamp:  time.Now(),
				}

				// Upsert to DB
				collection := dbPkg.GetCollection("hot-breads")
				filter := bson.M{
					"subdomain":   result.Subdomain,
					"root_domain": result.RootDomain,
				}
				update := bson.M{
					"$set": bson.M{
						"timestamp": result.Timestamp,
						"source":    result.Source,
					},
					"$setOnInsert": bson.M{
						"discovered_at": result.Timestamp,
					},
				}
				opts := options.Update().SetUpsert(true)

				upsertRes, err := collection.UpdateOne(dbPkg.Ctx, filter, update, opts)
				if err != nil {
					log.Printf("⚠️ DB upsert failed for '%s' (root: %s): %v", subdomain, rootDomain, err)
				} else {
					if upsertRes.UpsertedCount > 0 {
						batchNotifier.Add(result.Subdomain) // Notify only if new document was inserted
					}
				}
			} else {
				log.Printf("⚠️ Could not derive root domain for Gungnir output: '%s'", line)
			}
		}
	}()

	// Wait for command or context cancellation
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-ctx.Done():
		log.Println("🛑 Gungnir received shutdown signal...")
		if proc := cmd.Process; proc != nil {
			proc.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				proc.Kill() // Force kill if needed
			}
		}
	case err := <-done:
		log.Printf("⚠️ Gungnir process ended (PID %d): %v", pid, err)
	}
	log.Println("🛑 Gungnir (PID:", pid, ") stopped.")
}

// MonitorDynamic watches the hot-breads file and launches/restarts gungnir processes when it changes.
func MonitorDynamic(ctx context.Context, rootDomainsFilePath string) {
	log.Println("🛡️ Gungnir Dynamic Monitor Initializing...")

	if rootDomainsFilePath == "" {
		log.Println("❌ Gungnir Dynamic Monitor: Invalid file path.")
		return
	}

	if _, err := os.Stat(rootDomainsFilePath); os.IsNotExist(err) {
		log.Printf("❌ Gungnir Dynamic Monitor: File missing: %s", rootDomainsFilePath)
		// Could choose to create an empty file or wait for it to appear, but for now, exit.
		return
	}

	// Create the batch notifier here, shared across gungnir processes
	batchNotifier := NewBatchNotifier(50, 1*time.Minute)
	defer batchNotifier.Stop() // Ensures final flush happens when MonitorDynamic exits

	watcher, err := NewFileWatcher(rootDomainsFilePath)
	if err != nil {
		log.Printf("❌ Gungnir Dynamic Monitor: Error creating file watcher: %v", err)
		return
	}
	defer watcher.Close()

	gungnirCtx, gungnirCancel := context.WithCancel(ctx)

	// Initial launch
	log.Println("🚀 Launching initial Gungnir process...")
	go runGungnirProcess(gungnirCtx, rootDomainsFilePath, batchNotifier)

	for {
		select {
		case <-ctx.Done():
			log.Println("🛑 Gungnir Dynamic Monitor received shutdown signal...")
			gungnirCancel() // Cancel the current gungnir process
			return
		case event := <-watcher.Events:
			if event.Op&fsnotify.Write == fsnotify.Write { // Only react to writes/modifications
				log.Printf("📁 Detected change in %s, restarting Gungnir...", filepath.Base(rootDomainsFilePath))
				gungnirCancel() // Cancel the old process

				// Create a new context for the new process
				gungnirCtx, gungnirCancel = context.WithCancel(ctx)

				// Start the new process with the shared notifier
				go runGungnirProcess(gungnirCtx, rootDomainsFilePath, batchNotifier)
			}
		case err := <-watcher.Errors:
			log.Printf("⚠️ Gungnir Dynamic Monitor: File watcher error: %v", err)
			// Depending on the error, you might want to exit or try to recreate the watcher.
			// For now, continue.
		}
	}
}

// NewFileWatcher creates an fsnotify watcher for the specified file.
// It watches the parent directory and filters events for the specific file.
func NewFileWatcher(filePath string) (*fsnotify.Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	dir := filepath.Dir(filePath)
	err = watcher.Add(dir)
	if err != nil {
		watcher.Close()
		return nil, err
	}

	return watcher, nil
}

// extractRootDomain derives the root domain from a given FQDN.
func extractRootDomain(fqdn string) string {
	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 {
		return fqdn // If it's just one part, return it as is (unlikely for CT data)
	}
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	// Fallback: return the whole thing if somehow it's too short after splitting
	return fqdn
}

// sendNtfyNotification sends a message to the configured ntfy endpoint with retry logic and rate limiting.
func sendNtfyNotification(message string) {
	topic := os.Getenv("NTFY_TOPIC")
	serverURL := os.Getenv("NTFY_SERVER_URL") // Allow custom server if needed
	if topic == "" {
		log.Println("⚠️ NTFY_TOPIC environment variable not set, skipping notification.")
		return
	}
	if serverURL == "" {
		serverURL = "https://ntfy.sh" // Default server
	}

	url := serverURL + "/" + topic

	// Retry logic
	maxRetries := 3
	retryDelay := 500 * time.Millisecond // Initial delay

	for attempt := 1; attempt <= maxRetries; attempt++ {
		cmd := exec.Command("curl", "-d", message, url, "-s", "--max-time", "10") // Add timeout

		// Run the command synchronously for this attempt
		err := cmd.Run()
		if err == nil {
			return // Exit the function after successful send
		}

		// Log failure for this attempt
		log.Printf("⚠️ Failed to send ntfy notification (attempt %d/%d): %v", attempt, maxRetries, err)

		// If it's not the last attempt, wait before retrying
		if attempt < maxRetries {
			time.Sleep(retryDelay)
		}
	}

	// If we reach here, all retries failed
	log.Printf("❌ Failed to send ntfy notification after %d attempts for message: %s", maxRetries, message)
}
