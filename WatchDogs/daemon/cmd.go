// daemon/cmd.go
package daemonpkg

import (
	"bufio"
	"context" // Add this import
	"fmt"
	"net"
	"net/url" // Add this import
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// runScanCycleFunc holds the function pointer passed from the main package.
var runScanCycleFunc func(ctx context.Context) error // Updated signature

// Initialize sets up the daemon command package with the RunScanCycle function from the main package.
func Initialize(runScanCycle func(ctx context.Context) error) { // Updated signature
	runScanCycleFunc = runScanCycle
}

// getRunScanCycleFunc retrieves the injected RunScanCycle function.
func getRunScanCycleFunc() func(ctx context.Context) error { // Updated signature
	return runScanCycleFunc
}

// RootCmd is the main cobra command for daemon functionalities.
var RootCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Manage the Watchdogs daemon",
	Long:  `Commands to start, stop, and manage the Watchdogs background process.`,
}

// startCmd represents the daemon start command.
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the daemon",
	Long:  `Starts the Watchdogs tool in background mode, continuously monitoring and scanning.`,
	RunE:  startRunE,
}

// rerunCmd represents the rerun command.
var rerunCmd = &cobra.Command{
	Use:   "rerun",
	Short: "Rerun the scan process",
	Long:  `Executes the full scan process from scratch once.`,
	RunE:  rerunRunE,
}

// extractCmd represents the domain extraction command.
var extractCmd = &cobra.Command{
	Use:   "extract-domains",
	Short: "Extract domains from input",
	Long:  `Extracts domains from a list of URLs, either from a file or standard input.`,
	RunE:  extractRunE,
}

var (
	manager *Manager
)

func init() {
	// Global flags for database configuration (added to RootCmd)
	RootCmd.PersistentFlags().String("db-host", "localhost", "Database host address")
	RootCmd.PersistentFlags().Int("db-port", 27017, "Database port number")
	RootCmd.PersistentFlags().String("db-name", "watchdogs", "Database name")
	RootCmd.PersistentFlags().String("db-user", "", "Database username")
	RootCmd.PersistentFlags().String("db-password", "", "Database password (consider using environment variables)")

	// Daemon start command flags
	startCmd.Flags().String("status-file", "daemon_status.json", "Path to the daemon status file")
	startCmd.Flags().String("pid-file", "watchdogs.pid", "Path to the daemon PID file")

	// Rerun command flags (inherits global DB flags)
	rerunCmd.Flags().AddFlagSet(startCmd.Flags())

	// Extract command flags
	extractCmd.Flags().String("input-file", "", "Input file containing URLs (one per line)")
	extractCmd.Flags().Bool("from-db", false, "Extract domains from the database 'http' collection")

	RootCmd.AddCommand(startCmd)
	RootCmd.AddCommand(rerunCmd)
	RootCmd.AddCommand(extractCmd)
}

// startRunE is now a placeholder, as the main daemon loop is in main.go
func startRunE(cmd *cobra.Command, args []string) error {
	fmt.Println("The 'daemon start' command is deprecated. Please run './watchdogs' directly to start the daemon with file watching.")
	return nil
	/*
	// Old implementation, kept for reference if daemon package needs its own loop again
	statusFile, _ := cmd.Flags().GetString("status-file")
	pidFile, _ := cmd.Flags().GetString("pid-file")
	dbHost, _ := cmd.Flags().GetString("db-host")
	dbPort, _ := cmd.Flags().GetInt("db-port")
	dbName, _ := cmd.Flags().GetString("db-name")
	dbUser, _ := cmd.Flags().GetString("db-user")
	dbPass, _ := cmd.Flags().GetString("db-password")

	dbURI := fmt.Sprintf("mongodb://%s:%d", dbHost, dbPort)
	if dbUser != "" && dbPass != "" {
		dbURI = fmt.Sprintf("mongodb://%s:%s@%s:%d", dbUser, dbPass, dbHost, dbPort)
	}

	// Use the function passed via Initialize
	manager = NewManager(statusFile, pidFile, dbURI, dbName, getRunScanCycleFunc())
	return manager.Start(cmd, args) // This call is now invalid as Start doesn't exist in the updated manager.go
	*/
}

func rerunRunE(cmd *cobra.Command, args []string) error {
	// Reuse the same manager setup as daemon for consistency
	statusFile, _ := cmd.Flags().GetString("status-file")
	pidFile, _ := cmd.Flags().GetString("pid-file")
	dbHost, _ := cmd.Flags().GetString("db-host")
	dbPort, _ := cmd.Flags().GetInt("db-port")
	dbName, _ := cmd.Flags().GetString("db-name")
	dbUser, _ := cmd.Flags().GetString("db-user")
	dbPass, _ := cmd.Flags().GetString("db-password")

	dbURI := fmt.Sprintf("mongodb://%s:%d", dbHost, dbPort)
	if dbUser != "" && dbPass != "" {
		dbURI = fmt.Sprintf("mongodb://%s:%s@%s:%d", dbUser, dbPass, dbHost, dbPort)
	}

	manager = NewManager(statusFile, pidFile, dbURI, dbName, getRunScanCycleFunc()) // Updated call
	return manager.Rerun(cmd, args)
}

// extractRunE handles the domain extraction logic.
func extractRunE(cmd *cobra.Command, args []string) error {
	inputFile, _ := cmd.Flags().GetString("input-file")
	fromDB, _ := cmd.Flags().GetBool("from-db")
	if fromDB {
		fmt.Println("[EXTRACT] Extracting domains from DB is not implemented in this snippet.")
		// Implement DB connection and query here if needed
		return nil
	}

	var lines []string
	if inputFile != "" {
		data, err := os.ReadFile(inputFile)
		if err != nil {
			return fmt.Errorf("read input file: %w", err)
		}
		lines = strings.Split(string(data), "\n")
	} else {
		// Read from stdin
		fmt.Println("[EXTRACT] Reading URLs from stdin. Press Ctrl+D when done:")
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				lines = append(lines, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
	}

	extractAndPrintDomains(lines)
	return nil
}

// extractAndPrintDomains parses URLs and prints only the host part.
func extractAndPrintDomains(urls []string) {
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		parsed, err := url.Parse(u)
		if err != nil {
			// Attempt to parse as a plain host:port or just host
			host := u
			if h, _, err := net.SplitHostPort(u); err == nil {
				host = h
			}
			fmt.Println(host)
			continue
		}
		host := parsed.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		fmt.Println(host)
	}
}
