package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"watchdogs/colors"

	"github.com/spf13/cobra"
)

// apiCmd represents the api command
var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Start the Watchdogs API server",
	Long:  `Launches the FastAPI server (Python) located at Api/main.py to serve Watchdogs data via REST endpoints.`,
	Run: func(cmd *cobra.Command, args []string) {
		execPath, err := os.Executable()
		if err != nil {
			log.Fatalf("Cannot determine executable path: %v", err)
		}
		projectRoot := filepath.Dir(filepath.Dir(execPath))
		scriptPath := filepath.Join(projectRoot, "Api", "main.py")

		if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
			log.Fatalf("API script not found at: %s. Please ensure Api/main.py exists.", scriptPath)
		}

		pythonCmd := exec.Command("python3", "--version")
		if err := pythonCmd.Run(); err != nil {
			pythonCmd = exec.Command("python", "--version")
			if err := pythonCmd.Run(); err != nil {
				log.Fatal("Neither 'python3' nor 'python' found in PATH. Please install Python 3.x.")
			}
		}

		pythonExec := "python3"
		if err := exec.Command("python3", "--version").Run(); err != nil {
			pythonExec = "python"
		}

		port, _ := cmd.Flags().GetString("port")
		dbURI, _ := cmd.Flags().GetString("db-uri")

		env := os.Environ()
		env = append(env, fmt.Sprintf("MONGODB_URI=%s", dbURI))
		env = append(env, fmt.Sprintf("API_PORT=%s", port))

		cmdToRun := exec.Command(pythonExec, "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", port)
		cmdToRun.Dir = filepath.Join(projectRoot, "Api")
		cmdToRun.Env = env
		cmdToRun.Stdout = os.Stdout
		cmdToRun.Stderr = os.Stderr

		fmt.Printf("Starting Watchdogs Python API Server on http://0.0.0.0:%s/docs (Swagger UI)\n", port)
		fmt.Printf("   Connecting to DB URI: %s\n", dbURI)
		fmt.Println("   Press Ctrl+C to stop.")
		if err := cmdToRun.Run(); err != nil {
			uvErr := exec.Command(pythonExec, "-c", "import uvicorn").Run()
			if uvErr != nil {
				log.Println("Hint: It seems 'uvicorn' might not be installed. Install it using 'pip install uvicorn[standard]'")
			} else {
				log.Printf("Potential issues: Wrong port (%s), Database URI (%s) inaccessible, or other internal server errors.", port, dbURI)
			}
			log.Fatalf("Error running Python API server: %v", err)
		}
	},
}

// RootCmd represents the base command when called without any subcommands.
var RootCmd = &cobra.Command{
	Use:   "watchdogs",
	Short: "A security automation tool",
	Long:  `Watchdogs is a security automation tool for subdomain monitoring, vulnerability scanning, and reporting.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		noColor, _ := cmd.Flags().GetBool("no-color")
		if noColor {
			colors.SetNoColor(true)
		}
	},
}

func init() {
	// Add persistent --no-color flag to RootCmd (inherited by ALL subcommands)
	// Note: -nc is handled by pre-processing os.Args before Cobra runs
	RootCmd.PersistentFlags().Bool("no-color", false, "Disable colored output (useful for piping to other tools)")

	apiCmd.Flags().String("port", "8080", "Port for the Python API server to listen on")
	apiCmd.Flags().String("db-uri", "mongodb://localhost:27017/watchdogs", "MongoDB URI for the Python API server")

	RootCmd.AddCommand(BreadsCmd)
	RootCmd.AddCommand(gungnirCmd)
	RootCmd.AddCommand(xssCmd)
}

// stripNoColorFlag removes -nc/--nc from args and returns true if found
func stripNoColorFlag(args []string) ([]string, bool) {
	var cleaned []string
	found := false
	for _, arg := range args {
		if arg == "-nc" || arg == "--nc" {
			found = true
			continue
		}
		// Handle -nc combined with other flags like -ncf
		if strings.HasPrefix(arg, "-nc") && len(arg) > 3 && arg[3] != '-' {
			cleaned = append(cleaned, "-"+arg[3:])
			found = true
			continue
		}
		cleaned = append(cleaned, arg)
	}
	return cleaned, found
}

// Execute executes the root command.
func Execute(daemonCtx context.Context) error {
	// Pre-process args to handle -nc shorthand before Cobra parses
	if len(os.Args) > 1 {
		cleanedArgs, noColor := stripNoColorFlag(os.Args[1:])
		if noColor {
			colors.SetNoColor(true)
			os.Args = append([]string{os.Args[0]}, cleanedArgs...)
		}
	}

	RootCmd.SetContext(daemonCtx)
	return RootCmd.Execute()
}
