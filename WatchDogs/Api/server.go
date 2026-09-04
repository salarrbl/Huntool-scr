package api

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

type Server struct {
	cmd *exec.Cmd
	cfg *Config
}

func NewServer(cfg *Config) *Server {
	return &Server{cfg: cfg}
}

func (s *Server) Start() error {
	if !s.cfg.Enabled {
		return nil
	}

	// Ensure Logs directory exists
	logDir := filepath.Dir(s.cfg.LogPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("creating log directory: %w", err)
	}
	logFile, err := os.OpenFile(s.cfg.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("opening log file: %w", err)
	}

	scriptPath := filepath.Join("Api", "main.py")
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return fmt.Errorf("API script not found at: %s", scriptPath)
	}

	pythonExec := "python3"
	if err := exec.Command("python3", "--version").Run(); err != nil {
		pythonExec = "python"
	}

	env := os.Environ()
	env = append(env, fmt.Sprintf("MONGODB_URI=%s", s.cfg.DBURI))
	env = append(env, fmt.Sprintf("API_PORT=%d", s.cfg.Port))
	// Pass the API key from config to the Python environment
	env = append(env, fmt.Sprintf("WATCHDOGS_API_KEY=%s", s.cfg.APIKey))

	s.cmd = exec.Command(pythonExec, "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", fmt.Sprintf("%d", s.cfg.Port))
	s.cmd.Dir = "Api"
	s.cmd.Env = env

	// Redirect output to log file
	s.cmd.Stdout = logFile
	s.cmd.Stderr = logFile

	if err := s.cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("starting API process: %w", err)
	}

	log.Printf("🚀 API started on port %d | Logs: %s", s.cfg.Port, s.cfg.LogPath)
	return nil
}

func (s *Server) Stop() {
	if s.cmd != nil && s.cmd.Process != nil {
		s.cmd.Process.Signal(syscall.SIGTERM)
	}
}
