package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"github.com/salarrbl/raven-rdp/internal/engine"
	"github.com/salarrbl/raven-rdp/internal/input"
	"github.com/salarrbl/raven-rdp/internal/output"
	"github.com/salarrbl/raven-rdp/internal/rdp"
	"github.com/salarrbl/raven-rdp/internal/tui"
	"github.com/salarrbl/raven-rdp/internal/version"
	"github.com/salarrbl/raven-rdp/pkg/banner"
)

// App is one audit run: configuration, logging and wiring.
type App struct {
	cfg   Config
	log   *slog.Logger
	color bool
}

// New validates cfg and builds the App.
func New(cfg Config) (*App, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	var level slog.Level
	switch {
	case cfg.Verbose:
		level = slog.LevelDebug
	case cfg.Quiet:
		level = slog.LevelWarn
	default:
		level = slog.LevelInfo
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	color := term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("NO_COLOR") == ""

	return &App{cfg: cfg, log: log, color: color}, nil
}

// Run executes the full lifecycle and returns a process exit code:
// 0 success, 1 fatal setup/run error, 130 interrupted.
func (a *App) Run(parent context.Context) int {
	cfg := a.cfg

	users, err := input.ReadUsers(cfg.UsersFile)
	if err != nil {
		a.log.Error("load users", "error", err)
		return 1
	}
	pws, err := input.ReadPasswords(cfg.PasswordsFile)
	if err != nil {
		a.log.Error("load passwords", "error", err)
		return 1
	}
	a.log.Debug("loaded credential lists", "users", len(users), "passwords", pws.Len())

	reader, err := input.StreamTargets(parent, cfg.TargetsFile, cfg.Port)
	if err != nil {
		a.log.Error("open targets", "error", err)
		return 1
	}
	a.log.Debug("target stream ready", "file", cfg.TargetsFile)

	client := rdp.NewClient(cfg.Timeout)
	eng := engine.New(client, cfg.Policy(), users, pws.Len(), pws.At, a.log)

	jw, cw, err := a.openReportWriters()
	if err != nil {
		a.log.Error("open report writers", "error", err)
		return 1
	}

	console := output.NewConsole(os.Stderr, a.color, cfg.Quiet)

	if cfg.TUI && term.IsTerminal(int(os.Stdout.Fd())) {
		return a.runTUI(parent, eng, reader, console, jw, cw, len(users), pws.Len())
	}
	if cfg.TUI {
		a.log.Info("stdout is not a TTY; falling back to line output")
	}
	return a.runConsole(parent, eng, reader, console, jw, cw, len(users), pws.Len())
}

// openReportWriters creates the configured JSON/CSV report writers.
// With --output but no format flag, JSON is the default.
func (a *App) openReportWriters() (jw *output.JSONWriter, cw *output.CSVWriter, err error) {
	cfg := a.cfg
	if cfg.Output == "" {
		return nil, nil, nil
	}

	wantJSON := cfg.JSON || (!cfg.JSON && !cfg.CSV)
	wantCSV := cfg.CSV

	if wantJSON {
		path := cfg.Output
		if wantCSV {
			path = cfg.Output + ".json"
		}
		jw, err = output.NewJSONWriter(path)
		if err != nil {
			return nil, nil, err
		}
		a.log.Info("JSON report", "path", path)
	}
	if wantCSV {
		path := cfg.Output
		if wantJSON {
			path = cfg.Output + ".csv"
		}
		cw, err = output.NewCSVWriter(path)
		if err != nil {
			if jw != nil {
				jw.Close()
			}
			return nil, nil, err
		}
		a.log.Info("CSV report", "path", path)
	}
	return jw, cw, nil
}

// dispatch consumes the engine event stream and fans out to report
// writers, the console renderer (line mode) and, optionally, the TUI.
// Report writes are lossless; the TUI send may apply backpressure.
// It returns a channel closed when all output (including report
// flushes) is complete.
func (a *App) dispatch(events <-chan engine.Event, console *output.Console, jw *output.JSONWriter, cw *output.CSVWriter, send func(engine.Event)) <-chan struct{} {
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		defer func() {
			if jw != nil {
				if err := jw.Close(); err != nil {
					a.log.Error("close JSON report", "error", err)
				}
			}
			if cw != nil {
				if err := cw.Close(); err != nil {
					a.log.Error("close CSV report", "error", err)
				}
			}
		}()

		for ev := range events {
			if jw != nil {
				if err := jw.Event(ev.Time, ev.Target, ev.Status.String(), ev.Username, ev.Duration, ev.Message); err != nil {
					a.log.Error("JSON write failed", "error", err)
				}
			}
			if cw != nil {
				if err := cw.Event(ev.Time, ev.Target, ev.Status.String(), ev.Username, ev.Duration, ev.Message); err != nil {
					a.log.Error("CSV write failed", "error", err)
				}
			}
			if console != nil {
				if ev.Status == rdp.StatusAuthSuccess {
					console.Success(ev.Time, ev.Target, ev.Username)
				} else {
					console.Event(ev.Time, ev.Target, ev.Status.String(), ev.Username, ev.Message)
				}
			}
			if send != nil {
				send(ev)
			}
		}
	}()
	return finished
}

// runConsole is the line-oriented mode (no TUI).
func (a *App) runConsole(parent context.Context, eng *engine.Engine, reader *input.TargetReader, console *output.Console, jw *output.JSONWriter, cw *output.CSVWriter, userCount, passCount int) int {
	cfg := a.cfg

	if !cfg.Quiet {
		a.printBanner(console)
	}

	// Graceful shutdown: first signal cancels the run context, the
	// second force-exits.
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		first := true
		for range sig {
			if first {
				first = false
				a.log.Warn("interrupt received: stopping new work, draining in-flight attempts (press again to force)")
				if !cfg.Quiet {
					fmt.Fprintln(os.Stderr)
				}
				cancel()
			} else {
				os.Exit(130)
			}
		}
	}()

	finished := a.dispatch(eng.Events(), console, jw, cw, nil)

	runErr := eng.Run(ctx, reader)
	cancel()

	// Wait for the dispatcher to flush and close the reports before
	// printing the summary and exiting.
	<-finished

	a.printFinalSummary(console, eng, reader, userCount, passCount)

	if runErr != nil {
		if errors.Is(runErr, context.Canceled) {
			return 130
		}
		a.log.Error("run finished with error", "error", runErr)
		return 1
	}
	return 0
}

// runTUI is the interactive Bubble Tea mode.
func (a *App) runTUI(parent context.Context, eng *engine.Engine, reader *input.TargetReader, console *output.Console, jw *output.JSONWriter, cw *output.CSVWriter, userCount, passCount int) int {
	cfg := a.cfg

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	model := tui.New(eng, cancel)
	prog := tea.NewProgram(model, tea.WithoutSignalHandler())

	// SIGINT is translated into a model message: first press performs
	// the graceful stop, a second press while stopping force-quits.
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		for {
			select {
			case <-sig:
				prog.Send(tui.SIGINTMsg{})
			case <-ctx.Done():
				return
			}
		}
	}()

	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, reader) }()

	// Drain the event stream (and the report writers) only after the
	// run has finished, then deliver the terminal TUI message.
	go func() {
		runErr := <-done
		a.dispatch(eng.Events(), nil, jw, cw, func(ev engine.Event) {
			prog.Send(tui.EventMsg{Ev: ev})
		})
		prog.Send(tui.EngineDoneMsg{Err: runErr})
	}()

	if _, err := prog.Run(); err != nil {
		a.log.Error("TUI exited", "error", err)
	}

	if model.Forced() {
		return 130
	}
	if !cfg.Quiet && cfg.Output != "" {
		fmt.Fprintf(os.Stderr, "reports written to %s\n", cfg.Output)
	}
	return 0
}

// printBanner shows the wordmark, tagline and configuration summary.
func (a *App) printBanner(console *output.Console) {
	cfg := a.cfg
	fmt.Fprintln(os.Stderr, console.Header(banner.Art))
	fmt.Fprintln(os.Stderr, "  "+console.Header(banner.Tagline))
	fmt.Fprintln(os.Stderr, "  "+console.Value("RavenRDP v"+version.Version))
	fmt.Fprintln(os.Stderr)
	console.ConfigSummary([]string{
		"Targets: " + cfg.TargetsFile,
		"Users: " + cfg.UsersFile,
		"Passwords: " + cfg.PasswordsFile,
		"Port: " + fmt.Sprintf("%d", cfg.Port),
		"Workers: " + fmt.Sprintf("%d", cfg.Workers),
		"Timeout: " + cfg.Timeout.String(),
	})
	console.SafetyLimits(cfg.Policy().Summary())
	fmt.Fprintln(os.Stderr)
}

// printFinalSummary renders the closing statistics box.
func (a *App) printFinalSummary(console *output.Console, eng *engine.Engine, reader *input.TargetReader, userCount, passCount int) {
	met := eng.Metrics()
	s := output.Summary{
		Targets:        met.Targets.Load(),
		Open:           met.Open.Load(),
		Closed:         met.Closed.Load(),
		Timeout:        met.Timeout.Load(),
		ProbeError:     met.ProbeError.Load(),
		SkippedAuth:    met.SkippedAuth.Load(),
		Attempts:       met.Attempts.Load(),
		Success:        met.Success.Load(),
		Failed:         met.Failed.Load(),
		AuthTimeout:    met.AuthTimeout.Load(),
		AuthError:      met.AuthError.Load(),
		Cancelled:      met.Cancelled.Load(),
		LimitReached:   met.LimitReached.Load(),
		RateNotices:    met.RateNotices.Load(),
		Users:          userCount,
		Passwords:      passCount,
		TargetsInvalid: reader.Invalid(),
		TargetsDups:    reader.Dups(),
		Duration:       met.Elapsed(),
	}
	fmt.Fprintln(os.Stderr)
	console.Summary(s)
}
