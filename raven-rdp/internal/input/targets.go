// Package input parses operator-supplied list files (targets, users,
// passwords).
//
// All parsers are streaming: lines are read one at a time with a
// bounded scanner buffer and are never fully slurped into memory.
// Parsers ignore blank lines and lines starting with '#', trim
// surrounding whitespace, and remove duplicate entries.
package input

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"github.com/salarrbl/raven-rdp/internal/rdp"
)

// maxLineBytes bounds a single line. Targets and usernames are short;
// passwords may be long, but 64 KiB is far beyond any sane use.
const maxLineBytes = 64 * 1024

// MaxUsers caps the number of unique usernames per run.
const MaxUsers = 100_000

// MaxPasswords caps the number of unique passwords per run.
const MaxPasswords = 500_000

// nextLine yields the next non-blank, non-comment, trimmed line.
func nextLine(sc *bufio.Scanner) (string, bool) {
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line, true
	}
	return "", false
}

// openFile opens a list file with an actionable error message.
func openFile(path, kind string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s file %q does not exist", kind, path)
		}
		return nil, fmt.Errorf("open %s file %q: %w", kind, path, err)
	}
	return f, nil
}

// scanList reads an entire list file (users, passwords) into a slice,
// enforcing a hard entry cap so memory stays bounded for large files.
func scanList(path, kind string, max int) ([]string, error) {
	f, err := openFile(path, kind)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	seen := make(map[string]struct{}, 1024)
	out := make([]string, 0, 1024)
	for {
		line, ok := nextLine(sc)
		if !ok {
			break
		}
		if _, dup := seen[line]; dup {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
		if len(out) > max {
			return nil, fmt.Errorf("%s list too large: more than %d unique entries; split the file into smaller audited sets", kind, max)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s file %q: %w", kind, path, err)
	}
	return out, nil
}

// TargetReader streams parsed targets from a file. The Targets channel
// closes after the last target; Done carries a terminal error (nil on
// a clean read). Invalid lines are skipped and counted, never fatal.
type TargetReader struct {
	Targets <-chan rdp.Target
	Done    <-chan error

	ch   chan rdp.Target
	done chan error

	parsed  atomic.Int64
	invalid atomic.Int64
	dups    atomic.Int64
}

// Parsed counts accepted targets.
func (r *TargetReader) Parsed() int64 { return r.parsed.Load() }

// Invalid counts skipped malformed lines.
func (r *TargetReader) Invalid() int64 { return r.invalid.Load() }

// Dups counts duplicate lines removed.
func (r *TargetReader) Dups() int64 { return r.dups.Load() }

// StreamTargets parses target lines (host or host:port) from path,
// applying defaultPort when a line omits a port. Parsing continues in
// the background; consuming r.Targets drives the stream.
func StreamTargets(ctx context.Context, path string, defaultPort int) (*TargetReader, error) {
	f, err := openFile(path, "targets")
	if err != nil {
		return nil, err
	}

	ch := make(chan rdp.Target, 512)
	done := make(chan error, 1)
	r := &TargetReader{Targets: ch, Done: done, ch: ch, done: done}
	go func() {
		defer f.Close()
		defer close(r.ch)

		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
		seen := make(map[string]struct{}, 4096)

		emit := func(t rdp.Target) {
			for {
				select {
				case r.ch <- t:
					return
				case <-ctx.Done():
					return
				}
			}
		}

		for {
			line, ok := nextLine(sc)
			if !ok {
				break
			}
			t, err := rdp.ParseTarget(line, defaultPort)
			if err != nil {
				r.invalid.Add(1)
				continue
			}
			key := t.String()
			if _, dup := seen[key]; dup {
				r.dups.Add(1)
				continue
			}
			seen[key] = struct{}{}
			r.parsed.Add(1)
			emit(t)
		}
		if err := sc.Err(); err != nil {
			r.done <- fmt.Errorf("read targets file %q: %w", path, err)
		} else {
			r.done <- nil
		}
	}()
	return r, nil
}
