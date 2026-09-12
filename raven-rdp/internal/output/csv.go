package output

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"os"
	"time"
)

// CSVHeader is the report column order.
// The password column is included for successful authentication events.
var CSVHeader = []string{"timestamp", "target", "status", "username", "password", "duration_ms", "error"}

// CSVWriter streams audit results to a CSV file.
//
// It must be used from a single goroutine (the event dispatcher);
// Close flushes and syncs the file.
type CSVWriter struct {
	f   *os.File
	buf *bufio.Writer
	cw  *csv.Writer
}

// NewCSVWriter opens path for streaming CSV results.
func NewCSVWriter(path string) (*CSVWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("open CSV report %q: %w", path, err)
	}
	buf := bufio.NewWriterSize(f, 256*1024)
	cw := csv.NewWriter(buf)
	if err := cw.Write(CSVHeader); err != nil {
		f.Close()
		return nil, fmt.Errorf("write CSV header: %w", err)
	}
	return &CSVWriter{f: f, buf: buf, cw: cw}, nil
}

// Event appends one result row.
func (w *CSVWriter) Event(t time.Time, target, status, username, password string, duration time.Duration, errMsg string) error {
	return w.cw.Write([]string{
		t.UTC().Format(time.RFC3339),
		target,
		status,
		username,
		password,
		fmt.Sprintf("%d", duration.Milliseconds()),
		errMsg,
	})
}

// Close flushes and syncs the file.
func (w *CSVWriter) Close() error {
	w.cw.Flush()
	if err := w.buf.Flush(); err != nil {
		w.f.Close()
		return err
	}
	return w.f.Close()
}