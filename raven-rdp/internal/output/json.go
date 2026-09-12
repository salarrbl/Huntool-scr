package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// JSONRow is one serialized audit result. It carries the password
// field only for successful authentication events.
type JSONRow struct {
	Target     string `json:"target"`
	Status     string `json:"status"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	Timestamp  string `json:"timestamp"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

// JSONWriter streams audit results to a JSON array file.
//
// It must be used from a single goroutine (the event dispatcher);
// Close finalizes the array and syncs the file.
type JSONWriter struct {
	f   *os.File
	buf *bufio.Writer
	enc *json.Encoder
	n   int
}

// NewJSONWriter opens path for streaming JSON results.
func NewJSONWriter(path string) (*JSONWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("open JSON report %q: %w", path, err)
	}
	buf := bufio.NewWriterSize(f, 256*1024)
	if _, err := buf.WriteString("[\n"); err != nil {
		f.Close()
		return nil, fmt.Errorf("write JSON report: %w", err)
	}
	return &JSONWriter{f: f, buf: buf, enc: json.NewEncoder(buf)}, nil
}

// Event appends one result row.
func (w *JSONWriter) Event(t time.Time, target, status, username, password string, duration time.Duration, errMsg string) error {
	row := JSONRow{
		Target:     target,
		Status:     status,
		Username:   username,
		Password:   password,
		Timestamp:  t.UTC().Format(time.RFC3339),
		DurationMS: duration.Milliseconds(),
		Error:      errMsg,
	}
	if w.n > 0 {
		if _, err := w.buf.WriteString(",\n"); err != nil {
			return err
		}
	}
	w.n++
	return w.enc.Encode(row)
}

// Close finalizes the array, flushes and syncs the file.
func (w *JSONWriter) Close() error {
	_, err := w.buf.WriteString("\n]\n")
	if syncErr := w.buf.Flush(); err == nil {
		err = syncErr
	}
	if closeErr := w.f.Close(); err == nil {
		err = closeErr
	}
	return err
}
