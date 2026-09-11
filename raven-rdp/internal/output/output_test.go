package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJSONWriterRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	w, err := NewJSONWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	if err := w.Event(ts, "10.0.0.1:3389", "OPEN", "", 12*time.Millisecond, "NLA enforced"); err != nil {
		t.Fatal(err)
	}
	if err := w.Event(ts, "10.0.0.1:3389", "AUTH_FAILURE", "alice", 340*time.Millisecond, "invalid credentials"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows []JSONRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatalf("report is not valid JSON: %v\n%s", err, raw)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].Target != "10.0.0.1:3389" || rows[0].Status != "OPEN" || rows[0].DurationMS != 12 {
		t.Fatalf("row 0 = %+v", rows[0])
	}
	if rows[1].Username != "alice" || rows[1].Error != "invalid credentials" || rows[1].DurationMS != 340 {
		t.Fatalf("row 1 = %+v", rows[1])
	}

	// No secret field may ever appear in a serialized row.
	for _, r := range rows {
		b, _ := json.Marshal(r)
		if strings.Contains(strings.ToLower(string(b)), "password") {
			t.Fatalf("serialized row mentions password: %s", b)
		}
	}
}

func TestJSONWriterEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	w, err := NewJSONWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows []JSONRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatalf("empty report is not valid JSON: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("got %d rows, want 0", len(rows))
	}
}

func TestCSVWriterRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.csv")
	w, err := NewCSVWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	// Error field with commas and a quote exercises CSV quoting.
	if err := w.Event(ts, "10.0.0.2:3389", "ERROR", "", 5*time.Millisecond, `weird, "quoted", fail`); err != nil {
		t.Fatal(err)
	}
	if err := w.Event(ts, "10.0.0.2:3389", "AUTH_SUCCESS", "bob", 77*time.Millisecond, "ok"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rd := csv.NewReader(f)
	rd.FieldsPerRecord = -1
	all, err := rd.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("got %d records (incl. header), want 3", len(all))
	}
	if got, want := all[0], CSVHeader; len(got) != len(want) {
		t.Fatalf("header = %v, want %v", got, want)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("header = %v, want %v", got, want)
			}
		}
	}
	if all[1][2] != "ERROR" || all[1][5] != `weird, "quoted", fail` {
		t.Fatalf("error row = %v", all[1])
	}
	if all[2][3] != "bob" || all[2][4] != "77" {
		t.Fatalf("success row = %v", all[2])
	}
}

func TestConsoleSuccessRedacted(t *testing.T) {
	var buf bytes.Buffer
	c := NewConsole(&buf, false, false)
	c.Success(time.Now(), "10.0.0.9:3389", "admin")
	out := buf.String()
	if !strings.Contains(out, Redacted) {
		t.Fatalf("success line must contain %s: %q", Redacted, out)
	}
	if !strings.Contains(out, "admin") {
		t.Fatalf("success line must name the username: %q", out)
	}
}

func TestConsoleQuietFiltering(t *testing.T) {
	var buf bytes.Buffer
	c := NewConsole(&buf, false, true)
	c.Event(time.Now(), "10.0.0.1:3389", "OPEN", "", "NLA enforced")
	if buf.Len() != 0 {
		t.Fatalf("quiet mode must suppress OPEN: %q", buf.String())
	}
	buf.Reset()
	c.Event(time.Now(), "10.0.0.1:3389", "AUTH_SUCCESS", "admin", "ok")
	if !strings.Contains(buf.String(), "AUTH_SUCCESS") {
		t.Fatalf("quiet mode must keep AUTH_SUCCESS: %q", buf.String())
	}
}

func TestConsoleEventLine(t *testing.T) {
	var buf bytes.Buffer
	c := NewConsole(&buf, false, false)
	c.Event(time.Date(2026, 9, 9, 13, 5, 7, 0, time.Local), "10.0.0.1:3389", "CLOSED", "", "connection refused")
	line := strings.TrimSpace(buf.String())
	for _, want := range []string{"13:05:07", "10.0.0.1:3389", "CLOSED", "connection refused"} {
		if !strings.Contains(line, want) {
			t.Fatalf("line %q missing %q", line, want)
		}
	}
}

func TestSummaryRender(t *testing.T) {
	var buf bytes.Buffer
	c := NewConsole(&buf, false, false)
	c.Summary(Summary{
		Targets: 3, Open: 2, Closed: 1, Attempts: 6, Success: 1, Failed: 5,
		Duration: 42 * time.Second,
	})
	out := buf.String()
	for _, want := range []string{"Targets tested", "3", "6"} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary missing %q:\n%s", want, out)
		}
	}
}

// TestSummaryShowsDroppedEvents pins N7: the final summary must
// surface events that never reached the reports.
func TestSummaryShowsDroppedEvents(t *testing.T) {
	var buf bytes.Buffer
	c := NewConsole(&buf, false, false)
	c.Summary(Summary{Targets: 2, Dropped: 7, Duration: time.Second})
	out := buf.String()
	for _, want := range []string{"Dropped events", "7"} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary missing %q:\n%s", want, out)
		}
	}
}
