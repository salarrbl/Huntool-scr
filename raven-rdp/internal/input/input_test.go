package input

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadUsers(t *testing.T) {
	path := writeTemp(t, "users.txt", "# comment\n\nadmin\nCONTROSO\\ops\nadmin\n  svc \n")
	got, err := ReadUsers(path)
	if err != nil {
		t.Fatalf("ReadUsers: %v", err)
	}
	want := []string{"admin", "CONTROSO\\ops", "svc"}
	if len(got) != len(want) {
		t.Fatalf("got %d users %v, want %v", len(got), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestReadUsersWhitespaceRejected(t *testing.T) {
	path := writeTemp(t, "users.txt", "bad user\n")
	if _, err := ReadUsers(path); err == nil {
		t.Fatal("want error for whitespace entry")
	}
}

func TestReadUsersEmpty(t *testing.T) {
	path := writeTemp(t, "users.txt", "# only comments\n\n")
	if _, err := ReadUsers(path); err == nil {
		t.Fatal("want error for empty list")
	}
}

func TestReadUsersMissing(t *testing.T) {
	if _, err := ReadUsers(filepath.Join(t.TempDir(), "nope.txt")); err == nil {
		t.Fatal("want error for missing file")
	}
}

func TestReadUsersCap(t *testing.T) {
	var b []byte
	for i := 0; i <= MaxUsers; i++ {
		b = append(b, fmt.Sprintf("user%d\n", i)...)
	}
	path := writeTemp(t, "users.txt", string(b))
	if _, err := ReadUsers(path); err == nil {
		t.Fatalf("want error for %d unique users", MaxUsers+1)
	}
}

func TestReadPasswords(t *testing.T) {
	path := writeTemp(t, "passwords.txt", "p1\np2\np1\n# note\np3\n")
	pws, err := ReadPasswords(path)
	if err != nil {
		t.Fatalf("ReadPasswords: %v", err)
	}
	if pws.Len() != 3 {
		t.Fatalf("Len = %d, want 3", pws.Len())
	}
	if got := pws.At(1); got != "p2" {
		t.Fatalf("At(1) = %q, want p2", got)
	}
	if pws.At(-1) != "" || pws.At(99) != "" {
		t.Fatal("out-of-range At must return empty string")
	}
}

func TestPasswordsDefensiveCopy(t *testing.T) {
	orig := []string{"a", "b"}
	p := NewPasswords(orig)
	orig[0] = "mutated"
	if p.At(0) != "a" {
		t.Fatal("Passwords must not alias caller memory")
	}
}

func TestStreamTargets(t *testing.T) {
	path := writeTemp(t, "targets.txt",
		"10.0.0.1\n\n# audited segment\n10.0.0.2:3390\n10.0.0.1\nnot a target:xx\n10.0.0.3\n")
	r, err := StreamTargets(context.Background(), path, 3389)
	if err != nil {
		t.Fatalf("StreamTargets: %v", err)
	}

	var got []string
	for s := range r.Targets {
		got = append(got, s.String())
	}
	want := []string{"10.0.0.1:3389", "10.0.0.2:3390", "10.0.0.3:3389"}
	if len(got) != len(want) {
		t.Fatalf("streamed %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("streamed %v, want %v", got, want)
		}
	}
	if err := <-r.Done; err != nil {
		t.Fatalf("Done = %v, want nil", err)
	}
	if r.Parsed() != 3 || r.Invalid() != 1 || r.Dups() != 1 {
		t.Fatalf("counters parsed=%d invalid=%d dups=%d, want 3/1/1",
			r.Parsed(), r.Invalid(), r.Dups())
	}
}

func TestStreamTargetsMissingFile(t *testing.T) {
	if _, err := StreamTargets(context.Background(), filepath.Join(t.TempDir(), "x"), 3389); err == nil {
		t.Fatal("want error for missing targets file")
	}
}

func TestStreamTargetsCancelledContext(t *testing.T) {
	path := writeTemp(t, "targets.txt", "10.0.0.1\n10.0.0.2\n10.0.0.3\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r, err := StreamTargets(ctx, path, 3389)
	if err != nil {
		t.Fatalf("StreamTargets: %v", err)
	}

	done := make(chan struct{})
	go func() {
		for range r.Targets {
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("target stream did not close after context cancel")
	}
	<-r.Done
}

func TestStreamTargetsDefaultPort(t *testing.T) {
	path := writeTemp(t, "targets.txt", "10.9.9.9\n")
	r, err := StreamTargets(context.Background(), path, 9001)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for s := range r.Targets {
		got = append(got, s.String())
	}
	if len(got) != 1 || got[0] != "10.9.9.9:9001" {
		t.Fatalf("got %v, want [10.9.9.9:9001]", got)
	}
	<-r.Done
}

func TestScanListDedupeOrder(t *testing.T) {
	// Dedupe preserves first-seen order.
	path := writeTemp(t, "l.txt", "b\na\nb\nc\n")
	out, err := scanList(path, "users", 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"b", "a", "c"}
	if len(out) != 3 || out[0] != want[0] || out[1] != want[1] || out[2] != want[2] {
		t.Fatalf("got %v, want %v", out, want)
	}
}
