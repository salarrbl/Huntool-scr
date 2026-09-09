package input

import "fmt"

// Passwords is an in-memory credential list. It intentionally exposes
// only index-based access so callers cannot accidentally print the
// whole list, and the type is never serialized by any output package.
type Passwords struct {
	items []string
}

// NewPasswords wraps a password list.
func NewPasswords(items []string) *Passwords {
	// Defensive copy: the list must not alias caller memory.
	cp := make([]string, len(items))
	copy(cp, items)
	return &Passwords{items: cp}
}

// Len returns the number of passwords.
func (p *Passwords) Len() int { return len(p.items) }

// At returns the password at index i.
func (p *Passwords) At(i int) string {
	if i < 0 || i >= len(p.items) {
		return ""
	}
	return p.items[i]
}

// ReadPasswords reads a password list. Lines are trimmed, comments and
// blanks ignored, duplicates removed.
//
// The returned value must only ever be handed to the RDP authentication
// call. Nothing in the codebase logs, prints, or serializes it.
func ReadPasswords(path string) (*Passwords, error) {
	items, err := scanList(path, "passwords", MaxPasswords)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("passwords file %q contains no passwords", path)
	}
	return NewPasswords(items), nil
}
