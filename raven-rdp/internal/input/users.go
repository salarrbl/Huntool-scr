package input

import (
	"fmt"
	"strings"
)

// ReadUsers reads a username list. Lines are trimmed, comments and
// blanks ignored, duplicates removed.
//
// Usernames may carry an explicit domain prefix (CONTROSO\user or
// domain/user); both are preserved as-is for the RDP layer.
func ReadUsers(path string) ([]string, error) {
	out, err := scanList(path, "users", MaxUsers)
	if err != nil {
		return nil, err
	}
	for _, u := range out {
		if strings.ContainsAny(u, " \t") {
			return nil, fmt.Errorf("users file %q: entry %q contains whitespace", path, u)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("users file %q contains no usernames", path)
	}
	return out, nil
}
