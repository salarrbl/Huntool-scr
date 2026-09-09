package rdp

import "context"

// Client abstracts the RDP transport so the engine never depends on a
// concrete protocol implementation. Implementations must:
//
//   - respect ctx cancellation and deadlines on every network operation,
//   - distinguish connection problems from authentication problems,
//   - never embed passwords in returned results or errors.
type Client interface {
	// Probe checks whether the RDP service is reachable on the target.
	Probe(ctx context.Context, target Target) ProbeResult

	// Authenticate performs one controlled credential check.
	Authenticate(ctx context.Context, target Target, username, password string) AuthResult
}
