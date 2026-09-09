# RavenRDP

**RavenRDP** is an authorized RDP credential-auditing and exposure-testing
tool written in Go. Given lists of targets, usernames and passwords that you
are explicitly authorized to test, it checks which targets expose RDP,
classifies their Network Level Authentication (NLA) mode, and verifies which
credential pairs are valid — under hard, configurable safety limits.

> ## Authorized use only
> RavenRDP is intended exclusively for systems you own or are explicitly
> authorized to test (e.g. penetration tests, exposure audits of your own
> fleet, emergency credential-rotation checks). Using it against systems you
> do not own or have written authorization to test is illegal in most
> jurisdictions. The built-in attempt limits, rate limits and audit reports
> are not optional decoration — keep them on.

---

## Features

- **Lightweight RDP probe** — a minimal X.224/RDPneg fingerprint (no full
  session) classifies each target: port open/closed/timeout and NLA mode
  (required, hybrid-ex, or not enforced). Targets without NLA are reported
  and skipped — there is nothing for a credential check to do.
- **NLA (CredSSP) credential verification** — uses the maintained,
  pure-Go [`x90skysn3k/grdp`](https://github.com/x90skysn3k/grdp) RDP stack
  with auth-only logins; no RDP protocol code is reimplemented here. The
  transport sits behind a small `rdp.Client` interface so the engine has no
  protocol dependencies.
- **Interactive TUI** (Bubble Tea + Lip Gloss) — live statistics, a rolling
  event log with semantic colors, pause/resume, and graceful shutdown.
  Automatically falls back to line output when stdout is not a TTY or
  `--no-tui` is set. `NO_COLOR` is honored.
- **JSON / CSV audit reports** — one row per probe/auth outcome, with
  timestamps and durations. No secret appears in any report by
  construction: rows carry `timestamp, target, status, username,
  duration_ms, error` — there is no password field to leak.
- **No telemetry, no analytics, no hidden network calls.** The only traffic
  is to the targets you list.

## Safety controls (always on)

| Control | Flag / default | Behavior |
| --- | --- | --- |
| Per-target attempt limit | `--attempt-limit` (default 20) | Stops authentication for a target after N attempts → `ATTEMPT_LIMIT` |
| Per-target rate limit | `--target-rate` (default 10/min) | Spaces attempts per target; long waits surface as `RATE_LIMITED` |
| Global concurrency | `--workers` (default 10) | Caps simultaneous operations |
| Per-operation timeout | `--timeout` (default 5s) | Bounds every dial/read/auth |
| Graceful shutdown | `Ctrl+C` | First press: stop new work, drain in-flight attempts. Second press: force quit (exit 130) |
| Credential hygiene | — | Passwords are read into an opaque store with index-only access; they are never printed, logged, or serialized. Success lines show `Password: [REDACTED]` |

## Building

Requires Go 1.25+ (built and tested with 1.27).

```sh
make build          # -> dist/raven-rdp (version/commit/date stamped)
make test           # go test ./...
make race           # go test -race ./...
make lint           # gofmt check + go vet
make clean
```

Or directly:

```sh
go build -o raven-rdp ./cmd/raven-rdp
```

## Usage

```
raven-rdp \
  --targets targets.txt \
  --users users.txt \
  --passwords passwords.txt \
  --workers 10 --attempt-limit 20 --target-rate 10 \
  --timeout 5s --port 3389 \
  --output report.json --json [--csv] \
  [--no-tui] [--verbose | --quiet]
```

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--targets` | required | File of targets: `host`, `host:port`, or bare IPv6 |
| `--users` | required | Username list (`CONTROSO\user` and `domain/user` preserved) |
| `--passwords` | required | Password list (handled opaquely, never displayed) |
| `--workers` | `10` | Concurrent workers (global cap) |
| `--port` | `3389` | Default RDP port for lines without an explicit port |
| `--timeout` | `5s` | Timeout for every network operation |
| `--attempt-limit` | `20` | Max authentication attempts per target |
| `--target-rate` | `10` | Max authentication attempts per target per minute |
| `--output` | — | Report path (JSON by default; with `--json --csv`, writes `<path>.json` and `<path>.csv`) |
| `--json` / `--csv` | off | Report formats |
| `--no-tui` | off | Line output instead of the interactive UI |
| `--verbose` / `--quiet` | off | Debug logging / security-relevant events only |
| `--version` | | Print version, commit, build date |
| `--help` | | Usage |

List files: lines are trimmed; blank lines and `#` comments ignored;
duplicates removed. Malformed target lines are skipped and counted in the
summary.

### TUI keys

| Key | Action |
| --- | --- |
| `q` / `Ctrl+C` | Stop (first press graceful, second force) |
| `p` | Pause new authentication work |
| `r` | Resume |
| `k`/`j` or `↑`/`↓` | Scroll event log |
| `g` | Jump to newest event |

Colors: `OPEN` green, `AUTH_SUCCESS` bold green, `AUTH_FAILURE` red,
`TIMEOUT` yellow, headers purple/magenta.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Run completed |
| 1 | Fatal setup/run error |
| 2 | Usage / configuration error |
| 130 | Interrupted (Ctrl+C / SIGTERM) |

## Statuses

| Status | Meaning |
| --- | --- |
| `OPEN` | RDP endpoint reachable (NLA mode in the message) |
| `CLOSED` | Connection refused / endpoint gone |
| `TIMEOUT` | Dial or auth did not finish in time |
| `AUTH_SUCCESS` | Credential pair verified (password redacted) |
| `AUTH_FAILURE` | Credential pair rejected by the server |
| `RATE_LIMITED` | Waiting for a per-target rate slot (attempt still made) |
| `ATTEMPT_LIMIT` | Per-target attempt limit reached |
| `ERROR` | Transport/protocol problem that is not auth failure |
| `CANCELLED` | Stopped by shutdown before the attempt completed |
| `INFO` | Diagnostics (skips, list exhaustion, stream errors) |

## Reports

JSON (array) and CSV (header `timestamp,target,status,username,duration_ms,error`)
contain one row per outcome. The `username` column is present only for
authentication outcomes. No password or other secret is ever written.

Example JSON row:

```json
{"target":"10.0.0.5:3389","status":"AUTH_SUCCESS","username":"admin","timestamp":"2026-09-09T12:00:00Z","duration_ms":245,"error":"Password: [REDACTED]"}
```

## How it works

```
targets file ──► streaming parser (dedupe, default port, error counting)
                      │
                ┌─────▼─────┐     ┌────────────────────┐
                │ PROBE     │────►│ AUTH               │
                │ X.224 /   │     │ per-target job:    │
                │ RDPneg    │     │ (userIdx,passIdx)  │
                │ (grdp)    │     │ cursor — no users× │
                └───────────┘     │ passwords matrix   │
                                  │ materialized in    │
                                  │ memory             │
                                  └────────────────────┘
                      │
              bounded event stream ──► single dispatcher
                       ├─ TUI (live stats + event log)
                       ├─ console lines (--no-tui / non-TTY)
                       └─ JSON / CSV writers (lossless)
```

- **Probe stage**: bounded FIFO of targets, N concurrent workers. A failed
  probe never affects other targets.
- **Auth stage**: only `OPEN` + NLA-enforced targets create jobs. Each job
  holds its safety guard (attempt limit), its rate limiter, and a cursor
  into the credential matrix; the password itself is pulled through an
  accessor per attempt and never stored. A job performs one attempt per
  dequeue and is re-queued if work remains, so a rate-limited target never
  pins a worker.
- **Metrics & events**: all counters are atomic; one event fan-out feeds
  the UI, console, and report writers. Report writes are lossless.

## Project layout

```
cmd/raven-rdp/        entrypoint (flag dispatch, exit codes)
internal/app/         lifecycle, configuration validation
internal/cli/         flag parsing, help, version
internal/input/       streaming list parsers (targets/users/passwords)
internal/rdp/         Client interface + grdp-backed implementation
internal/engine/      queues, rate limiter, jobs, workers, metrics
internal/safety/      policy + per-target attempt guard
internal/output/      console renderer, JSON/CSV writers, summary
internal/tui/         Bubble Tea model, views, keys
internal/version/     build-time version info
pkg/banner/           wordmark
testdata/             sample list files
```

## Testing

The suite covers parsing/dedup, configuration validation, the rate limiter
and attempt guard (including concurrent use), the bounded queue, the job
cursor, the full engine against a mocked RDP client (success, attempt
limit, list exhaustion, timeouts, cancellation, pause/resume, metric
consistency), report serialization, and password redaction.

```sh
make test && make race
```

## License

GPL-3.0 — see [LICENSE](LICENSE). This requirement follows the primary RDP
dependency, [x90skysn3k/grdp](https://github.com/x90skysn3k/grdp) (GPL-3.0).
