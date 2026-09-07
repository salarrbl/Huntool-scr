# rdp-scan

**Lightweight RDP exposure scanner — CIDR → IPs → *is RDP actually running?* → reachable hosts.**

A small, dependency-free Go CLI for **authorized corporate penetration-testing
engagements**. Give it IPv4 CIDR ranges (or single IPs, AS numbers, dash
ranges, wildcards — from files or the command line) and it expands and
deduplicates them, then probes every address: a TCP connect and — by default —
the **X.224 RDP negotiation request** every RDP client sends. A host is only
reported when the RDP service itself answers, so "port 3389 happens to be
open" and "RDP is live here" stop being the same finding.

```
$ ./rdp-scan ranges.txt --eco
[*] Loading targets...
[*] Loading file: ranges.txt
[+] 8,448 unique IPs in 11 range(s) after deduplication
[*] streaming 8,448 addresses in 17 chunks of 512 — memory stays flat at any range size
[*] Scanning TCP/3389 — RDP service verification (64 concurrent, 2s timeout, 120/s max)
[+] 1.0.1.14:3389 RDP UP — NLA (CredSSP)
[!] 1.0.1.72:3389 open but NOT RDP — not RDP — answered: "HTTP/1.1 404 Not Found"
[+] 1.0.2.91:3389 RDP UP — TLS
[!] Scan interrupted — everything found so far is already on disk
[*] 8,448/8,448 probed | 8,211 refused | 0 timeout | 0 other | 395 ip/s | elapsed 21.4s
[*] 37 host(s) answered on TCP/3389: 28 run RDP, 0 silent, 9 run another service
[*] verdicts: rdp(nla)×21, rdp(tls)×6, not-rdp×9
[+] Results saved to: rdp_live.txt (28 hosts)
```

`rdp_live.txt` contains the verified hosts, one bare IP per line, ascending:

```
1.0.1.14
1.0.2.91
```

---

## What it does — and does not do

| Does | Does not |
|------|----------|
| Expand CIDRs, IPs, ASNs, ranges, wildcards to individual IPv4s | Nmap, UDP, or any port other than the one you pass (default TCP/3389) |
| Deduplicate overlapping/duplicate ranges **as ranges**, so memory stays flat | A materialised list of IPs — a `/8` is streamed, never expanded into RAM |
| TCP connect check, then the RDP negotiation request (MS-RDPBCGR) to confirm an RDP service answers | Authentication of any kind: no credentials, no cookie, no login attempt |
| Report which security layer the server selected (NLA/CredSSP, TLS, legacy) and negotiation failures | Exploits, scanners, brute force, MITM, session establishment |
| Write hits as they are found, flushed per chunk, so Ctrl-C keeps the results | Root privileges — everything runs as an unprivileged user |
| Pace itself for a laptop (`--eco`, `--rate`, `--chunk-delay`, `--nice`, `--max-cpu`) | DNS: no reverse lookups, no hostname resolution, only IPs are dialed |

**Detection method.** For each address, `net.Dialer` connects to the port; on a
successful handshake the tool writes the 19-byte RDP client
negotiation PDU (`TPKT + X.224 CR + RDP_NEG_REQ`,
`requestedProtocols = SSL|HYBRID`, the
same offer an NLA-enabled `mstsc`/FreeRDP makes) and classifies the reply:

| Reply | Verdict |
|-------|---------|
| `RDP_NEG_RSP` with a selected protocol | `rdp` — `RDP UP — NLA (CredSSP)` / `TLS` / `NLA with early user info` / `Remote Credential Guard`, plus restricted-admin or redirected-auth flags |
| `RDP_NEG_FAILURE` | `rdp` — the RDP service answered and refused *our* offer (e.g. "NLA (HYBRID) required by server"): still a live RDP host |
| X.224 DISCONNECT / REJECT | `rdp` — pre-connection RDP is speaking, it just did not like the request |
| TPKT-framed answer with no negotiation structure | `rdp` — a server without protocol negotiation (legacy RDP security) |
| Anything else (HTTP, SSH, MQTT, an immediate close) | `not-rdp` — quoted first line of the foreign banner when there is one |
| Connected, wrote the request, no answer in time | `open` — listed only with `--include-open` or `--report` |

> **The honest caveats.** A host with RDP behind a TLS-only gateway, or an RDP
> listener that only talks after a full TLS handshake, can answer `open` rather
> than `rdp`; a port forwarded by a proxy may answer `not-rdp`. Use `--report`
> to keep every answered host with its verdict and decide for yourself, and
> `--check port` when you want the cheap, exhaustive, "3389 is open" answer.

> **Scope & authorization** — Use only on systems and networks you are
> authorized to test. Unauthorized port scanning may violate computer misuse
> laws and acceptable-use policies. You are responsible for compliance.

---

## Installation

Requires **Go 1.20+** and nothing else (standard library only — no
`go mod download`, no CGO, no root):

```bash
cd rdp-scan
go build -o rdp-scan ./cmd/rdp-scan
./rdp-scan --help
```

```bash
go install ./cmd/rdp-scan
```

---

## Usage

```
rdp-scan [flags] <input> [input ...]
```

### Inputs (one or more, in any mix)

| Form | Example | Expands to |
|------|---------|-----------|
| file | `ranges.txt` | every entry in the file (see file format below) |
| CIDR | `10.0.0.0/24` | 256 IPs (non-canonical bases like `10.0.0.77/30` are normalized) |
| single IP | `10.0.0.5` | 1 IP |
| AS number | `AS15169` / `ASN15169` / `15169` | all ranges for that ASN (needs an ASN database) |
| dash range | `10.0.0.1-10.0.0.9` | 9 IPs (inclusive) |
| wildcard | `10.0.*.*` | a /16 (`10.0.0.*` = /24) |

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--check` | `rdp` | `rdp` = an RDP service must answer; `port` = TCP handshake is enough (`tcp`/`connect`/`open` are accepted for `port`, `service`/`verify` for `rdp`) |
| `-o`, `--output` | `rdp_live.txt` | hit list, one IP per line, ascending |
| `--report` | *(off)* | also write a TSV with one line per **answered** host, non-RDP included: `# ip port state rtt detail` |
| `--include-open` | off | with `--check rdp`, also list hosts that completed TCP but gave no RDP evidence |
| `-c`, `--concurrency` | `0` = auto | concurrent probes; auto = `128 × NumCPU`, clamped to 128–1024 and to the descriptor budget |
| `-t`, `--timeout` | `3s` | per-connection TCP timeout |
| `--rdp-timeout` | `--timeout` | how long to wait for the RDP negotiation answer |
| `--port` | `3389` | TCP port to probe |
| `--rate` | `0` = off | probe cap per second (token bucket: ¼ s of burst, capped at 512) |
| `--chunk` | `4096` | addresses per chunk: bounds memory *and* sets how often results are flushed (16 … 2²⁰) |
| `--chunk-delay` | `0` | pause after each drained chunk, e.g. `200ms` |
| `--nice` | `0` | scheduling priority penalty 0–19 (Unix; `setpriority`, never raises priority) |
| `--max-cpu` | `0` = all | cap `GOMAXPROCS` |
| `--eco` | off | laptop profile — see below |
| `--max-live` | `0` = all | stop as soon as N live hosts were found |
| `--shard` | *(off)* | `k/n`: scan only every n-th address, offset `k` |
| `--exclude` | *(off)* | ranges to drop, e.g. `"10.0.0.0/8,192.168.0.0/16"` |
| `--asn-file` | *(auto-detect)* | ASN-to-CIDR database (TSV) |
| `--max-ips` | `67108864` | safety cap on the *scope* (not memory): protects against `/0`, `/1`, … |
| `--dry-run` | off | parse, deduplicate, print the plan, send nothing |
| `-q`, `--quiet` | off | no progress or informational output (findings and errors only) |
| `-v`, `--version` | | print version and exit |
| `-h`, `--help` | | print help and exit |

Long aliases: `--output`, `--concurrency`, `--timeout`, `--quiet`,
`--version`. Flags may appear **before or after** the inputs, `--flag=value`
and `-c64` both work, and `--` forces everything after it to be treated as an
input (useful for a file name that starts with `-`).

---

## Big ranges on a small machine

Scanning is **streaming end to end**. Addresses are never materialised into a
list: the merged span set is walked in `--chunk` batches, one batch is being
dispatched while the previous one drains, and results are written and flushed
at every chunk boundary. A `/8` therefore costs the same memory as a `/24`
(one chunk of addresses plus one chunk of results), and an interrupt loses at
most the chunk in flight:

```bash
./rdp-scan 10.0.0.0/8 --dry-run        # what would this cost? (sends nothing)
./rdp-scan 10.0.0.0/8 --chunk 8192 --rate 400 --chunk-delay 200ms
```

`--dry-run` prints the number of addresses, the chunk count and a worst-case
ETA without sending a single packet, which is the cheap way to check a target
list before committing to it.

### `--eco`: the laptop profile

```bash
./rdp-scan ranges.txt --eco
```

is exactly `--rate 120 --chunk 512 --chunk-delay 200ms --nice 10 -t 2s -c 64`,
and every value you set explicitly wins over it. The point is that the scan
stays in the background of a working machine: few sockets, a probe cap that
keeps a Wi-Fi NIC and its NAT table from saturating, a pause between batches so
the fan never spins up, and a scheduling penalty so your editor keeps the CPU.

Two more things run on a laptop regardless of `--eco`:

* **Descriptor budget.** The worker count is clamped to 80 % of the process's
  `RLIMIT_NOFILE` minus a margin, so a stock macOS shell (`ulimit -n 256`,
  hard limit 256 — note that Go already raises the soft limit to the hard one
  at startup) produces a slower scan instead of a wall of `EMFILE` errors. If
  the clamp bites, the tool says so and tells you to raise `ulimit -n` for
  faster scans. Attempts that hit the limit anyway are retried once after a
  short pause and counted as `retried after the descriptor limit` in the
  summary.
* **Niceness.** `--nice`/`--eco` only ever *lowers* priority (`Setpriority`,
  PRIO_PROCESS) and never tries to raise it, so it works unprivileged and fails
  silently-safely where it cannot.

### `--shard`: split one huge range across machines

```bash
./rdp-scan 10.0.0.0/8 --shard 0/2 -o part0.txt & ./rdp-scan 10.0.0.0/8 --shard 1/2 -o part1.txt &
wait; sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n part0.txt part1.txt > live.txt
```

Sharding is **positional**: after deduplication, shard `k` of `n` takes the
`k`-th, `(k+n)`-th, `(k+2n)`-th … address of the ordered target list. That is
what makes the shards an exact partition — every address appears in exactly
one shard, no shard gets more work than another — even when the input is a
patchwork of a thousand unrelated ranges. `--shard 0/1` (or omitting it) is the
inert case, `k >= n` is a usage error, and an empty shard is reported as such
instead of running a zero-address scan.

---

## ASN support

Passing an AS number (`AS15169`, `ASN15169`, `as15169`, or bare `15169`) as an
input expands it to all CIDR ranges registered for that ASN. rdp-scan does
**not** query the network for this — it reads a local TSV database in the
common pyasn / iptoasn formats (column order is detected; header and comment
lines are ignored):

```
# pyasn ipasn.tsv style:
64512	10.0.0.0	10.0.0.255

# iptoasn ip2asn-v4.tsv style:
range_start	range_end	AS_number	country_code	AS_description
10.0.0.0	10.0.0.255	64512	ZZ	EXAMPLE-AS
```

Provide it with `--asn-file`, or via the `RDP_SCAN_ASN_FILE` environment
variable, or just place `ip2asn-v4.tsv` / `ipasn.tsv` / `ip2asn.tsv` in the
current directory — it is auto-detected. Free ASN→CIDR snapshots are published
by iptoasn.com and by the pyasn project.

```bash
./rdp-scan AS15169 --asn-file ip2asn-v4.tsv
./rdp-scan asn-list.txt -o live.txt          # file containing AS numbers
```

---

## Output

* Progress on stdout: `Progress: 1,234/8,448 (14.6%) | 395 ip/s | eta 18s`,
  updated in place on a terminal (throttled to 4 Hz and re-rendered at every
  chunk boundary), one line per update when piped.
* Findings as they are confirmed: `[+] ip:port RDP UP — …`,
  `[!] ip:port open but NOT RDP — …`, `[!] ip:port open, no RDP answer — …`.
* Summary: probed/refused/timeout/other plus, in `--check rdp` mode, how many
  answered hosts run RDP, are silent, or run another service, and a tally of
  verdicts (`rdp(nla)×21, rdp(tls)×6, not-rdp×9`).
* `-o` file: bare IPs, one per line, ascending. In `--check rdp` mode that
  means RDP-verified hosts only (plus `open` hosts with `--include-open`); in
  `--check port` mode every host that completed the handshake. Truncated if it
  exists; written (empty) even when nothing is found; flushed per chunk.
* `--report` file: TSV, one line per **answered** host — RDP, non-RDP and
  silent alike — with the port, verdict, RTT and the detail string. This is the
  file to grep when you want "everything that responded on 3389" rather than
  "everything that is RDP".

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | scan finished (finding zero hosts is still a successful scan) |
| `1`  | runtime error (unreadable input file, unwritable output path, ASN database missing, …) |
| `2`  | usage error (bad flags, no input, invalid concurrency/timeout/port/shard) |
| `130`| interrupted with SIGINT/SIGTERM — everything found up to the last chunk is already on disk |

---

## Performance

* Targets are held as merged `uint32` spans, not expanded: deduplication of a
  few thousand ranges is `O(ranges log ranges)` and the scan itself is `O(1)`
  memory per chunk. The old "expand a /8 into a slice first" behaviour — a few
  hundred MB of RAM for 16.7 M addresses — is gone.
* Fixed worker pool (`-c` goroutines), one `net.Dialer` per attempt, no
  per-IP process spawning, no unbounded socket creation. Throughput for
  filtered ranges is roughly `concurrency / timeout` probes per second
  (`-c 1024 -t 2s` ≈ 500/s); hosts that answer immediately — open or refused —
  process far faster, and `--rate` caps it from above when you want that.
* `--chunk` also bounds the *result* backlog: nothing is accumulated across
  chunk boundaries beyond what the sink has already been handed.
* `--max-ips` is a scope guard, not a memory guard now; raise it deliberately
  when you really do want to sweep hundreds of millions of addresses.
* No DNS is ever performed — only IP addresses are dialed.

## Error handling

* Malformed CIDRs/IPs/ranges in files → warning to stderr, line skipped, scan
  continues.
* Missing input file → clear error, exit 1. A file with no valid target in it
  is an error too, not a silent zero-IP scan.
* Invalid flags / values → usage message, exit 2.
* Unwritable output file → error, exit 1; write errors mid-scan are reported
  once, not spammed per host.
* `--exclude` that swallows the entire target list is an error, and the number
  of removed addresses is reported when it does not.
* SIGINT/SIGTERM mid-scan → feeding stops, the in-flight chunk is drained and
  published, then exit 130 with the partial results on disk.

## Testing

```bash
cd rdp-scan
go test ./...
```

The suite is self-contained: no root, no network, no external scanners. What it
covers, beyond parsing/expansion cases (`/32`, `/31`, non-canonical bases,
overlaps, comments, ASN parsing):

* `internal/cidr` — span merging (including touching ranges fusing), span
  arithmetic and overflow at the top of the address space, `--exclude`
  subtraction, `IterateSpans` agreeing with `Expand`, positional sharding
  (the shards tile the list exactly and `ShardCount` matches what is yielded),
  chunk counting.
* `internal/rdp` — the exact 19-byte client PDU (TPKT length and X.224 length
  indicator checked against each other), a 20-case classification table
  (length-indicator 0x0e *and* 0x06, `X.224 DATA` vs `CC`, negotiation failure
  codes, disconnect/reject, foreign banners), a 20 000-case fuzz run asserting
  the classifier never invents RDP out of noise, and `Probe` against four fake
  hosts over real loopback TCP (RDP, HTTP, silent, hangup).
* `internal/scan` — streaming vs materialised paths producing identical
  results, `OnFlush` firing on every chunk boundary (including chunks with no
  hits), `--chunk-delay` pacing, the limiter, `--max-live`, cancellation
  reaching the first chunk of a `/8` in milliseconds with `Skipped` accounted,
  the descriptor clamp, and a scan against two loopback hosts on the same port
  where one runs RDP and one runs HTTP — asserting `rdp=1, not-rdp=1,
  refused=1` and ascending output.
* `cmd/rdp-scan` — flag reordering (never losing an argument), long aliases,
  `--eco` only replacing values you did not type, every validation path, the
  exit-code table (`0`/`1`/`2`, dry-run creating no file), sink inclusion rules
  per mode, and the verdict bucketing.

## Project layout

```
rdp-scan/
├── cmd/rdp-scan/
│   ├── main.go             CLI: flags, plan, progress, sink, exit codes
│   ├── nice_unix.go        --nice via Setpriority (PRIO_PROCESS = 0)
│   └── nice_other.go       same signature where there is no nice(2)
├── internal/cidr/
│   ├── cidr.go             target parsing (files, CIDR, IP, ranges, wildcards, ASNs)
│   └── spans.go            span algebra: merge, count, subtract, shard, iterate
├── internal/rdp/rdp.go     X.224/TPKT negotiation request + response classifier
├── internal/scan/
│   ├── scan.go             streaming chunked pipeline (Source, workers, publish)
│   ├── ratelimit.go        token bucket for --rate
│   ├── rlimit_unix.go      descriptor budget from RLIMIT_NOFILE
│   └── rlimit_other.go     "no clamp" where there is no RLIMIT_NOFILE
├── examples/               sample input files
├── go.mod                  module github.com/salarrbl/Huntool-scr/rdp-scan (Go 1.20)
├── README.md
└── LICENSE
```

`internal/rdp` deliberately has no `net.Dial` in it: `Probe` takes an
already-connected `net.Conn`, which is what makes the protocol logic testable
against a fake host on loopback.

## License

MIT — see [LICENSE](LICENSE).
