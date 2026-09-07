# rdp-scan

**Lightweight RDP exposure scanner — CIDR → IPs → TCP/3389 connectivity → reachable hosts.**

A small, dependency-free Go CLI for **authorized corporate penetration-testing
engagements**. Give it IPv4 CIDR ranges (or single IPs, AS numbers, dash
ranges, wildcards — from files or the command line) and it expands them,
deduplicates them, checks **TCP port 3389** on every address with bounded
concurrency, and writes the reachable IPs to an output file.

```
$ ./rdp-scan ranges.txt -o rdp_live.txt -c 200 -t 2s
[*] Loading targets...
[*] Loading file: ranges.txt
[*] Expanding 11 range(s)...
[+] 8448 unique IPs
[*] Scanning TCP/3389 (200 concurrent, 2s timeout)...
Progress: 1234/8448 (14.6%)
[+] 1.0.1.14:3389 OPEN
[+] 1.0.1.72:3389 OPEN
[+] 1.0.2.91:3389 OPEN
...
[+] Scan complete
[*] 37 live | 8211 refused | 200 timeout | 0 other | elapsed 21.4s
[+] 37 RDP hosts found
[+] Results saved to: rdp_live.txt
```

`rdp_live.txt` contains only the hosts whose TCP handshake to 3389 succeeded:

```
1.0.1.14
1.0.1.72
1.0.2.91
```

---

## What it does — and does not do

| Does | Does not |
|------|----------|
| Expand CIDRs, IPs, ASNs, ranges, wildcards to individual IPv4s | Nmap, UDP, or any port other than TCP/3389 (unless you explicitly pass `--port`) |
| Deduplicate overlapping/duplicate ranges | ICMP/ping — TCP connectivity **is** the liveness test |
| Bounded-concurrency TCP connect checks | Banner grabs, RDP handshake, or any protocol exchange |
| Save reachable IPs (one per line) to an output file | Password attacks, brute force, credential spraying, authentication |
| Graceful handling of malformed input | Root privileges — everything runs as an unprivileged user |

**Detection method:** a host is considered *RDP live* exactly when a TCP
connection to port 3389 completes the three-way handshake
(`net.DialTimeout` in Go). The connection is closed immediately — no data is
sent, no banner is read, no credentials are ever exchanged. Unreachable
hosts (filtered/dropping packets) are bounded by the per-connection timeout
(`-t`) and classified separately from hosts that actively refuse the
connection.

> **Scope & authorization** — Use only on systems and networks you are
> authorized to test. Unauthorized port scanning may violate computer misuse
> laws and acceptable-use policies. You are responsible for compliance.

---

## Installation

Requires **Go 1.20+** (uses only the standard library — zero third-party
dependencies, no `go mod download` needed):

```bash
cd rdp-scan
go build -o rdp-scan ./cmd/rdp-scan
./rdp-scan --help
```

Optionally install to your PATH:

```bash
go install ./cmd/rdp-scan
```

No root privileges are required at build time or run time.

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

| Flag | Long alias | Default | Description |
|------|-----------|---------|-------------|
| `-o` | `--output` | `rdp_live.txt` | output file for reachable IPs (one per line) |
| `-c` | `--concurrency` | `500` | number of concurrent TCP connection attempts |
| `-t` | `--timeout` | `3s` | per-connection timeout (`2s`, `500ms`, …) |
| | `--port` | `3389` | TCP port to probe (RDP default) |
| | `--asn-file` | *(auto-detect)* | ASN-to-CIDR database (TSV), see below |
| | `--max-ips` | `33554432` | safety cap on expanded IPs (protects against `/0`, `/1`, …) |
| `-v` | `--version` | | print version and exit |
| `-h` | `--help` | | print help and exit |

Flags may appear **before or after** the inputs, so both of these work:

```bash
./rdp-scan -c 200 -t 2s ranges.txt
./rdp-scan ranges.txt -o rdp_live.txt -c 200 -t 2s
```

### Examples

```bash
# basic: one CIDR file, defaults
./rdp-scan ranges.txt

# tuned scan
./rdp-scan ranges.txt -o rdp_live.txt -c 200 -t 2s

# mixed inputs: CIDR + ASN + single IP
./rdp-scan 10.0.0.0/16 AS15169 10.9.9.9 -o live.txt --asn-file ip2asn-v4.tsv

# multiple files
./rdp-scan site-a.txt site-b.txt -o live.txt

# scan all of a /8 with high concurrency and a tight LAN timeout
./rdp-scan 10.0.0.0/8 -c 2000 -t 800ms
```

### Input file format

One target per line; `#` starts a comment (full-line or inline); blank lines
are ignored; whitespace-separated entries on one line are all accepted.
Malformed lines are **skipped with a warning** — a bad line never aborts the
scan.

```
# ranges.txt — example input
1.0.1.0/24
1.0.2.0/23
1.0.8.0/21
1.0.32.0/19

1.1.0.0/24
1.1.2.0/23
1.1.4.0/22
1.1.8.0/21
1.1.16.0/20

# duplicates and overlaps are fine — they are deduplicated:
1.0.1.0/24
1.0.2.0/23
```

---

## ASN support

Passing an AS number (`AS15169`, `ASN15169`, `as15169`, or bare `15169`) as
an input expands it to all CIDR ranges registered for that ASN. rdp-scan
does **not** query the network for this — it reads a local TSV database in
the common pyasn / iptoasn formats (column order is detected; header and
comment lines are ignored):

```
# pyasn ipasn.tsv style:
64512	10.0.0.0	10.0.0.255

# iptoasn ip2asn-v4.tsv style:
range_start	range_end	AS_number	country_code	AS_description
10.0.0.0	10.0.0.255	64512	ZZ	EXAMPLE-AS
```

Provide it with `--asn-file`, or via the `RDP_SCAN_ASN_FILE` environment
variable, or just place `ip2asn-v4.tsv` / `ipasn.tsv` / `ip2asn.tsv` in the
current directory — it is auto-detected. Free ASN→CIDR snapshots are
published by iptoasn.com and by the pyasn project.

```bash
./rdp-scan AS15169 --asn-file ip2asn-v4.tsv
./rdp-scan asn-list.txt -o live.txt          # file containing AS numbers
```

---

## Output

* Progress counter on stdout: `Progress: 1234/8448 (14.6%)`
  (updates in place on a terminal, periodic lines when piped).
* Live hosts as they are found: `[+] 1.0.1.14:3389 OPEN`.
* Summary: `live | refused | timeout | other` counts and elapsed time —
  `refused` = host answered RST, `timeout` = host dropped packets.
* Output file: bare IPs, one per line, sorted ascending, only for hosts
  whose TCP connection to the target port succeeded. The file is truncated
  if it exists; it is written even when zero hosts are found (empty file).

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | scan finished (finding zero hosts is still a successful scan) |
| `1`  | runtime error (unreadable input file, unwritable output path, ASN database missing, …) |
| `2`  | usage error (bad flags, no input, invalid concurrency/timeout/port) |
| `130`| interrupted with SIGINT/SIGTERM — partial results are still saved |

---

## Performance

* Expansion and deduplication work on packed `uint32` addresses with a
  hash-set + sort: a full `/8` (16.7 million IPs) expands and deduplicates
  in seconds using a few hundred MB of RAM.
* The scanner uses a fixed worker pool (`-c` goroutines) — no per-IP process
  spawning, no unbounded socket creation. Throughput for filtered ranges is
  roughly `concurrency / timeout` probes per second (e.g. `-c 2000 -t 2s`
  ≈ 1000/s); hosts that answer immediately (open or refused) process much
  faster.
* `--max-ips` guards against accidentally expanding huge ranges (`/0`, `/1`);
  raise it deliberately when you really do want hundreds of millions of IPs.
* No DNS is ever performed — only IP addresses are dialed.

## Error handling

* Malformed CIDRs/IPs/ranges in files → warning to stderr, line skipped,
  scan continues.
* Missing input file → clear error, exit 1.
* Invalid flags / values → usage message, exit 2.
* Unwritable output file → error, exit 1.
* SIGINT/SIGTERM mid-scan → in-flight attempts are aborted, hosts already
  confirmed live are still written, exit 130.

## Testing

Unit tests (expansion edge cases: `/32`, `/31`, `/30`, overlaps, comments,
ASN parsing, live/refused/cancel behavior) and a local integration test are
included:

```bash
cd rdp-scan
go test ./...
```

The tool was also verified end-to-end against real local TCP/3389 listeners
on `127.0.0.1` and `127.0.0.2` (no root needed — port 3389 > 1024): scanning
`127.0.0.0/24` plus malformed lines reported exactly those two hosts and the
output file contained only them:

```
$ ./rdp-scan local-test.txt -o local-live.txt -c 100 -t 2s
[*] Loading targets...
[*] Loading file: local-test.txt
[*] Expanding 2 range(s)...
[+] 260 unique IPs
[*] Scanning TCP/3389 (100 concurrent, 2s timeout)...
[+] 127.0.0.2:3389 OPEN
[+] 127.0.0.1:3389 OPEN
[+] Scan complete
[*] 2 live | 254 refused | 4 timeout | 0 other | elapsed 2s
[+] 2 RDP host(s) found
[+] Results saved to: local-live.txt

$ cat local-live.txt
127.0.0.1
127.0.0.2
```

## Project layout

```
rdp-scan/
├── cmd/rdp-scan/main.go    CLI: flags, progress, output, exit codes
├── internal/cidr/          target parsing + expansion/dedup (stdlib only)
├── internal/scan/          bounded-concurrency TCP connect scanner
├── examples/               sample input files
├── go.mod                  module github.com/salarrbl/Huntool-scr/rdp-scan (Go 1.20)
├── README.md
└── LICENSE
```

## License

MIT — see [LICENSE](LICENSE).
