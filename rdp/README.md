# RDP Exposure Scanner

Lightweight CLI tool for authorized corporate penetration testing. Discovers live RDP (TCP/3389) hosts from CIDR ranges.

## Features

- CIDR range expansion with deduplication and overlap handling
- TCP/3389 connectivity testing (no nmap, no UDP, no brute force)
- Bounded concurrency with configurable worker pool
- Configurable TCP timeout
- Progress tracking
- Graceful handling of malformed input
- Single binary, zero external dependencies

## Installation

```bash
go build -o rdp-scan main.go
```

Or with Go modules:

```bash
go mod init rdp-scan
go mod tidy
go build -o rdp-scan .
```

## Usage

```bash
./rdp-scan <input> [options]
```

### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `<input>` | Path to file containing CIDR ranges | Required |
| `-o, --output` | Output file for found hosts | `rdp_live.txt` |
| `-c, --concurrency` | Number of concurrent TCP checks | `100` |
| `-t, --timeout` | TCP connection timeout (e.g., `500ms`, `2s`) | `2s` |
| `--max-cidr` | Skip CIDRs smaller than this prefix (e.g., `20` skips /20 and larger networks) | `0` (no skip) |

### Input File Format

One CIDR per line:

```text
1.0.1.0/24
1.0.2.0/23
# This is a comment
1.0.8.0/21

1.0.32.0/19
```

Blank lines and lines starting with `#` are ignored. Malformed entries are skipped with a warning.

## Examples

### Basic scan

```bash
./rdp-scan ranges.txt
```

### With custom output and concurrency

```bash
./rdp-scan ranges.txt -o results.txt -c 200
```

### Quick scan with lower concurrency

```bash
./rdp-scan ranges.txt -c 50 -t 1s
```

### Skip large ranges (only scan /24 and smaller)

```bash
./rdp-scan ranges.txt --max-cidr 24
```

### Large-scale scan with conservative resources

```bash
./rdp-scan cn-i-ranges.txt -c 100 -t 2s --max-cidr 20
```

## Concurrency Guidelines

Choose concurrency based on your available resources:

| CPU Cores | Suggested Concurrency | Notes |
|-----------|----------------------|-------|
| 2 | 50-100 | Low impact |
| 4 | 100-200 | Balanced |
| 8 | 200-500 | Aggressive |
| 16+ | 500-1000 | Maximum throughput |

**Start conservative.** If you see high CPU/memory usage, reduce `--concurrency`. A good rule of thumb: start with `concurrency = cores * 25` and adjust up or down based on system response.

## Performance Tips

1. **Use `--max-cidr`** to skip large ranges that would take too long. For example, `--max-cidr 20` skips /20, /19, /16, etc.
2. **Lower concurrency** on slower networks or shared machines.
3. **Shorter timeout** (`-t 500ms`) for faster scans when you expect most hosts to be unreachable.
4. **Longer timeout** (`-t 5s`) for networks with higher latency.

## Output

Found hosts are printed to stdout as they're discovered:

```text
[+] 1.0.1.14:3389 OPEN
[+] 1.0.1.72:3389 OPEN
```

Results are saved to the output file:

```text
1.0.1.14
1.0.1.72
```

## How It Works

1. **Parse** CIDR ranges from input file (skipping comments, blanks, malformed entries)
2. **Expand** ranges to individual IPs, deduplicating across overlapping ranges
3. **Skip** ranges larger than `--max-cidr` prefix (to prevent memory/CPU overload)
4. **Scan** each IP with a TCP connect to port 3389 using configurable timeout
5. **Report** only IPs where the TCP connection succeeds (no false positives from ICMP or port probing)
6. **Save** results to output file

## Error Handling

- Malformed CIDRs are logged and skipped
- Overlapping CIDRs are deduplicated
- Large CIDRs (configurable via `--max-cidr`) are skipped with a warning
- Connection timeouts don't hang the scan
- Refused connections are treated as closed (not errors)

## Limitations

- IPv4 only
- TCP/3389 only (no other ports)
- No authentication or credential testing
- No service enumeration beyond connectivity

## License

GPL-3.0

## Author

For authorized penetration testing use only. Ensure you have explicit written permission before scanning any networks.
