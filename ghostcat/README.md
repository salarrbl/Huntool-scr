# 👻 Ghostcat Scanner — CVE-2020-1938

**Apache Tomcat AJP Local File Inclusion / Remote Code Execution Detector**

Standalone Go tool for detecting CVE-2020-1938 (Ghostcat) vulnerability on Apache Tomcat servers via the AJP (Apache JServ Protocol) connector on port 8009.

## How It Works

1. **TCP Probe** — Checks if port 8009 is open on the target
2. **AJP Exploit Packet** — Sends a crafted AJP Forward Request with three `javax.servlet.include.*` attributes:
   - `javax.servlet.include.request_uri` = `/`
   - `javax.servlet.include.path_info` = `/WEB-INF/web.xml`
   - `javax.servlet.include.servlet_path` = `/`
3. **Response Analysis** — If Tomcat returns a `200 OK` with file content (XML from web.xml), the target is **vulnerable**
4. **Concurrent scanning** — Worker pool scans multiple targets in parallel

## Build

```bash
cd ghostcat
go build -o ghostcat .
```

## Usage

```bash
# Basic scan
./ghostcat targets.txt

# Custom port, 20 workers, 10s timeout
./ghostcat targets.txt -p 8009 -w 20 -t 10

# Save results to file
./ghostcat targets.txt -o results.txt

# Verbose mode (show response body)
./ghostcat targets.txt -v

# Single target (echo into file)
echo "192.168.1.10" > targets.txt
./ghostcat targets.txt
```

## Targets File Format

One host per line (IP or hostname). Lines starting with `#` are ignored.

```
192.168.1.10
192.168.1.20
tomcat.example.com
10.0.0.0/24    # not supported — use naabu to expand first
```

## Options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--port` | `-p` | AJP port to scan | 8009 |
| `--timeout` | `-t` | Connection timeout (seconds) | 5 |
| `--workers` | `-w` | Concurrent scan workers | 10 |
| `--output` | `-o` | Save results to file | — |
| `--verbose` | `-v` | Show response body content | false |
| `--help` | `-h` | Show usage | — |

## Output

```
  📋 Loaded 3 target(s) from targets.txt
  🎯 Port: 8009  ⏱ Timeout: 5s  ⚡ Workers: 10

  ────────────────────────────────────────────────────────
  ⚠ VULNERABLE        192.168.1.10:8009  Tomcat AJP 8009 OPEN
    ├── Status:  200 OK
    ├── Server:  Apache-Coyote/1.1
    ├── Body:    1247 bytes
    └── Took:    45ms
  ● 192.168.1.20:8009           Port open, not vulnerable  (403, 52ms)
  ✗ 192.168.1.30:8009           port closed or host unreachable  (5s)

  ────────────────────────────────────────────────────────
  📊 Scan Summary:
    🔴 Vulnerable:      1
    🟢 Open (safe):     1
    ⚫ Closed/Filtered: 1
```

## Detection Logic

| Response | Verdict |
|----------|---------|
| TCP connect fails | Port closed / Host unreachable |
| AJP response with `200 OK` + body containing XML/web-app tags | **VULNERABLE** |
| AJP response with `200 OK` + non-empty body | **VULNERABLE** (likely) |
| AJP response with `403`/`404`/other | Open but not vulnerable (patched or restricted) |
| No AJP response | Not an AJP service |

## CVE Details

| Field | Value |
|-------|-------|
| CVE | CVE-2020-1938 |
| CNVD | CNVD-2020-10487 |
| CVSS | 9.8 (Critical) |
| Affected | Tomcat 7.0.0–7.0.99, 8.5.0–8.5.50, 9.0.0.M1–9.0.30 |
| Fixed | 7.0.100, 8.5.51, 9.0.31 |
| Protocol | AJP 1.3 (port 8009) |

## Mitigation

1. **Disable AJP** — Comment out the `<Connector port="8009" .../>` in `conf/server.xml`
2. **Set a secret** — Add `secret="YOUR_SECRET"` to the AJP connector
3. **Upgrade** — Tomcat 7.0.100, 8.5.51, or 9.0.31+
4. **Firewall** — Block port 8009 from untrusted networks

## Disclaimer

This tool is for **authorized security testing only**. Unauthorized access to computer systems is illegal. Always obtain proper authorization before scanning.
