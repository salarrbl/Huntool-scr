# 👻 Ghostcat Scanner — Go Version

**Apache Tomcat AJP Local File Inclusion / Remote Code Execution Detector**

Standalone Go tool for detecting CVE-2020-1938 (Ghostcat) vulnerability on Apache Tomcat servers via the AJP (Apache JServ Protocol) connector on port 8009.

## 📁 Project Structure

```
ghostcat-go/
├── cmd/
│   └── ghostcat/
│       └── main.go          # Main application code
├── go.mod                   # Go module file
└── (built binary will be ghostcat)
```

## 🚀 Building

### Prerequisites

- Go 1.21 or later

### Build Commands

```bash
# Using the build script
./build.sh

# Or manually
cd ghostcat-go
go mod tidy
go build -o ghostcat ./cmd/ghostcat
```

## 📋 Usage

```bash
# Basic scan
./ghostcat targets.txt

# Custom port, workers, timeout
./ghostcat targets.txt -p 8009 -w 20 -t 10

# Save all results to file
./ghostcat targets.txt -o results.txt

# Save ONLY vulnerable targets to text file
./ghostcat targets.txt -f vulns.txt

# Save vulnerable targets as JSON
./ghostcat targets.txt -j vulns.json

# Save all results as CSV
./ghostcat targets.txt --csv results.csv

# Verbose mode (show response body)
./ghostcat targets.txt -v

# Combine multiple outputs
./ghostcat targets.txt -f vulns.txt -j vulns.json -o results.txt --csv results.csv
```

## 💾 Saving Vulnerable Targets

At the end of each scan, the tool displays:

```
  📁 Vulnerable Targets Found: 3
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Target                           Status
  ⚠ 192.168.1.100:8009            VULNERABLE (AJP 8009, 1247 bytes)
  ⚠ 10.0.0.50:8009                VULNERABLE (AJP 8009, 2048 bytes)
  ⚠ tomcat.example.com:8009       VULNERABLE (AJP 8009, 1536 bytes)
```

### Output Formats

#### Text File (`-f` / `--vuln-file`)
```
# Ghostcat Vulnerable Targets Report
# CVE-2020-1938
# Generated: 2026-09-06 10:07:23
# Total Vulnerable: 3
#============================================================

1. 192.168.1.100:8009
   File: /WEB-INF/web.xml
   Response Size: 1247 bytes
   Response Time: 45ms
   Found At: 2026-09-06T10:07:23Z
--------------------------------------------------

============================================================
SUMMARY: 3 vulnerable target(s) found
```

#### JSON File (`-j` / `--json`)
```json
{
  "scan_info": {
    "vulnerability": "CVE-2020-1938",
    "name": "Ghostcat - Apache Tomcat AJP File Read/Inclusion",
    "cvss_score": 9.8,
    "generated_at": "2026-09-06T10:07:23Z"
  },
  "summary": {
    "total_vulnerable": 3
  },
  "targets": [
    {
      "host": "192.168.1.100",
      "port": 8009,
      "filepath": "/WEB-INF/web.xml",
      "body_length": 1247,
      "response_time_ms": 45,
      "found_at": "2026-09-06T10:07:23Z"
    }
  ]
}
```

#### CSV (`--csv`)
```csv
host,port,status,status_code,body_length,response_time_ms,error
192.168.1.100,8009,VULNERABLE,200,1247,45,
10.0.0.50,8009,OPEN_SAFE,403,0,12,
```

## 🔍 How It Works

1. **TCP Probe** — Checks if port 8009 is open
2. **AJP Exploit Packet** — Sends crafted AJP Forward Request with:
   - `javax.servlet.include.request_uri = "/"`
   - `javax.servlet.include.path_info = "/WEB-INF/web.xml"`
   - `javax.servlet.include.servlet_path = "/"`
3. **Response Analysis** — If Tomcat returns 200 OK with file content → VULNERABLE

## 📄 License & Disclaimer

This tool is for **authorized security testing only**. Unauthorized access to computer systems is illegal.

See main repository README for full documentation.
