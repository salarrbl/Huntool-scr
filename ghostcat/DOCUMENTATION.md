# Ghostcat Scanner — How to Save Vulnerable Targets

This tool can save vulnerable targets in multiple formats:

## Text File (with -f / --vuln-file)

Save only vulnerable targets to a text file:

```bash
python3 ghostcat.py targets.txt -f vulnerable-targets.txt
```

Output file format:
```
# Ghostcat Vulnerable Targets Report
# CVE-2020-1938
# Generated: 2024-01-15 14:30:00
# Total Vulnerable: 3
#==========================================================================

1. 192.168.1.100:8009
   File: /WEB-INF/web.xml
   Response Size: 1247 bytes
   Response Time: 45ms
   Found At: 2024-01-15T14:30:05.123456
------------------
2. 10.0.0.50:8009
   ...

==========================================================================
SUMMARY: 3 vulnerable target(s) found
```

## JSON File (with -j / --json)

Save vulnerable targets as structured JSON:

```bash
python3 ghostcat.py targets.txt -j vulns.json
```

Output JSON:
```json
{
  "scan_info": {
    "vulnerability": "CVE-2020-1938",
    "name": "Ghostcat - Apache Tomcat AJP File Read/Inclusion",
    "cvss_score": 9.8,
    "generated_at": "2024-01-15T14:30:05.123456"
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
      "found_at": "2024-01-15T14:30:05.123456"
    }
  ]
}
```

## All Results (with -o / --output)

Save ALL scan results (not just vulnerable):

```bash
python3 ghostcat.py targets.txt -o all-results.txt
```

## CSV Format (with --csv)

Save all results as CSV for spreadsheet import:

```bash
python3 ghostcat.py targets.txt --csv results.csv
```

## Combined Usage

Save vulnerable targets in multiple formats:

```bash
python3 ghostcat.py targets.txt \
  -f vulns.txt \
  -j vulns.json \
  -o all-results.txt \
  --csv results.csv
```

## End of Scan Summary

At the end of each scan, the tool displays:

```
  ────────────────────────────────────────────────────────
  📊 Scan Summary:
    🔴 Vulnerable:      3
    🟢 Open (safe):     5
    ⚫ Closed/Filtered: 2

  📁 Vulnerable Targets Found: 3
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Target                            Status
  ⚠ 192.168.1.100:8009             VULNERABLE (AJP 8009, 1247 bytes)
  ⚠ 10.0.0.50:8009                 VULNERABLE (AJP 8009, 2048 bytes)
  ⚠ tomcat.example.com:8009        VULNERABLE (AJP 8009, 1536 bytes)
```
