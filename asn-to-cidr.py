#!/usr/bin/env python3
import subprocess
import re
import ipaddress
import json
import sys

# optional: use bgpview API as a second source if requests is installed
try:
    import requests
    HAVE_REQUESTS = True
except Exception:
    HAVE_REQUESTS = False

WHOIS_HOST = "whois.radb.net"  # قابل تغییر به whois.cymru.com یا غیره

ipv4_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b')
ipv6_re = re.compile(r'\b[0-9a-fA-F:]+/\d{1,3}\b')

def query_whois_radb(asn, timeout=15):
    """Query RADb for routes originating from AS<asn>"""
    query = f"-i origin AS{asn}"
    try:
        result = subprocess.run(
            ['whois', '-h', WHOIS_HOST, '--', query],
            capture_output=True, text=True, timeout=timeout
        )
    except FileNotFoundError:
        raise FileNotFoundError("whois command not found. Install it (e.g. apt install whois).")
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"whois query timed out for AS{asn}")

    if result.returncode != 0:
        # Some whois servers still return 0 even if empty; handle stderr too
        stderr = result.stderr.strip()
        if stderr:
            raise RuntimeError(f"whois error: {stderr}")
    return result.stdout or ""

def extract_cidrs_from_text(text):
    found = set()
    for m in ipv4_re.findall(text):
        try:
            net = ipaddress.ip_network(m, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                found.add(str(net))
        except ValueError:
            pass
    for m in ipv6_re.findall(text):
        try:
            net = ipaddress.ip_network(m, strict=False)
            if isinstance(net, ipaddress.IPv6Network):
                found.add(str(net))
        except ValueError:
            pass
    return found

def query_bgpview(asn):
    """Optional: query bgpview.io API for prefixes (requires requests)"""
    if not HAVE_REQUESTS:
        return set()
    url = f"https://api.bgpview.io/asn/{asn}/prefixes"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return set()
        j = r.json()
        prefixes = set()
        for p in j.get("data", {}).get("ipv4_prefixes", []):
            prefixes.add(p.get("prefix"))
        for p in j.get("data", {}).get("ipv6_prefixes", []):
            prefixes.add(p.get("prefix"))
        return set([str(ipaddress.ip_network(x)) for x in prefixes if x])
    except Exception:
        return set()

def get_cidrs_from_asn(asn):
    nets = set()
    # 1) whois RADb
    try:
        out = query_whois_radb(asn)
        nets.update(extract_cidrs_from_text(out))
    except Exception as e:
        print(f"[!] whois error for AS{asn}: {e}", file=sys.stderr)

    # 2) optional: bgpview API (as cross-check)
    if HAVE_REQUESTS:
        try:
            nets.update(query_bgpview(asn))
        except Exception:
            pass

    return sorted(nets)

def normalize_as_line(line):
    s = line.strip()
    if not s:
        return None
    if s.upper().startswith("AS"):
        s = s[2:]
    # try int conversion to remove leading zeros etc
    try:
        s_int = int(s)
        if s_int <= 0:
            return None
        return str(s_int)
    except Exception:
        return None

def main():
    input_file = './all-asn'
    output_file = 'cidrs_output.txt'

    try:
        with open(input_file, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[!] Input file '{input_file}' not found.")
        return

    asns = []
    for l in lines:
        n = normalize_as_line(l)
        if n:
            asns.append(n)

    if not asns:
        print("[!] No valid ASNs found.")
        return

    print(f"[+] Querying {len(asns)} ASNs...")
    all_nets = set()
    for a in asns:
        print(f"[+] AS{a} ...")
        nets = get_cidrs_from_asn(a)
        print(f"    -> {len(nets)} prefixes found.")
        all_nets.update(nets)

    with open(output_file, 'w') as f:
        for n in sorted(all_nets, key=lambda x: (ipaddress.ip_network(x).version, ipaddress.ip_network(x))):
            f.write(n + "\n")

    print(f"[+] Done. {len(all_nets)} unique prefixes saved to {output_file}.")

if __name__ == "__main__":
    main()

