#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import mmh3
import requests
import codecs
import sys
import urllib.parse

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def get_favicon_hash(url):
    """Fetch favicon from URL and return its mmh3 hash."""
    try:
        # Ensure the URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        print(f"[+] Fetching favicon from: {url}")
        response = requests.get(url, verify=False, timeout=10)

        if response.status_code != 200:
            raise Exception(f"HTTP {response.status_code}")

        favicon_content = response.content
        favicon_base64 = codecs.encode(favicon_content, "base64")
        favicon_hash = mmh3.hash(favicon_base64)

        print(f"[✓] Favicon fetched successfully.")
        print(f"[!] http.favicon.hash: {favicon_hash}")
        print(f"[*] View Results on Shodan:")
        print(f"    https://www.shodan.io/search?query=http.favicon.hash%3A{favicon_hash}")

        return favicon_hash

    except requests.exceptions.RequestException as e:
        print(f"[✗] Network error: {e}")
        return None
    except Exception as e:
        print(f"[✗] Error: {e}")
        return None

def auto_try_https(url):
    """If HTTP fails, try HTTPS."""
    if url.startswith('http://'):
        https_url = url.replace('http://', 'https://', 1)
        print(f"[i] Trying HTTPS version: {https_url}")
        return get_favicon_hash(https_url)
    return None

def main():
    if len(sys.argv) != 2:
        print("[!] Error: Missing target URL.")
        print(f"[-] Usage: python3 {sys.argv[0]} <target_url>")
        print("    Example: python3 favicon_hash.py http://example.com/favicon.ico")
        print("    Tip: You can omit 'http://' — it will be added automatically.")
        sys.exit(1)

    target = sys.argv[1].strip()

    # Try to fetch favicon
    hash_result = get_favicon_hash(target)

    # If failed and it was HTTP, try HTTPS
    if hash_result is None and target.startswith('http://'):
        hash_result = auto_try_https(target)

    if hash_result is None:
        print("[✗] Could not retrieve favicon hash. Please check the URL or network connection.")

if __name__ == "__main__":
    main()
