import subprocess
import re
import ipaddress

def get_cidrs_from_asn(asn):
    try:
        # اجرای دستور whois با timeout
        result = subprocess.run(
            ['whois', '-h', 'whois.radb.net', '--', f'-i origin AS{asn}'],
            capture_output=True,
            text=True,
            timeout=15
        )

        # بررسی وضعیت خروجی
        if result.returncode != 0:
            print(f"[!] Whois failed for AS{asn}: {result.stderr.strip()}")
            return []

        if not result.stdout.strip():
            print(f"[-] No data returned for AS{asn}")
            return []

        # یافتن همه الگوهای احتمالی CIDR (IPv4)
        potential_cidrs = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b', result.stdout)

        # اعتبارسنجی و فیلتر CIDRهای واقعی
        valid_cidrs = set()
        for cidr in potential_cidrs:
            try:
                # strict=False allows host bits (e.g., 192.168.1.5/24 → treated as 192.168.1.0/24)
                network = ipaddress.ip_network(cidr, strict=False)
                if isinstance(network, ipaddress.IPv4Network):
                    valid_cidrs.add(str(network))
            except ValueError:
                continue  # نادیده گرفتن CIDRهای نامعتبر

        return list(valid_cidrs)

    except subprocess.TimeoutExpired:
        print(f"[!] Timeout while querying AS{asn}")
        return []
    except FileNotFoundError:
        print("[!] Error: 'whois' command not found. Install it (e.g., 'apt install whois' on Debian/Ubuntu).")
        return []
    except Exception as e:
        print(f"[!] Unexpected error for AS{asn}: {e}")
        return []


def main():
    input_file = './aaaaaaaaaaa'  # ⬅️ نام فایل ورودی را اینجا تنظیم کنید
    output_file = 'cidrs_output.txt'

    try:
        with open(input_file, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[!] Input file '{input_file}' not found.")
        return

    # خواندن و پاک‌سازی ASNها
    asns = []
    for line in lines:
        line = line.strip()
        if line and line.upper().startswith('AS'):
            asn_num = line[2:].lstrip('0') or '0'  # حذف AS و صفرهای ابتدایی
            asns.append(asn_num)
        elif line.isdigit():
            asns.append(line)
        # نادیده گرفتن خطوط خالی یا نامعتبر

    if not asns:
        print("[!] No valid ASNs found in input file.")
        return

    print(f"[+] Processing {len(asns)} ASN(s)...")
    all_cidrs = set()

    for asn in asns:
        print(f"[+] Querying AS{asn}...")
        cidrs = get_cidrs_from_asn(asn)
        all_cidrs.update(cidrs)

    # ذخیره خروجی
    with open(output_file, 'w') as f:
        for cidr in sorted(all_cidrs):
            f.write(cidr + '\n')

    print(f"[+] Done! {len(all_cidrs)} unique CIDR(s) saved to '{output_file}'.")


if __name__ == '__main__':
    main()
