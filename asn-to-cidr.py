import subprocess
import re

def get_cidrs_from_asn(asn):
    try:
        result = subprocess.run(['whois', '-h', 'whois.radb.net', f'--', f'-i origin AS{asn}'], 
                              capture_output=True, text=True)
        cidrs = re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}', result.stdout)
        return list(set(cidrs))  # Remove duplicates
    except Exception as e:
        print(f"Error: {e}")
        return []

# Read ASNs from file and get CIDRs
with open('', 'r') as f:
    asns = [line.strip() for line in f if line.strip()]

all_cidrs = []
for asn in asns:
    cidrs = get_cidrs_from_asn(asn)
    all_cidrs.extend(cidrs)

# Save to output file
with open('cidrs_output.txt', 'w') as f:
    for cidr in all_cidrs:
        f.write(f"{cidr}\n")
