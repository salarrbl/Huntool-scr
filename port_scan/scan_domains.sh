#!/bin/bash

# Define the file containing the list of domains
domains_file="../subdomains/all_Subdomains.txt"

# Read each domain from the file and scan all ports
while IFS= read -r domain; do
    echo "Scanning $domain..."
    nmap -p- -sV $domain
done < "$domains_file" >> nmap_porrt_scan_res.txt
