#!/bin/bash

# Define the file containing the list of domains
domains_file="../subdomains/all_Subdomains.txt"
# domains_file="./a"

# Read each domain from the file and scan all ports
cat ./a | while  read  domains; do
    echo "Scanning $domains..."
    nmap -vv -T4 -p- -sV --max-retries 5  $domains
done  > namp_res.txt
