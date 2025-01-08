#!/bin/bash

if [ $# -eq 0 ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

target=$1

echo "Scanning ports 1-8000 on $target..."

for port in {1..8000}; do
    timeout 1 bash -c "echo > /dev/tcp/$target/$port" 2>/dev/null && \
    echo "Port $port is open"
done

echo "Scan complete."
DEFAULT_PORT="80"

ip=$1
if [[ "$ip" =~ ^[a-zA-Z]+$ ]]; then
	ip=dig +short ${ip}
fi

if [[ -z "${ip}" ]]; then
  echo "You must provide an IP address."
  exit 1
fi

if [[ -z "${port}" ]]; then
  echo "You did not provide a specific port, defaulting to ${DEFAULT_PORT}"
  port="${DEFAULT_PORT}"
fi

echo "Attempting to grab the Server header of ${ip}..."

result=$(curl -s --head "${ip}:${port}" | grep Server | awk -F':' '{print $2}') 

echo "Server header for ${ip} on port ${port} is: ${result}"

