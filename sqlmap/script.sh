#!/bin/bash

RED='\033[31m'
RESET='\033[0m'

path_dir='../result/url_possible_vulnarblities/sqli.txt'
path2='../result/url_possible_vulnarblities/all_possible_vulns_urls.txt'
# Check if the file with URLs is provided as an argument
if [ -z "$path_dir" ]; then
  if [ -z "$path2" ]; then
	  echo "Usage: $0 <file_with_urls>"
	  exit 1
  fi
fi
check_sqli(){
	# Read the file line by line
	if [ -e "../result/url_possible_vulnarblities/sqli.txt" ]; then
		cat $path_dir | while IFS= read -r url; do
		  # Check if the line is not empty
		  echo -e  ${RED}$url${RESET}
		  if [ -n "$url" ]; then
			echo "Running sqlmap on: $url"
			# Run sqlmap on the current URL
			sqlmap -u "$url" --batch --risk=3 --level=5 --dbs
		  fi
		done 
	fi



	if [ -e "../result/url_possible_vulnarblities/all_possible_vulns_urls.txt" ]; then
		cat $path_dir | while IFS= read -r url; do
		  # Check if the line is not empty
		  echo -e  ${RED}$url${RESET}
		  if [ -n "$url" ]; then
			echo "Running sqlmap on: $url"
			# Run sqlmap on the current URL
			sqlmap -u "$url" --batch --risk=3 --level=5 --dbs
		  fi
		done 
	fi
}

mkdir -p ../result/sqlmap_result
check_sqli > ../result/sqlmap_result/result_sqli_sqlmap.txt
