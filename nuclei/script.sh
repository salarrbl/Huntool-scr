#!/bin/bash

# Define the files containing the URLs
files=("../subdomains/all_Subdomains.txt" "../urls/all_urls.txt" "../url_possible_vulnarblities/all_possible_vulns_urls.txt")

# Loop through each file
for file in "${files[@]}"; do

    while IFS= read -r url; do

        nuclei -u "$url" -t nuclei-templates/ -o "results_$(basename "$file" .txt).txt"
    done < "$file"
done

