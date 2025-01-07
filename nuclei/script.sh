#!/bin/bash

# Define the files containing the URLs
files=("../subdomains/all_Subdomains.txt" "../urls/all_urls.txt" "../url_possible_vulnarblities/all_possible_vulns_urls.txt")

# Loop through each file
for file in "${files[@]}"; do

    while IFS= read -r url; do

		nuclei -silent -si 30 -stats -u "$url"  -es info,low -etags network -o nuclei_output.txt -rl 100;
        # nuclei -u "$url" -t ~/nuclei-templates -o "results_$(basename "$file" .txt).txt"
    done < "$file"
done

