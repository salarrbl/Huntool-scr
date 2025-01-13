#!/bin/bash

# Define the files containing the URLs
files="./../result/subdomains/all_Subdomains.txt"

# Loop through each file
for file in "${files}"; do

    while IFS= read -r url; do

		# nuclei -silent -si 30 -stats -u "$url"  -es info,low -etags network -o nuclei_output.txt -rl 100;
		nuclei  -si 30 -stats -u "$url"  -es info,low -etags network -o nuclei_output.txt -rl 100;
    done < "$file"
done

