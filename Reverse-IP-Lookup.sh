#!/bin/bash

# Usage: ./extract_domains.sh cidrs.txt
# Input file: one CIDR per line, e.g. 91.212.78.0/24

INPUT_FILE="${1:-cidrs.txt}"

if [[ ! -f "$INPUT_FILE" ]]; then
    echo "Usage: $0 <cidr_file>"
    echo "Example file content:"
    echo "  91.212.78.0/24"
    echo "  192.168.1.0/24"
    exit 1
fi

# Create safe filename from CIDR (replace / with -)
sanitize_cidr() {
    echo "$1" | sed 's/\//-/g'
}

while IFS= read -r cidr || [[ -n "$cidr" ]]; do
    # Skip empty lines or comments
    [[ -z "$cidr" || "$cidr" =~ ^[[:space:]]*# ]] && continue

    # Validate CIDR format roughly
    if ! [[ "$cidr" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        echo "Skipping invalid line: $cidr"
        continue
    fi

    FILENAME=$(sanitize_cidr "$cidr")
    URL="https://rapiddns.io/s/$cidr?full=1#result"

    echo "Fetching: $cidr → $FILENAME"

    # Fetch HTML (note: fragment #result is ignored by curl; it's client-side)
    curl -s -A "Mozilla/5.0" "$URL" -o "$FILENAME" || {
        echo "  ⚠️ Failed to fetch $cidr"
        rm -f "$FILENAME" 2>/dev/null
        continue
    }

    # Extract domains from 2nd <td> in each <tr> (more accurate than generic pattern)
    # Using your method but improved with context
    grep -oP '<td>\K[^<]*\.[^<]*\.[^<]*[^<]*</td>' "$FILENAME" | \
        sed 's/<\/\?td>//g' | \
        grep -E '\.' | \
        sort -u > "$FILENAME.domains"

    # Optional: remove the HTML file after extraction
    # rm "$FILENAME"

    echo "  → Extracted $(wc -l < "$FILENAME.domains") domains to $FILENAME.domains"
done < "$INPUT_FILE"

echo "✅ Done."
