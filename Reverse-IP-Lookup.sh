#!/bin/bash

# Usage: ./extract_domains_with_https.sh cidrs.txt

INPUT_FILE="${1:-cidrs.txt}"

if [[ ! -f "$INPUT_FILE" ]]; then
    echo "Usage: $0 <cidr_file>"
    echo "Example file content:"
    echo "  91.212.78.0/24"
    exit 1
fi

sanitize_cidr() {
    echo "$1" | sed 's/\//-/g'
}

while IFS= read -r cidr || [[ -n "$cidr" ]]; do
    [[ -z "$cidr" || "$cidr" =~ ^[[:space:]]*# ]] && continue

    if ! [[ "$cidr" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        echo "Skipping invalid line: $cidr"
        continue
    fi

    FILENAME=$(sanitize_cidr "$cidr")
    URL="https://rapiddns.io/s/$cidr?full=1#result"

    echo "Fetching: $cidr → $FILENAME"

    curl -s -A "Mozilla/5.0" "$URL" -o "$FILENAME" || {
        echo "  ⚠️ Failed to fetch $cidr"
        rm -f "$FILENAME" 2>/dev/null
        continue
    }

    # Extract domains, prepend https://, deduplicate, and save
    grep -oP '<td>\K[^<]*\.[^<]*\.[^<]*[^<]*</td>' "$FILENAME" | \
        sed 's/<\/\?td>//g' | \
        grep -E '\.' | \
        grep -vE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' | \
        sort -u | \
        sed 's/^/https:\/\//' > "$FILENAME.domains"

    echo "  → Extracted $(wc -l < "$FILENAME.domains") domains to $FILENAME.domains"

    # Random delay between 10–20 seconds
    DELAY=$((10 + RANDOM % 11))
    echo "  ⏳ Sleeping for $DELAY seconds..."
    sleep "$DELAY"

done < "$INPUT_FILE"

echo "✅ Done."
