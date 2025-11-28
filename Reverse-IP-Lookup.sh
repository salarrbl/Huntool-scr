#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

BATCH_SIZE=50
INPUT_FILE="${1:-cidrs.txt}"

if [[ ! -f "$INPUT_FILE" ]]; then
    echo -e "${RED}❌ Error:${NC} File not found: $INPUT_FILE"
    echo "Usage: $0 <cidr_file>"
    echo "Example:"
    echo "  91.212.78.0/24"
    exit 1
fi

sanitize_cidr() {
    echo "$1" | sed 's/\//-/g'
}

fetch_and_extract() {
    local cidr="$1"
    local FILENAME=$(sanitize_cidr "$cidr")
    local URL="https://rapiddns.io/s/$cidr?full=1"

    echo -e "${BLUE}📥 Fetching: $cidr → $FILENAME${NC}"

    HTTP_CODE=$(curl -s -A "Mozilla/5.0" -w "%{http_code}" -o "$FILENAME" "$URL")

    if [[ "$HTTP_CODE" == "200" ]]; then
        # Extract domains and prepend https://
        grep -oP '<td>\K[^<]*\.[^<]*\.[^<]*[^<]*</td>' "$FILENAME" 2>/dev/null | \
            sed 's/<\/\?td>//g' | \
            grep -E '\.' | \
            grep -vE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' | \
            sort -u | \
            sed 's/^/https:\/\//' > "$FILENAME.domains"

        local count=$(wc -l < "$FILENAME.domains" 2>/dev/null || echo 0)
        if [[ "$count" -gt 0 ]]; then
            echo -e "  ${GREEN}✅ Found $count domains → $FILENAME.domains${NC}"
        else
            echo -e "  ⚪ No domains found."
            rm -f "$FILENAME.domains" 2>/dev/null
        fi
        rm -f "$FILENAME"
    elif [[ "$HTTP_CODE" == "403" || "$HTTP_CODE" == "429" || "$HTTP_CODE" == "503" ]]; then
        echo -e "${RED}🔥 Cloudflare / Rate-limit detected! HTTP $HTTP_CODE${NC}"
        echo -e "${RED}🛑 Stopping to avoid blocking.${NC}"
        touch ".cloudflare_block"
        exit 1
    else
        echo -e "  ⚠️ HTTP $HTTP_CODE – Failed to fetch $cidr"
        rm -f "$FILENAME" 2>/dev/null
    fi
}

# Load valid CIDRs
mapfile -t CIDRS < <(grep -v '^[[:space:]]*#' "$INPUT_FILE" | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$')

if [[ ${#CIDRS[@]} -eq 0 ]]; then
    echo -e "${YELLOW}⚠️ No valid CIDRs found in $INPUT_FILE${NC}"
    exit 0
fi

echo -e "${BLUE}🚀 Starting batch processing (${#CIDRS[@]} CIDRs, batch size: $BATCH_SIZE)${NC}"

i=0
while [[ $i -lt ${#CIDRS[@]} ]]; do
    if [[ -f ".cloudflare_block" ]]; then
        echo -e "${RED}🛑 Aborted due to Cloudflare block.${NC}"
        exit 1
    fi

    batch_end=$(( i + BATCH_SIZE ))
    if [[ $batch_end -gt ${#CIDRS[@]} ]]; then
        batch_end=${#CIDRS[@]}
    fi

    echo -e "${YELLOW}📦 Batch $((i+1))–$batch_end of ${#CIDRS[@]}${NC}"
    for (( j=i; j<batch_end; j++ )); do
        fetch_and_extract "${CIDRS[j]}" &
    done

    wait

    # Check for block signal
    if [[ -f ".cloudflare_block" ]]; then
        echo -e "${RED}🛑 Aborted due to Cloudflare block during batch.${NC}"
        exit 1
    fi

    # Delay only if more batches remain
    if [[ $((i + BATCH_SIZE)) -lt ${#CIDRS[@]} ]]; then
        DELAY=$((60 + RANDOM % 61))  # 60 to 120 seconds
        echo -e "${BLUE}⏳ Sleeping for $DELAY seconds (1–2 min) before next batch...${NC}"
        sleep "$DELAY"
    fi

    i=$((i + BATCH_SIZE))
done

rm -f ".cloudflare_block"
echo -e "${GREEN}🎉 All done!${NC}"
