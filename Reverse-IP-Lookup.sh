#!/usr/bin/env bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

BATCH_SIZE=30
MAX_RETRIES=3
INPUT_FILE="${1:-cidrs.txt}"

if [[ ! -f "$INPUT_FILE" ]]; then
    echo -e "${RED}❌ Error:${NC} File not found: $INPUT_FILE"
    echo "Usage: $0 <cidr_file>"
    exit 1
fi

sanitize_cidr() {
    echo "$1" | sed 's/\//-/g'
}

fetch_with_retry() {
    local cidr="$1"
    local retry=0
    local FILENAME=$(sanitize_cidr "$cidr")
    local URL="https://rapiddns.io/s/$cidr?full=1" # 🔥 فاصله اضافی حذف شد!

    while [[ $retry -lt $MAX_RETRIES ]]; do
        echo -e "${BLUE}📥 Attempt $((retry + 1)) for: $cidr${NC}"

        HTTP_CODE=$(curl -s -A "Mozilla/5.0" -w "%{http_code}" -o "$FILENAME" "$URL")

        if [[ "$HTTP_CODE" == "200" ]]; then
            # Extract domains
            grep -oP '<td>\K[^<]*\.[^<]*\.[^<]*[^<]*</td>' "$FILENAME" 2>/dev/null |
                sed 's/<\/\?td>//g' |
                grep -E '\.' |
                grep -vE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' |
                sort -u |
                sed 's|^|https://|' >"$FILENAME.domains" # better syntax

            local count=$(wc -l <"$FILENAME.domains" 2>/dev/null || echo 0)
            if [[ "$count" -gt 0 ]]; then
                echo -e "  ${GREEN}✅ Found $count domains → $FILENAME.domains${NC}"
            else
                echo -e "  ⚪ No domains found."
                rm -f "$FILENAME.domains" 2>/dev/null
            fi
            rm -f "$FILENAME"
            return 0

        elif [[ "$HTTP_CODE" == "403" || "$HTTP_CODE" == "429" || "$HTTP_CODE" == "503" || "$HTTP_CODE" == "500" || "$HTTP_CODE" == "502" ]]; then
            retry=$((retry + 1))
            if [[ $retry -lt $MAX_RETRIES ]]; then
                DELAY_SEC=$((300 + RANDOM % 301))
                echo -e "${RED}🔥 Server error or rate-limit (HTTP $HTTP_CODE) on $cidr. Retry $retry/$MAX_RETRIES after $((DELAY_SEC / 60))m...${NC}"
                sleep "$DELAY_SEC"
            else
                echo -e "${RED}🛑 Max retries ($MAX_RETRIES) reached for $cidr (last code: $HTTP_CODE). Skipping.${NC}"
                rm -f "$FILENAME" 2>/dev/null
                return 1
            fi
        else
            # Other errors (404, etc.) → skip immediately
            echo - e "  ⚠️ HTTP $HTTP_CODE – Skipping $cidr permanently."
            rm -f "$FILENAME" 2>/dev/null
            return 1
        fi
    done
}

# Load and validate CIDRs
mapfile -t CIDRS < <(grep -v '^[[:space:]]*#' "$INPUT_FILE" | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$')

if [[ ${#CIDRS[@]} -eq 0 ]]; then
    echo -e "${YELLOW}⚠️ No valid CIDRs found.${NC}"
    exit 0
fi

echo -e "${BLUE}🚀 Starting batch processing (${#CIDRS[@]} CIDRs, batch size: $BATCH_SIZE)${NC}"

i=0
while [[ $i -lt ${#CIDRS[@]} ]]; do
    batch_end=$((i + BATCH_SIZE))
    if [[ $batch_end -gt ${#CIDRS[@]} ]]; then
        batch_end=${#CIDRS[@]}
    fi

    echo -e "${YELLOW}📦 Batch $((i + 1))–$batch_end of ${#CIDRS[@]}${NC}"

    for ((j = i; j < batch_end; j++)); do
        fetch_with_retry "${CIDRS[j]}" &
    done

    wait

    if [[ $((i + BATCH_SIZE)) -lt ${#CIDRS[@]} ]]; then
        DELAY=$((60 + RANDOM % 61))
        echo -e "${BLUE}⏳ Sleeping $DELAY seconds before next batch...${NC}"
        sleep "$DELAY"
    fi

    i=$((i + BATCH_SIZE))
done

echo -e "${GREEN}🎉 All done!${NC}"
