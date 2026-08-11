#!/run/current-system/sw/bin/bash
#
# Usage:
#   curl -s https://target.com/path | ./html2img.sh [output.png] [width] [height]
#   ./html2img.sh out.png 1366 768 < page.html
#
# Renders piped HTML with headless Chrome and screenshots it.
# If a terminal image viewer (chafa / timg / kitty icat / viu) is
# found, it prints the image inline. Otherwise just leaves the PNG
# on disk and tells you where it is.

set -euo pipefail

CHROME="${CHROME_BIN:-/run/current-system/sw/bin/google-chrome-stable}"
OUT="${1:-/tmp/html2img_$$.png}"
WIDTH="${2:-1280}"
HEIGHT="${3:-1600}"

if [ -t 0 ]; then
    echo "No HTML piped in. Usage: curl -s URL | $0 [output.png] [width] [height]" >&2
    exit 1
fi

if [ ! -x "$CHROME" ]; then
    echo "Chrome not found at $CHROME (set CHROME_BIN=...)" >&2
    exit 1
fi

TMP_HTML="$(mktemp --suffix=.html)"
trap 'rm -f "$TMP_HTML"' EXIT

cat > "$TMP_HTML"

if [ ! -s "$TMP_HTML" ]; then
    echo "Piped input was empty — nothing to render." >&2
    exit 1
fi

"$CHROME" \
    --headless=new \
    --disable-gpu \
    --no-sandbox \
    --hide-scrollbars \
    --screenshot="$OUT" \
    --window-size="${WIDTH},${HEIGHT}" \
    "file://$TMP_HTML" >/dev/null 2>&1

if [ ! -s "$OUT" ]; then
    echo "Render failed — no screenshot produced." >&2
    exit 1
fi

echo "Saved: $OUT" >&2

if command -v chafa >/dev/null 2>&1; then
    chafa --size="${COLUMNS:-100}x40" "$OUT"
elif command -v timg >/dev/null 2>&1; then
    timg -g "${COLUMNS:-100}x40" "$OUT"
elif command -v viu >/dev/null 2>&1; then
    viu "$OUT"
elif [ -n "${KITTY_WINDOW_ID:-}" ] && command -v kitty >/dev/null 2>&1; then
    kitty +kitten icat "$OUT"
else
    echo "No terminal image viewer found (install one of: chafa, timg, viu)." >&2
    echo "Screenshot left at: $OUT" >&2
fi
