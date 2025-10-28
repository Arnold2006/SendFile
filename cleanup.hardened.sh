#!/usr/bin/env bash
# cleanup_shares.sh
# Safely remove expired shares and orphaned tmp chunk dirs.
# Install as cron (e.g. run every hour).
# Ensure this script runs as the same user that owns the upload/data directories (or root).

UPLOAD_DIR="/var/www/html/SendFile/uploads"
DATA_DIR="/var/www/html/SendFile/data"
TMP_DIR="/var/www/html/SendFile/tmp_chunks"
LOG="/var/log/sendfile_cleanup.log"
NOW=$(date +%s)

# Safety: don't run if dirs missing
[ -d "$UPLOAD_DIR" ] || exit 0
[ -d "$DATA_DIR" ] || exit 0

echo "Cleanup started: $(date -u)" >> "$LOG"

# Remove expired shares
for meta in "$DATA_DIR"/*.json; do
    [ -f "$meta" ] || continue
    # read expires in a safe way (avoid executing JSON)
    expires=$(grep -oP '"expires"\s*:\s*\K[0-9]+' "$meta" | head -n1)
    id=$(basename "$meta" .json)
    if [ -z "$expires" ]; then
        echo "No expires field for $meta — skipping" >> "$LOG"
        continue
    fi
    if [ "$expires" -lt "$NOW" ]; then
        # double-check realpath to avoid accidental deletion
        share_dir="$UPLOAD_DIR/$id"
        real=$(realpath -m "$share_dir")
        uploads_real=$(realpath -m "$UPLOAD_DIR")
        if [[ "$real" == "$uploads_real"* ]]; then
            rm -rf -- "$real" >> "$LOG" 2>&1
            rm -f -- "$meta" >> "$LOG" 2>&1
            echo "Removed expired share $id" >> "$LOG"
        else
            echo "Warning: share dir $share_dir resolved outside uploads — skipping" >> "$LOG"
        fi
    fi
done

# Remove orphaned tmp dirs older than 48 hours (stale chunk sessions)
find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d -mtime +2 -print0 2>/dev/null | while IFS= read -r -d '' d; do
    # ensure not a symlink outside
    real=$(realpath -m "$d")
    tmp_real=$(realpath -m "$TMP_DIR")
    if [[ "$real" == "$tmp_real"* ]]; then
        rm -rf -- "$d" >> "$LOG" 2>&1
        echo "Removed stale tmp dir $d" >> "$LOG"
    else
        echo "Warning: tmp dir $d resolved outside TMP_DIR — skipping" >> "$LOG"
    fi
done

echo "Cleanup finished: $(date -u)" >> "$LOG"
exit 0
