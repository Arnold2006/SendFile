#!/bin/bash
# cleanup_shares.sh
# Run this script to delete expired shares and their files for your PHP file sharing app

DATA_DIR="./data"
UPLOAD_DIR="./uploads"
NOW=$(date +%s)

find "$DATA_DIR" -type f -name "*.json" | while read -r json_file; do
    # Extract the "expires" and "id" fields using jq
    expires=$(jq '.expires' "$json_file" 2>/dev/null)
    id=$(jq -r '.id' "$json_file" 2>/dev/null)
    if [[ -z "$expires" || -z "$id" || "$expires" == "null" || "$id" == "null" ]]; then
        continue
    fi
    # If expired, delete files and metadata
    if (( expires < NOW )); then
        share_dir="$UPLOAD_DIR/$id"
        if [[ -d "$share_dir" ]]; then
            rm -rf "$share_dir"
        fi
        rm -f "$json_file"
        echo "Deleted expired share $id"
    fi
done