#!/bin/bash
set -euo pipefail

DATA_DIR=/opt/veriwork-data
BACKUP_DIR="$DATA_DIR/backups"
STAMP=$(date +%Y%m%d-%H%M%S)
DB_FILE="$DATA_DIR/veriwork.db"
EVIDENCE_DIR="$DATA_DIR/evidence"

mkdir -p "$BACKUP_DIR"

if [ -f "$DB_FILE" ]; then
    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 "$DB_FILE" ".backup '$BACKUP_DIR/veriwork-$STAMP.db'"
    else
        cp "$DB_FILE" "$BACKUP_DIR/veriwork-$STAMP.db"
    fi
fi

if [ -d "$EVIDENCE_DIR" ] && [ -n "$(find "$EVIDENCE_DIR" -type f -print -quit)" ]; then
    tar -czf "$BACKUP_DIR/evidence-$STAMP.tar.gz" -C "$DATA_DIR" evidence
fi

chmod 600 "$BACKUP_DIR"/* 2>/dev/null || true
find "$BACKUP_DIR" -type f -mtime +14 -delete

echo "VeriWork backup completed: $STAMP"
