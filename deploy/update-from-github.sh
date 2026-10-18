#!/bin/bash
set -euo pipefail

APP_DIR=/opt/veriwork
DATA_DIR=/opt/veriwork-data
ENV_FILE="$APP_DIR/.env"
TMP_DIR=$(mktemp -d)
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

ensure_env() {
    local key="$1"
    local value="$2"
    if ! grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
        printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
    fi
}

mkdir -p "$DATA_DIR/backups" "$DATA_DIR/evidence"
chown -R veriwork:veriwork "$DATA_DIR"

# Keep the production database outside the web application directory.
if [ -f "$APP_DIR/data/veriwork.db" ] && [ ! -f "$DATA_DIR/veriwork.db" ]; then
    install -o veriwork -g veriwork -m 600 "$APP_DIR/data/veriwork.db" "$DATA_DIR/veriwork.db"
fi

if [ -f "$DATA_DIR/veriwork.db" ]; then
    BACKUP="$DATA_DIR/backups/veriwork-$(date +%Y%m%d-%H%M%S).db"
    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 "$DATA_DIR/veriwork.db" ".backup '$BACKUP'"
    else
        cp "$DATA_DIR/veriwork.db" "$BACKUP"
    fi
    chown veriwork:veriwork "$BACKUP"
    chmod 600 "$BACKUP"
    find "$DATA_DIR/backups" -type f -name 'veriwork-*.db' -mtime +14 -delete
fi

touch "$ENV_FILE"
ensure_env VERIWORK_DB_PATH "$DATA_DIR/veriwork.db"
ensure_env VERIWORK_EVIDENCE_DIR "$DATA_DIR/evidence"
ensure_env MAX_EVIDENCE_BYTES "8388608"
ensure_env SESSION_COOKIE_PATH "/veriwork/"
ensure_env SESSION_COOKIE_SECURE "0"
chown veriwork:veriwork "$ENV_FILE"
chmod 600 "$ENV_FILE"

echo "Downloading latest VeriWork release from GitHub..."
curl -fsSL "https://github.com/XGH530/veriwork/archive/refs/heads/main.tar.gz" -o "$TMP_DIR/source.tar.gz"

echo "Updating application files..."
tar -xzf "$TMP_DIR/source.tar.gz" -C "$APP_DIR" --strip-components=1 \
    --exclude='.env' --exclude='.venv' --exclude='__pycache__' --exclude='data/veriwork.db'

echo "Installing dependencies..."
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

chown -R veriwork:veriwork "$APP_DIR"
chmod 600 "$ENV_FILE" 2>/dev/null || true

echo "Restarting service..."
systemctl restart veriwork
sleep 2
curl -fsS http://127.0.0.1:8000/api/health >/dev/null
systemctl --no-pager --full status veriwork | head -20
