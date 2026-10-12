#!/bin/bash
set -euo pipefail
APP_DIR=/opt/veriwork
TMP_DIR=$(mktemp -d)
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

echo "Downloading latest VeriWork release from GitHub..."
curl -fsSL "https://github.com/XGH530/veriwork/archive/refs/heads/main.tar.gz" -o "$TMP_DIR/source.tar.gz"

echo "Updating application files..."
tar -xzf "$TMP_DIR/source.tar.gz" -C "$APP_DIR" --strip-components=1 --exclude='.env' --exclude='.venv' --exclude='__pycache__'

echo "Installing dependencies..."
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

chown -R veriwork:veriwork "$APP_DIR"
chmod 600 "$APP_DIR/.env" 2>/dev/null || true

echo "Restarting service..."
systemctl restart veriwork
sleep 2
systemctl --no-pager --full status veriwork | head -20
