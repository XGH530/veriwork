#!/bin/bash
set -euo pipefail
SOURCE="$(cd "$(dirname "$0")" && pwd)/veriwork.nginx.conf"
TARGET="${1:-/www/server/panel/vhost/nginx/extension/8.133.222.0/veriwork.conf}"
if [ ! -f "$TARGET" ]; then
    echo "Nginx target not found: $TARGET" >&2
    exit 1
fi
cp -a "$TARGET" "$TARGET.bak-$(date +%Y%m%d-%H%M%S)"
install -m 644 "$SOURCE" "$TARGET"
nginx -t
systemctl reload nginx
echo "Nginx guard installed: $TARGET"
