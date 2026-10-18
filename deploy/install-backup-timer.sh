#!/bin/bash
set -euo pipefail
SOURCE_DIR=$(cd "$(dirname "$0")" && pwd)
install -m 755 "$SOURCE_DIR/veriwork-backup.sh" /usr/local/sbin/veriwork-backup.sh
install -m 644 "$SOURCE_DIR/veriwork-backup.service" /etc/systemd/system/veriwork-backup.service
install -m 644 "$SOURCE_DIR/veriwork-backup.timer" /etc/systemd/system/veriwork-backup.timer
systemctl daemon-reload
systemctl enable --now veriwork-backup.timer
systemctl --no-pager --full status veriwork-backup.timer | head -20
