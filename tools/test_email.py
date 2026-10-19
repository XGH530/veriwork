"""Send a one-off SMTP test message using the server's .env configuration."""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import server  # noqa: E402


def main() -> int:
    recipient = os.environ.get("TEST_EMAIL", "").strip() or server.ADMIN_EMAIL
    if not recipient:
        print("未设置 TEST_EMAIL 或 ADMIN_EMAIL")
        return 1
    if not server.smtp_configured():
        print("SMTP 未配置完整：请检查 SMTP_HOST、SMTP_USERNAME、SMTP_PASSWORD、SMTP_FROM")
        return 1
    server.send_email_message(
        recipient,
        "职安盾邮件配置测试",
        "这是一封职安盾 VeriWork 邮件配置测试。收到本邮件说明 SMTP 已可正常发信。",
    )
    print(f"测试邮件已发送至 {recipient}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
