#!/usr/bin/env python3
"""抓取公开官方来源并建立可追溯清单。

只抓取政府、人大和人社部门公开页面，不采集个人信息。
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import urllib.request
from datetime import datetime
from pathlib import Path

from lxml import html

ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "official_sources" / "raw"
TEXT_DIR = ROOT / "data" / "official_sources" / "text"
MANIFEST = ROOT / "data" / "official_sources" / "manifest.json"

SOURCES = [
    {
        "id": "minimum_wage_2026_10",
        "category": "policy",
        "title": "全国各省、自治区、直辖市最低工资标准情况（截至2026年10月1日）",
        "url": "https://www.mohrss.gov.cn/SYrlzyhshbzb/laodongguanxi_/fwyd/202610/t20261008_585187.html",
        "browser": True,
    },
    {
        "id": "guangdong_minimum_wage_notice",
        "category": "policy",
        "title": "广东省人民政府关于调整我省最低工资标准的通知",
        "url": "https://www.gd.gov.cn/zwgk/gongbao/2026/18/content/post_4942204.html",
        "browser": False,
    },
    {
        "id": "labor_law",
        "category": "law",
        "title": "中华人民共和国劳动法",
        "url": "http://www.npc.gov.cn/npc/c2/c30834/201905/t20190521_296651.html",
        "browser": False,
    },
    {
        "id": "labor_contract_law",
        "category": "law",
        "title": "中华人民共和国劳动合同法",
        "url": "https://www.samr.gov.cn/zw/zfxxgk/fdzdgknr/bgt/art/2023/art_0abfdd261c03417b949df19d869add8d.html",
        "browser": False,
    },
    {
        "id": "social_insurance_law",
        "category": "law",
        "title": "中华人民共和国社会保险法",
        "url": "https://www.gov.cn/guoqing/2021-10/29/content_5647616.htm",
        "browser": False,
    },
    {
        "id": "employment_promotion_law",
        "category": "law",
        "title": "中华人民共和国就业促进法",
        "url": "https://www.gov.cn/guoqing/2021-10/29/content_5647636.htm",
        "browser": False,
    },
]


def find_edge() -> str | None:
    candidates = [
        shutil.which("msedge"),
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    return None


def fetch_url(url: str, browser: bool) -> bytes:
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36"}
    if not browser:
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=40) as response:
            return response.read()

    edge = find_edge()
    if not edge:
        raise RuntimeError("需要浏览器抓取，但未找到 Microsoft Edge")
    with tempfile.TemporaryDirectory(prefix="veriwork-edge-") as profile:
        command = [
            edge, "--headless=old", "--no-sandbox", "--disable-gpu",
            "--disable-gpu-sandbox", "--disable-software-rasterizer",
            f"--user-data-dir={profile}", "--virtual-time-budget=8000",
            "--dump-dom", url,
        ]
        completed = subprocess.run(command, check=True, capture_output=True, timeout=90)
        return completed.stdout


def clean_text(raw: bytes) -> str:
    doc = html.fromstring(raw)
    for bad in doc.xpath("//script|//style|//noscript|//nav|//header|//footer"):
        parent = bad.getparent()
        if parent is not None:
            parent.remove(bad)

    containers = [
        "//div[@id='UCAP-CONTENT']",
        "//div[contains(@class,'pages_content')]",
        "//article",
        "//div[contains(@class,'article')]",
        "//div[contains(@class,'content')]",
    ]
    best = ""
    for expression in containers:
        nodes = doc.xpath(expression)
        if not nodes:
            continue
        text = "\n".join(
            re.sub(r"\s+", " ", value).strip()
            for value in nodes[0].xpath(".//text()")
            if re.sub(r"\s+", " ", value).strip()
        )
        if len(text) > len(best):
            best = text
    if len(best) > 200:
        return best

    lines = []
    for value in doc.xpath("//body//text()"):
        text = re.sub(r"\s+", " ", value).strip()
        if text:
            lines.append(text)
    return "\n".join(lines)


def extract_title(raw: bytes, fallback: str) -> str:
    doc = html.fromstring(raw)
    title = doc.xpath("string(//meta[@name='ArticleTitle']/@content)") or doc.xpath("string(//title)")
    return re.sub(r"\s+", " ", title).strip() or fallback


def extract_pub_date(raw: bytes) -> str | None:
    doc = html.fromstring(raw)
    value = doc.xpath("string(//meta[@name='PubDate']/@content)")
    return re.sub(r"\s+", " ", value).strip() or None


def extract_minimum_wage_table(raw: bytes) -> list[dict]:
    doc = html.fromstring(raw)
    tables = doc.xpath("//table")
    if not tables:
        return []
    parsed = []
    for tr in tables[0].xpath(".//tr"):
        cells = ["".join(td.itertext()).strip() for td in tr.xpath("./th|./td")]
        clean = ["".join(ch for ch in cell if not ch.isspace()) for cell in cells]
        if len(clean) < 6 or not clean[0] or clean[0] in {"地区", "第一档"}:
            continue
        parsed.append({
            "region": clean[0],
            "monthly": [value for value in clean[1:5] if value],
            "hourly": [value for value in clean[5:9] if value],
        })
    return parsed


def main() -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    TEXT_DIR.mkdir(parents=True, exist_ok=True)
    manifest = {"generated_at": datetime.now().isoformat(timespec="seconds"), "sources": []}

    for source in SOURCES:
        print("fetch", source["id"], source["url"])
        raw = fetch_url(source["url"], source["browser"])
        raw_path = RAW_DIR / f"{source['id']}.html"
        text_path = TEXT_DIR / f"{source['id']}.txt"
        raw_path.write_bytes(raw)
        text = clean_text(raw)
        text_path.write_text(text, encoding="utf-8")
        item = {
            **source,
            "fetched_at": datetime.now().isoformat(timespec="seconds"),
            "resolved_title": extract_title(raw, source["title"]),
            "published_at": extract_pub_date(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "raw_file": str(raw_path.relative_to(ROOT)),
            "text_file": str(text_path.relative_to(ROOT)),
            "text_chars": len(text),
        }
        if source["id"] == "minimum_wage_2026_10":
            item["minimum_wage_table"] = extract_minimum_wage_table(raw)
        manifest["sources"].append(item)

    MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print("manifest", MANIFEST)


if __name__ == "__main__":
    main()
