#!/usr/bin/env python3
"""职安盾 VeriWork 本地服务。

仅使用 Python 标准库，既可提供静态前端，也可在配置环境变量后接入
OpenAI-compatible 大模型接口。硬规则和法源引用由程序控制，模型只负责
在已有证据范围内优化解释，不拥有修改风险等级和新增法源的权限。
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

BASE_DIR = Path(__file__).resolve().parent


def load_env_file() -> None:
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_env_file()

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
MAX_BODY = 12 * 1024 * 1024
DB_PATH = BASE_DIR / "data" / "veriwork.db"
PBKDF2_ITERATIONS = 200_000
SESSION_DAYS = 7


def auth_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS
    ).hex()
    return salt, digest


def init_auth_db() -> None:
    with auth_db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'student',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                case_type TEXT NOT NULL,
                jurisdiction TEXT NOT NULL,
                document_language TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                risk_ids TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            """
        )
        demo_username = os.environ.get("DEMO_USERNAME", "demo")
        demo_password = os.environ.get("DEMO_PASSWORD", "demo123456")
        existing = connection.execute("SELECT id FROM users WHERE username = ?", (demo_username,)).fetchone()
        salt, digest = hash_password(demo_password)
        if not existing:
            connection.execute(
                "INSERT INTO users(username, salt, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (demo_username, salt, digest, "student", datetime.now().isoformat(timespec="seconds")),
            )
        else:
            connection.execute(
                "UPDATE users SET salt = ?, password_hash = ?, role = 'student' WHERE username = ?",
                (salt, digest, demo_username),
            )
        admin_username = os.environ.get("ADMIN_USERNAME", "admin")
        admin_password = os.environ.get("ADMIN_PASSWORD", "admin123456")
        existing_admin = connection.execute("SELECT id FROM users WHERE username = ?", (admin_username,)).fetchone()
        salt, digest = hash_password(admin_password)
        if not existing_admin:
            connection.execute(
                "INSERT INTO users(username, salt, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (admin_username, salt, digest, "admin", datetime.now().isoformat(timespec="seconds")),
            )
        else:
            connection.execute(
                "UPDATE users SET salt = ?, password_hash = ?, role = 'admin' WHERE username = ?",
                (salt, digest, admin_username),
            )
        connection.commit()


init_auth_db()


def register_user(username: str, password: str, role: str = "student") -> dict:
    username = username.strip()
    if not (3 <= len(username) <= 32):
        raise ValueError("用户名长度应为3至32位")
    if len(password) < 8:
        raise ValueError("密码至少8位")
    salt, digest = hash_password(password)
    try:
        with auth_db() as connection:
            cursor = connection.execute(
                "INSERT INTO users(username, salt, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, salt, digest, role, datetime.now().isoformat(timespec="seconds")),
            )
            connection.commit()
            return {"id": cursor.lastrowid, "username": username, "role": role}
    except sqlite3.IntegrityError as exc:
        raise ValueError("用户名已存在") from exc


def authenticate_user(username: str, password: str) -> dict | None:
    with auth_db() as connection:
        row = connection.execute("SELECT * FROM users WHERE username = ?", (username.strip(),)).fetchone()
    if not row:
        return None
    _, digest = hash_password(password, row["salt"])
    if not secrets.compare_digest(digest, row["password_hash"]):
        return None
    return {"id": row["id"], "username": row["username"], "role": row["role"]}


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.now()
    expires = now + timedelta(days=SESSION_DAYS)
    with auth_db() as connection:
        connection.execute(
            "INSERT INTO sessions(token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, user_id, now.isoformat(timespec="seconds"), expires.isoformat(timespec="seconds")),
        )
        connection.commit()
    return token


def resolve_session(token: str | None) -> dict | None:
    if not token:
        return None
    with auth_db() as connection:
        row = connection.execute(
            """
            SELECT users.id, users.username, users.role, sessions.expires_at
            FROM sessions JOIN users ON sessions.user_id = users.id
            WHERE sessions.token = ?
            """,
            (token,),
        ).fetchone()
        if not row:
            return None
        if datetime.fromisoformat(row["expires_at"]) < datetime.now():
            connection.execute("DELETE FROM sessions WHERE token = ?", (token,))
            connection.commit()
            return None
    return {"id": row["id"], "username": row["username"], "role": row["role"]}


def save_case_record(user: dict, result: dict, case_type: str, jurisdiction: str, language: str) -> None:
    with auth_db() as connection:
        connection.execute(
            """
            INSERT INTO cases(user_id, case_type, jurisdiction, document_language, risk_score, risk_level, risk_ids, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user["id"],
                case_type,
                jurisdiction,
                language,
                int(result.get("riskScore", 0)),
                str(result.get("riskLevel", "")),
                ",".join(risk["id"] for risk in result.get("risks", [])),
                datetime.now().isoformat(timespec="seconds"),
            ),
        )
        connection.commit()


def admin_stats() -> dict:
    with auth_db() as connection:
        users = connection.execute("SELECT id, username, role, created_at FROM users ORDER BY id DESC").fetchall()
        cases = connection.execute(
            """
            SELECT cases.id, cases.case_type, cases.jurisdiction, cases.document_language,
                   cases.risk_score, cases.risk_level, cases.risk_ids, cases.created_at,
                   users.username
            FROM cases JOIN users ON cases.user_id = users.id
            ORDER BY cases.id DESC LIMIT 100
            """
        ).fetchall()
    risk_counter = {}
    for case in cases:
        for risk_id in filter(None, case["risk_ids"].split(",")):
            risk_counter[risk_id] = risk_counter.get(risk_id, 0) + 1
    return {
        "userCount": len(users),
        "caseCount": len(cases),
        "highRiskCount": sum(1 for case in cases if case["risk_score"] >= 70),
        "users": [dict(row) for row in users],
        "cases": [dict(row) for row in cases],
        "topRisks": sorted(risk_counter.items(), key=lambda item: item[1], reverse=True)[:10],
        "model": os.environ.get("LLM_MODEL", ""),
        "rules": len(RISKS),
        "laws": len(LAWS),
    }


def revoke_session(token: str | None) -> None:
    if not token:
        return
    with auth_db() as connection:
        connection.execute("DELETE FROM sessions WHERE token = ?", (token,))
        connection.commit()


LAWS = [
    {
        "id": "lcl_10_82",
        "title": "书面劳动合同与二倍工资",
        "source": "《中华人民共和国劳动合同法》第十条、第八十二条",
        "summary": "建立劳动关系应订立书面劳动合同；超过一个月未订立存在二倍工资责任风险。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "lcl_19",
        "title": "试用期期限与次数",
        "source": "《中华人民共和国劳动合同法》第十九条",
        "summary": "试用期期限与合同期限对应，同一用人单位与同一劳动者只能约定一次试用期。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "lcl_20",
        "title": "试用期工资底线",
        "source": "《中华人民共和国劳动合同法》第二十条",
        "summary": "试用期工资不得低于本单位相同岗位最低档工资或者合同约定工资的80%，且不得低于当地最低工资标准。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "lcl_9",
        "title": "禁止收取财物和扣押证件",
        "source": "《中华人民共和国劳动合同法》第九条",
        "summary": "用人单位不得扣押证件、要求担保或者以其他名义向劳动者收取财物。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "lcl_26",
        "title": "无效或部分无效条款",
        "source": "《中华人民共和国劳动合同法》第二十六条",
        "summary": "免除用人单位法定责任、排除劳动者权利的条款可能无效或部分无效。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "lcl_23_24",
        "title": "竞业限制人员、期限与补偿",
        "source": "《中华人民共和国劳动合同法》第二十三条、第二十四条",
        "summary": "竞业限制期限不得超过二年，并应关注适用人员范围和补偿安排。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "labor_41_44",
        "title": "加班安排与加班费",
        "source": "《中华人民共和国劳动法》第四十一条、第四十四条",
        "summary": "延长工作时间应符合法定程序和时长限制，并依法支付加班工资。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "labor_50_wage",
        "title": "工资支付与不得克扣拖欠",
        "source": "《中华人民共和国劳动法》第五十条",
        "summary": "工资应以货币形式按月支付，不得克扣或者无故拖欠。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "lcl_35",
        "title": "合同变更应协商一致",
        "source": "《中华人民共和国劳动合同法》第三十五条",
        "summary": "变更劳动合同约定内容应协商一致并采用书面形式。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "lcl_37",
        "title": "劳动者提前通知解除合同",
        "source": "《中华人民共和国劳动合同法》第三十七条",
        "summary": "劳动者提前三十日书面通知可以解除劳动合同，试用期提前三日通知。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "lcl_38_46_47",
        "title": "解除情形与经济补偿",
        "source": "《中华人民共和国劳动合同法》第三十八条、第四十六条、第四十七条",
        "summary": "欠薪、未依法缴社保等情形下劳动者可以解除合同并可能获得经济补偿。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "lcl_85",
        "title": "拖欠工资等行为的法律后果",
        "source": "《中华人民共和国劳动合同法》第八十五条",
        "summary": "未及时足额支付报酬、低于最低工资、未依法支付加班费等存在限期支付和加付赔偿金风险。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "social_58_60",
        "title": "社会保险登记与依法缴纳",
        "source": "《中华人民共和国社会保险法》第五十八条、第六十条",
        "summary": "用人单位应依法办理社保登记并按时足额缴费，不能通过约定放弃法定义务。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "employment_27",
        "title": "平等就业与反歧视",
        "source": "《中华人民共和国就业促进法》第二十七条",
        "summary": "用人单位招用人员应依法保障劳动者平等就业权利。",
        "url": "https://flk.npc.gov.cn/",
    },
]


REVIEW_RULES = [
    {
        "id": "relationship_ambiguity",
        "regex": r"实习|兼职|劳务|非全日制|灵活用工|项目合作|合作人员|合作协议",
        "title": "劳动关系性质需核实",
        "detail": "实习、兼职、劳务或非全日制关系适用规则不同，需要结合实际管理方式、报酬和用工事实判断。",
    },
    {
        "id": "missing_terms",
        "regex": r"工资面议|薪资面议|社保面议|试用期待定|合同期限未定|以实际为准|另行约定|尚未确定|尚未明确|未确定|未明确",
        "title": "关键条款缺失或表述不确定",
        "detail": "工资、试用期、社保或合同期限未明确，不能仅凭当前材料输出确定结论。",
    },
    {
        "id": "oral_context",
        "regex": r"口头承诺|微信里说|HR口头表示|暂未写入合同",
        "title": "口头约定需要补充证据",
        "detail": "未写入书面材料的口头承诺需要聊天、录音、邮件或其他证据佐证。",
    },
]


JURISDICTIONS = {
    "全国规则": {
        "id": "全国规则",
        "title": "全国基础规则包",
        "status": "基础模式",
        "note": "当前使用全国性法律法规规则，不自动套用未经验证的地方数字标准。",
    },
    "北京": {
        "id": "北京",
        "title": "北京地区政策适配包",
        "status": "原型占位",
        "note": "正式参赛前接入北京市人社部门最新政策，并保留生效日期。",
    },
    "上海": {
        "id": "上海",
        "title": "上海地区政策适配包",
        "status": "原型占位",
        "note": "正式参赛前接入上海市人社部门最新政策，并保留生效日期。",
    },
    "广东": {
        "id": "广东",
        "title": "广东地区政策适配包",
        "status": "原型占位",
        "note": "广东不同城市最低工资存在差异，正式部署应按用工所在地建立城市级政策包。",
    },
}


RISKS = [
    {
        "id": "no_social_insurance",
        "title": "约定不缴或放弃社会保险",
        "category": "社会保障",
        "severity": "high",
        "weight": 22,
        "confidence": 0.97,
        "regex": r"(?:不|不予|不再|无需|拒绝)[^。；\n]{0,8}(?:缴纳|购买|办理)[^。；\n]{0,8}(?:社保|社会保险)|自愿放弃[^。；\n]{0,10}(?:社保|社会保险)|社保补贴代替社保",
        "reason": "依法参加社会保险属于法定义务，通常不能通过“自愿放弃”或现金补贴有效排除。",
        "action": "要求书面确认社保缴纳主体、起始月份和基数，并要求删除放弃社保条款。",
        "lawIds": ["social_58_60", "lcl_26", "lcl_38_46_47"],
    },
    {
        "id": "employment_deposit",
        "title": "押金、保证金或扣押证件",
        "category": "入职收费",
        "severity": "high",
        "weight": 20,
        "confidence": 0.96,
        "regex": r"押金|保证金|设备押金|服装费|扣留身份证|扣押身份证|提交证件原件|身份证原件由公司保管",
        "exceptionRegex": r"(?:不|不会|不得|禁止)[^。；\n]{0,12}(?:收取|要求)[^。；\n]{0,12}(?:押金|保证金|服装费)|不扣押[^。；\n]{0,10}(?:证件|身份证)",
        "reason": "用人单位不得收取押金、保证金等财物，也不得扣押居民身份证和其他证件。",
        "action": "拒绝支付入职押金，保留招聘信息和付款记录，必要时向人社部门投诉。",
        "lawIds": ["lcl_9", "lcl_26"],
    },
    {
        "id": "training_loan",
        "title": "培训贷或变相岗前收费",
        "category": "招聘诈骗",
        "severity": "high",
        "weight": 24,
        "confidence": 0.95,
        "regex": r"培训贷|分期贷款|贷款培训|岗前培训费|先交[^。；\n]{0,10}培训费|工作未满[^。；\n]{0,12}偿还培训贷款",
        "exceptionRegex": r"(?:不|不会|不得|禁止)[^。；\n]{0,12}(?:要求|设置|收取)?[^。；\n]{0,12}(?:培训贷|培训费|岗前收费)",
        "reason": "以入职为条件要求贷款或先缴高额培训费用，存在招聘诈骗和变相收费风险。",
        "action": "停止付款和贷款，核验机构资质，保留聊天、合同、转账与宣传页面证据。",
        "lawIds": ["lcl_9", "lcl_26"],
    },
    {
        "id": "probation_salary",
        "title": "试用期工资低于法定底线",
        "category": "试用期",
        "severity": "high",
        "weight": 18,
        "confidence": 0.88,
        "regex": r"试用期[^。；\n]{0,18}(?:工资|薪资|薪酬)[^。；\n]{0,15}(?:50%|60%|70%|不支付|零工资|无薪)",
        "exceptionRegex": r"不低于[^。；\n]{0,8}80%|达到[^。；\n]{0,8}80%|符合[^。；\n]{0,8}80%",
        "reason": "试用期工资不得低于法定底线的80%规则，并不得低于当地最低工资标准。",
        "action": "要求写明试用期月工资，并对照合同约定工资和当地最低工资核验。",
        "lawIds": ["lcl_20", "lcl_85"],
    },
    {
        "id": "probation_duration",
        "title": "试用期期限需要重点核验",
        "category": "试用期",
        "severity": "medium",
        "weight": 11,
        "confidence": 0.82,
        "regex": r"(?:试用期[^。；\n]{0,12}(?:六个月|6个月|一年|十二个月|延长试用期)|(?:转正后|入职后)[^。；\n]{0,12}再次试用)",
        "exceptionRegex": r"试用期[^。；\n]{0,8}不超过(?:六个月|6个月)|(?:合同期限三年以上|三年以上固定期限|无固定期限)[^。；\n]{0,30}试用期[^。；\n]{0,10}(?:六个月|6个月)",
        "reason": "六个月试用期仅在特定合同期限下才可能合法，同一单位只能约定一次试用期。",
        "action": "核对劳动合同期限、试用期次数和转正条件，拒绝不合理重复试用。",
        "lawIds": ["lcl_19"],
    },
    {
        "id": "noncompete_risk",
        "title": "竞业限制期限或补偿异常",
        "category": "离职限制",
        "severity": "high",
        "weight": 19,
        "confidence": 0.91,
        "regex": r"竞业限制[^。；\n]{0,35}(?:三年|3年|不支付(?:经济)?补偿|无需支付|无经济补偿)|离职后[^。；\n]{0,12}(?:三年|3年)[^。；\n]{0,15}不得",
        "reason": "竞业限制期限不得超过二年，适用人员范围和补偿安排均有法定限制。",
        "action": "核对岗位是否适用，要求明确补偿标准、支付方式和限制范围。",
        "lawIds": ["lcl_23_24"],
    },
    {
        "id": "overtime_unpaid",
        "title": "排除或变相规避加班费",
        "category": "工时薪酬",
        "severity": "high",
        "weight": 18,
        "confidence": 0.92,
        "regex": r"996|自愿加班|无偿加班|不支付加班费|加班费[^。；\n]{0,10}(?:包含|已包含)[^。；\n]{0,8}工资|自愿放弃加班费",
        "reason": "加班安排和加班费支付属于法定义务，以“自愿”为名排除责任存在违法风险。",
        "action": "保存考勤、工作群、任务记录和工资单，要求明确工时制度和加班费计算方式。",
        "lawIds": ["labor_41_44", "labor_50_wage", "lcl_85"],
    },
    {
        "id": "resignation_penalty",
        "title": "辞职违约金或不合理离职限制",
        "category": "离职限制",
        "severity": "high",
        "weight": 18,
        "confidence": 0.89,
        "regex": r"(?:辞职|离职|未满[^。；\n]{0,6}年)[^。；\n]{0,18}违约金|离职需[^。；\n]{0,12}批准",
        "reason": "除服务期和竞业限制等法定情形外，一般不得随意约定由劳动者承担违约金。",
        "action": "核验违约金对应的法定情形和金额依据，保留提出离职和送达证据。",
        "lawIds": ["lcl_37", "lcl_26"],
    },
    {
        "id": "unilateral_change",
        "title": "单方调岗、调薪或变更工作地点",
        "category": "合同变更",
        "severity": "medium",
        "weight": 12,
        "confidence": 0.86,
        "regex": r"(?:公司|用人单位)[^。；\n]{0,12}(?:随时|根据经营需要|无需同意)[^。；\n]{0,14}(?:调岗|调薪|调整(?:岗位|薪酬|薪资|工作地点))|无条件服从[^。；\n]{0,8}调岗",
        "reason": "合同变更原则上应协商一致并采用书面形式，完全排除协商权存在风险。",
        "action": "要求明确岗位、薪酬、工作地点和变更程序，保留原合同及调岗通知。",
        "lawIds": ["lcl_35", "lcl_26"],
    },
    {
        "id": "wage_delay",
        "title": "工资延迟、押金式发放或离职结算异常",
        "category": "工资支付",
        "severity": "high",
        "weight": 18,
        "confidence": 0.90,
        "regex": r"押[^。；\n]{0,4}个月工资|次月[^。；\n]{0,4}(?:30|28|月底)[^。；\n]{0,8}发放|年底[^。；\n]{0,6}(?:统一|一次性)[^。；\n]{0,4}发放|离职后[^。；\n]{0,12}结算(?:剩余)?工资",
        "reason": "工资应依法按月足额支付，无故拖欠或克扣工资存在法律责任。",
        "action": "确认每月工资发放日期，保留工资条、银行流水和催款记录。",
        "lawIds": ["labor_50_wage", "lcl_85"],
    },
    {
        "id": "no_written_contract",
        "title": "不签订或拖延签订书面劳动合同",
        "category": "合同形式",
        "severity": "high",
        "weight": 17,
        "confidence": 0.91,
        "regex": r"口头约定|暂不签订[^。；\n]{0,10}劳动合同|转正后[^。；\n]{0,8}(?:再|才)[^。；\n]{0,6}签订|试用期不签合同",
        "reason": "建立劳动关系后应依法订立书面劳动合同，超过一个月未订立存在二倍工资等风险。",
        "action": "保留入职通知、考勤、工资发放和工作沟通记录，主动要求补签书面合同。",
        "lawIds": ["lcl_10_82"],
    },
    {
        "id": "social_base",
        "title": "社保基数或缴纳方式异常",
        "category": "社会保障",
        "severity": "medium",
        "weight": 11,
        "confidence": 0.78,
        "regex": r"社保[^。；\n]{0,15}(?:最低基数|按最低标准)|(?:按)?最低基数[^。；\n]{0,10}(?:办理|缴纳)[^。；\n]{0,6}社保|最低标准[^。；\n]{0,10}(?:办理|缴纳)[^。；\n]{0,6}社保|工资[^。；\n]{0,12}另发[^。；\n]{0,12}社保",
        "reason": "社保缴费基数通常应与工资收入相关联，统一按最低基数可能产生争议。",
        "action": "核对工资构成、合同金额、社保缴费记录和缴费基数。",
        "lawIds": ["social_58_60"],
    },
    {
        "id": "discrimination",
        "title": "婚育、性别等就业歧视风险",
        "category": "平等就业",
        "severity": "high",
        "weight": 18,
        "confidence": 0.94,
        "regex": r"(?:不得|禁止|承诺)[^。；\n]{0,8}(?:怀孕|生育|结婚|婚育)|仅限男性|男性优先|女性[^。；\n]{0,8}(?:未婚|未育)",
        "reason": "与岗位无关的性别、婚育限制可能构成就业歧视。",
        "action": "保存招聘页面和沟通记录，可向人社部门、工会或公共法律服务平台反映。",
        "lawIds": ["employment_27"],
    },
]


SEMANTIC_PATTERNS = {
    "no_social_insurance": r"(?=.*(?:社保|社会保险))(?=.*(?:员工自行|自行购买|公司不承担|不办理|不缴|再补缴|自行承担)).*",
    "employment_deposit": r"(?=.*(?:押金|保证金|工装费|服装费|毕业证原件|证件原件|身份证原件))(?=.*(?:入职|录用|先交|需交|须交|上交|收取|保管|缴纳)).*",
    "training_loan": r"(?=.*(?:贷款|培训费|培训收费|技能提升))(?=.*(?:入职|岗前|岗位|办理|分期|工资中扣除|先交|为获得)).*",
    "probation_salary": r"(?:试用期[^。；\n]{0,22}(?:[1-7][0-9]%|一半|低于[^。；\n]{0,6}80%)|前(?:一|二|三|1|2|3)个月[^。；\n]{0,18}(?:一半|只发|仅发|不给)).*",
    "probation_duration": r"(?:(?:试用期|实习期)[^。；\n]{0,16}(?:[7-9]个月|1[0-2]个月|八个月|九个月|十个月|十一个月|十二个月|一年)|(?:劳动合同|合同期限|期限)[^。；\n]{0,14}(?:一年|两年|二年|1年|2年)[^。；\n]{0,18}试用期[^。；\n]{0,8}(?:[3-9]个月|1[0-2]个月)).*",
    "noncompete_risk": r"(?=.*(?:竞业禁止|竞业限制|不得同业|不得从事同类))(?=.*(?:三年|3年|24个月|无补偿|未约定[^。；\n]{0,8}补偿|不支付[^。；\n]{0,8}补偿)).*",
    "overtime_unpaid": r"(?=.*(?:加班|额外工时|延长工作时间))(?=.*(?:不计算|不结算|不支付|已覆盖|不再结算|视为自愿|不得主张)).*",
    "resignation_penalty": r"(?=.*(?:离职|辞职|服务期))(?=.*(?:赔偿|违约金|须经[^。；\n]{0,8}同意|未完成|扣发)).*",
    "unilateral_change": r"(?=.*(?:调岗|调薪|调整[^。；\n]{0,8}(?:岗位|薪资|薪酬)|工作地点[^。；\n]{0,8}变更))(?=.*(?:公司有权|无需同意|不得异议|根据[^。；\n]{0,8}业务|依[^。；\n]{0,8}业务|向业务变化)).*",
    "wage_delay": r"(?=.*(?:工资|报酬))(?=.*(?:推迟|下月底|三个月后|再发放|延后|延期)).*",
    "no_written_contract": r"(?=.*(?:书面合同|劳动合同|书面文件))(?=.*(?:代替|再签|后再签|满[^。；\n]{0,8}再签|未签|暂不签)).*",
    "social_base": r"(?=.*(?:社保|社会保险))(?=.*(?:最低档|最低基数|按基本工资|不含绩效|不按实际工资)).*",
    "discrimination": r"(?:未婚女性|已婚未育|不生育|生育承诺|承诺[^。；\n]{0,8}(?:不怀孕|不生育)|仅限男性|男性优先).*",
}


def parse_page_range(spec: str, total: int) -> list[int]:
    spec = (spec or "").strip().lower()
    if not spec or spec in {"all", "全部", "*"}:
        return list(range(total))
    selected = []
    for part in spec.replace("，", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start, end = int(start_text), int(end_text)
        else:
            start = end = int(part)
        start = max(1, start)
        end = min(total, end)
        if start <= end:
            selected.extend(range(start - 1, end))
    return sorted(dict.fromkeys(selected))


def extract_document(filename: str, data: bytes, language: str = "zh", page_range: str = "") -> dict:
    suffix = Path(filename).suffix.lower()
    text = ""
    if suffix == ".pdf":
        try:
            from pypdf import PdfReader
        except ImportError as exc:
            raise ValueError("服务器未安装 pypdf，无法解析PDF") from exc
        reader = PdfReader(io.BytesIO(data))
        selected = parse_page_range(page_range, len(reader.pages))
        text = "\n".join((reader.pages[index].extract_text() or "") for index in selected)
    elif suffix == ".docx":
        try:
            import docx
        except ImportError as exc:
            raise ValueError("服务器未安装 python-docx，无法解析DOCX") from exc
        document = docx.Document(io.BytesIO(data))
        lines = [paragraph.text for paragraph in document.paragraphs if paragraph.text.strip()]
        for table in document.tables:
            for row in table.rows:
                cells = [cell.text.strip() for cell in row.cells if cell.text.strip()]
                if cells:
                    lines.append(" | ".join(cells))
        text = "\n".join(lines)
    elif suffix in {".txt", ".md", ".json", ".csv"}:
        text = data.decode("utf-8", errors="replace")
    else:
        raise ValueError(f"暂不支持的文件类型：{suffix or '未知'}")
    text = "\n".join(line.strip() for line in text.splitlines() if line.strip())
    if len(text) < 20:
        raise ValueError("文件中未提取到足够的文本内容")
    return {"filename": filename, "format": suffix.lstrip("."), "language": language, "pageRange": page_range, "chars": len(text), "text": text}


def law_map() -> dict[str, dict]:
    return {item["id"]: item for item in LAWS}


def tokenize_chinese(text: str) -> set[str]:
    normalized = re.sub(r"[^\u4e00-\u9fa5a-zA-Z0-9]", "", text)
    tokens: set[str] = set()
    for index, char in enumerate(normalized):
        tokens.add(char)
        if index + 1 < len(normalized):
            tokens.add(normalized[index:index + 2])
    return tokens


def retrieve_laws(clause: str, seed_ids: list[str], laws_by_id: dict[str, dict], limit: int = 4) -> list[dict]:
    query_tokens = tokenize_chinese(clause)
    seed_set = set(seed_ids)
    ranked = []
    for law in laws_by_id.values():
        haystack = " ".join([law["title"], law["source"], law["summary"]])
        haystack_tokens = tokenize_chinese(haystack)
        overlap = sum((2 if len(token) > 1 else 1) for token in query_tokens if token in haystack_tokens)
        ranked.append({
            "law": law,
            "score": overlap + (100 if law["id"] in seed_set else 0),
            "seed": law["id"] in seed_set,
        })
    ranked.sort(key=lambda item: (item["score"], item["seed"]), reverse=True)

    selected = []
    seen = set()
    for item in ranked:
        law = item["law"]
        if law["id"] in seen:
            continue
        if not item["seed"] and item["score"] <= 0 and len(selected) >= len(seed_ids):
            continue
        seen.add(law["id"])
        selected.append({**law, "retrievalScore": item["score"], "seed": item["seed"]})
        if len(selected) >= limit:
            break
    return selected


def semantic_detection(
    clauses: list[str],
    already_detected: set[str],
    laws_by_id: dict[str, dict],
) -> list[dict]:
    risk_by_id = {risk["id"]: risk for risk in RISKS}
    candidates = []
    for risk_id, semantic_regex in SEMANTIC_PATTERNS.items():
        if risk_id in already_detected:
            continue
        base = risk_by_id[risk_id]
        pattern = re.compile(semantic_regex, re.IGNORECASE)
        for clause in clauses:
            match = pattern.search(clause)
            if not match:
                continue
            if base.get("exceptionRegex") and re.search(base["exceptionRegex"], clause, flags=re.IGNORECASE):
                continue
            item = dict(base)
            item["clause"] = clause
            item["matchText"] = match.group(0)
            item["lawItems"] = retrieve_laws(clause, base["lawIds"], laws_by_id, 4)
            item["detectionMode"] = "semantic"
            candidates.append(item)
            break
    return candidates


def split_clauses(text: str) -> list[str]:
    return [part.strip() for part in re.split(r"[\n。；]+", text) if len(part.strip()) > 1]


def deterministic_analysis(text: str, case_type: str, jurisdiction: str, language: str = "zh") -> dict:
    started_at = time.perf_counter()
    jurisdiction_profile = JURISDICTIONS.get(jurisdiction, JURISDICTIONS["全国规则"])
    clauses = split_clauses(text)
    laws_by_id = law_map()
    detected: list[dict] = []

    for risk in RISKS:
        pattern = re.compile(risk["regex"], re.IGNORECASE)
        for clause in clauses:
            match = pattern.search(clause)
            if not match:
                continue
            if risk.get("exceptionRegex") and re.search(risk["exceptionRegex"], clause, flags=re.IGNORECASE):
                continue
            item = dict(risk)
            item["clause"] = clause
            item["matchText"] = match.group(0)
            item["lawItems"] = retrieve_laws(clause, risk["lawIds"], laws_by_id, 4)
            item["detectionMode"] = "deterministic"
            detected.append(item)
            break

    detected.extend(semantic_detection(clauses, {item["id"] for item in detected}, laws_by_id))

    review_items = []
    for rule in REVIEW_RULES:
        if re.search(rule["regex"], text, flags=re.IGNORECASE):
            review_items.append({"id": rule["id"], "title": rule["title"], "detail": rule["detail"]})
    if jurisdiction != "全国规则":
        review_items.append({
            "id": "dynamic_local_policy",
            "title": "地区标准需要核验",
            "detail": f"当前选择“{jurisdiction}”政策模式，最低工资、社保缴费等动态标准必须使用当地最新有效版本。",
        })

    high_count = sum(1 for item in detected if item["severity"] == "high")
    medium_count = sum(1 for item in detected if item["severity"] == "medium")
    has_review = bool(review_items)
    if detected:
        risk_score = min(96, 22 + sum(item["weight"] for item in detected))
        risk_level = "高风险" if risk_score >= 70 else "中风险" if risk_score >= 40 else "低风险"
    elif has_review:
        risk_score = 35
        risk_level = "待核实"
    else:
        risk_score = 6
        risk_level = "低风险"
    unique_law_ids = list(dict.fromkeys(law_id for item in detected for law_id in item["lawIds"]))
    citations = [laws_by_id[law_id] for law_id in unique_law_ids if law_id in laws_by_id]
    citation_coverage = round(sum(1 for item in detected if item["lawItems"]) / len(detected) * 100) if detected else 100
    questions = [item["action"] for item in detected[:6]] or ["请提供正式劳动合同文本并确认薪资、工时、社保和离职条款。"]
    evidence_lines = [f"- {item['title']}：{item['action']}" for item in detected[:8]]
    complaint_lines = [
        "劳动权益事项材料整理草稿",
        "",
        "一、诉求事项",
        "请求核对并依法处理下列合同风险：" + "、".join(item["title"] for item in detected) + "。"
        if detected else "当前未识别到需要生成投诉材料的明显风险。",
        "",
        "二、可提交证据",
        *(evidence_lines or ["- 保存 Offer、合同、岗位说明、考勤和工资记录。"]),
        "",
        "三、办理提示",
        "建议先与用人单位书面沟通；协商不成时，可向用工所在地劳动保障监察机构、人社部门或公共法律服务平台咨询。",
        "",
        "本系统用于竞赛展示、普法教育和材料整理，不替代专业法律意见。",
    ]

    return {
        "caseType": case_type,
        "documentLanguage": language,
        "inputText": text,
        "jurisdiction": jurisdiction,
        "generatedAt": datetime.now().isoformat(timespec="seconds"),
        "jurisdictionProfile": jurisdiction_profile,
        "clauses": clauses,
        "risks": detected,
        "riskScore": risk_score,
        "riskLevel": risk_level,
        "riskHeadline": (
            f"发现 {len(detected)} 项风险，其中 {high_count} 项高风险"
            if detected
            else ("材料信息不足，暂不能给出确定结论" if has_review else "未发现明显高风险条款")
        ),
        "riskDescription": (
            "以下结论来自确定性规则与法源匹配，并已列出需要人工核实的事项。"
            if has_review
            else "以下结论来自确定性规则与法源匹配。涉及地区政策和具体事实的结论仍需人工复核。"
        ),
        "reviewItems": review_items,
        "requiresHumanReview": has_review,
        "citations": citations,
        "citationCoverage": citation_coverage,
        "processingMs": max(1, round((time.perf_counter() - started_at) * 1000)),
        "trace": [
            {"title": "条款切分与事实抽取", "detail": f"识别 {len(clauses)} 个语义片段，抽取合同关键事实。"},
            {"title": "本地法源检索", "detail": f"风险规则关联 {len(citations)} 条核心法源，并结合条款关键词执行本地检索排序。"},
            {"title": "规则引擎研判", "detail": f"执行 {len(RISKS)} 条规则，识别 {high_count} 项高风险、{medium_count} 项中风险。"},
            {"title": "交叉验证与拒答策略", "detail": f"发现 {len(review_items)} 项需要人工核实的事实；无可靠法源或关键信息不足时，系统停止输出确定结论。"},
        ],
        "questions": questions,
        "complaintDraft": "\n".join(complaint_lines),
        "engine": "deterministic-rules",
    }


def extract_json_object(content: str) -> dict:
    content = content.strip()
    if content.startswith("```"):
        content = re.sub(r"^```(?:json)?\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
    start = content.find("{")
    end = content.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("模型未返回 JSON 对象")
    return json.loads(content[start:end + 1])


def recompute_after_enhancement(result: dict) -> None:
    detected = result["risks"]
    high_count = sum(1 for item in detected if item["severity"] == "high")
    medium_count = sum(1 for item in detected if item["severity"] == "medium")
    review_items = result.get("reviewItems", [])
    if detected:
        risk_score = min(96, 22 + sum(item["weight"] for item in detected))
        risk_level = "高风险" if risk_score >= 70 else "中风险" if risk_score >= 40 else "低风险"
        risk_headline = f"发现 {len(detected)} 项风险，其中 {high_count} 项高风险"
        risk_description = "以下结论来自规则、语义与模型候选，并经本地法源绑定；仍需人工复核具体事实。"
    elif review_items:
        risk_score = 35
        risk_level = "待核实"
        risk_headline = "材料信息不足，暂不能给出确定结论"
        risk_description = "当前材料缺少决定性事实，系统停止输出确定结论。"
    else:
        risk_score = 6
        risk_level = "低风险"
        risk_headline = "未发现明显高风险条款"
        risk_description = "当前链路未发现明显风险，但不代表合同不存在争议。"

    law_ids = list(dict.fromkeys(law_id for item in detected for law_id in item["lawIds"]))
    laws_by_id = law_map()
    citations = [laws_by_id[law_id] for law_id in law_ids if law_id in laws_by_id]
    citation_coverage = round(sum(1 for item in detected if item["lawItems"]) / len(detected) * 100) if detected else 100
    questions = [item.get("modelAction") or item["action"] for item in detected[:6]]
    if not questions:
        questions = ["请提供正式劳动合同文本并确认薪资、工时、社保和离职条款。"]
    evidence_lines = [f"- {item['title']}：{item.get('modelAction') or item['action']}" for item in detected[:8]]

    result.update({
        "riskScore": risk_score,
        "riskLevel": risk_level,
        "riskHeadline": risk_headline,
        "riskDescription": risk_description,
        "citations": citations,
        "citationCoverage": citation_coverage,
        "questions": questions,
        "requiresHumanReview": bool(review_items),
        "complaintDraft": "\n".join([
            "劳动权益事项材料整理草稿",
            "",
            "一、诉求事项",
            "请求核对并依法处理下列合同风险：" + "、".join(item["title"] for item in detected) + "。"
            if detected else "当前材料不足以形成确定诉求，请先补充书面合同和用工事实。",
            "",
            "二、可提交证据",
            *(evidence_lines or ["- 保存 Offer、合同、岗位说明、考勤和工资记录。"]),
            "",
            "三、办理提示",
            "建议先与用人单位书面沟通；协商不成时，可向用工所在地劳动保障监察机构、人社部门或公共法律服务平台咨询。",
            "",
            "本系统用于竞赛展示、普法教育和材料整理，不替代专业法律意见。",
        ]),
    })


def enhance_with_llm(result: dict) -> dict:
    api_url = os.environ.get("LLM_API_URL", "").strip()
    api_key = os.environ.get("LLM_API_KEY", "").strip()
    model = os.environ.get("LLM_MODEL", "").strip()
    if not api_url or not model:
        result["engine"] = "rules+semantic+retrieval"
        return result

    allowed_ids = [risk["id"] for risk in RISKS]
    compact_risks = []
    for item in result["risks"]:
        compact_risks.append({
            "id": item["id"],
            "clause": item["clause"],
            "lawItems": [{"source": law["source"], "summary": law["summary"]} for law in item["lawItems"]],
        })

    system_prompt = (
        "你是就业合同候选风险识别器。只能从允许的风险ID中选择，不得创造新ID。"
        "只有原文明确支持时才提出风险；信息不足时不要猜测。"
        "文档可能为中文、英文或日文，但解释和行动建议统一用中文。返回严格 JSON："
        '{"items":[{"id":"风险ID","clause":"原文片段","reason":"不超过120字",'
        '"action":"不超过120字","confidence":0.0}]}。'
    )
    user_payload = {
        "allowedRiskIds": allowed_ids,
        "currentRisks": compact_risks,
        "documentLanguage": result.get("documentLanguage", "zh"),
        "documentText": result.get("inputText", "")[:15000],
    }
    body = {
        "model": model,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
        ],
    }
    request = urllib.request.Request(
        api_url,
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=35) as response:
            payload = json.loads(response.read().decode("utf-8"))
        content = payload["choices"][0]["message"]["content"]
        enhanced = extract_json_object(content)
        risk_by_id = {risk["id"]: risk for risk in RISKS}
        laws_by_id = law_map()
        existing = {risk["id"]: risk for risk in result["risks"]}
        input_text = result.get("inputText", "")

        for update in enhanced.get("items", []):
            risk_id = update.get("id")
            clause = str(update.get("clause", "")).strip()
            if risk_id not in risk_by_id or not clause or clause not in input_text:
                continue
            try:
                model_confidence = float(update.get("confidence", 0))
            except (TypeError, ValueError):
                model_confidence = 0
            if model_confidence < 0.55:
                continue

            if risk_id in existing:
                risk = existing[risk_id]
            else:
                base = risk_by_id[risk_id]
                risk = dict(base)
                risk["clause"] = clause
                risk["matchText"] = clause
                risk["lawItems"] = retrieve_laws(clause, base["lawIds"], laws_by_id, 4)
                risk["detectionMode"] = "llm_candidate"
                risk["confidence"] = min(float(base["confidence"]), model_confidence)
                result["risks"].append(risk)
                existing[risk_id] = risk

            if update.get("reason"):
                risk["modelReason"] = str(update["reason"])[:240]
            if update.get("action"):
                risk["modelAction"] = str(update["action"])[:240]

        result["engine"] = "rules+semantic+retrieval+llm"
        result["trace"].append({
            "title": "大模型候选风险召回",
            "detail": f"模型 {model} 可在允许的风险ID内提出有原文依据的候选；无原文命中、低置信度或非法ID将被丢弃。",
        })
        recompute_after_enhancement(result)
    except (KeyError, ValueError, json.JSONDecodeError, urllib.error.URLError, TimeoutError) as exc:
        result["engine"] = "rules+semantic+retrieval+llm-fallback"
        result["trace"].append({
            "title": "模型调用降级",
            "detail": f"模型服务不可用或返回格式异常，系统已保留规则与语义结果。原因：{type(exc).__name__}。",
        })
    return result


class Handler(BaseHTTPRequestHandler):
    server_version = "VeriWork/0.9"

    def send_json(self, payload: dict, status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def bearer_token(self) -> str | None:
        header = self.headers.get("Authorization", "")
        if header.lower().startswith("bearer "):
            return header[7:].strip()
        return None

    def current_user(self) -> dict | None:
        return resolve_session(self.bearer_token())

    def require_user(self) -> dict | None:
        user = self.current_user()
        if not user:
            self.send_json({"error": "请先登录后再使用研判和文件解析功能"}, 401)
            return None
        return user

    def handle_auth(self, path: str) -> None:
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(content_length).decode("utf-8")) if content_length else {}
            if path == "/api/auth/register":
                user = register_user(str(body.get("username", "")), str(body.get("password", "")))
                token = create_session(user["id"])
                self.send_json({"token": token, "user": user})
                return
            if path == "/api/auth/login":
                user = authenticate_user(str(body.get("username", "")), str(body.get("password", "")))
                if not user:
                    self.send_json({"error": "用户名或密码错误"}, 401)
                    return
                token = create_session(user["id"])
                self.send_json({"token": token, "user": user})
                return
            if path == "/api/auth/logout":
                revoke_session(self.bearer_token())
                self.send_json({"ok": True})
                return
            self.send_json({"error": "not_found"}, 404)
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, 400)
        except Exception as exc:  # noqa: BLE001
            self.send_json({"error": f"认证失败：{type(exc).__name__}"}, 500)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/auth/me":
            user = self.current_user()
            self.send_json({"authenticated": bool(user), "user": user})
            return
        if parsed.path == "/api/admin/stats":
            user = self.current_user()
            if not user or user.get("role") != "admin":
                self.send_json({"error": "需要管理员权限"}, 403)
                return
            self.send_json(admin_stats())
            return
        if parsed.path == "/api/health":
            self.send_json({
                "ok": True,
                "name": "职安盾 VeriWork",
                "llmConfigured": bool(os.environ.get("LLM_API_URL") and os.environ.get("LLM_MODEL")),
                "model": os.environ.get("LLM_MODEL", ""),
                "apiUrlConfigured": bool(os.environ.get("LLM_API_URL")),
                "rules": len(RISKS),
                "laws": len(LAWS),
            })
            return
        if parsed.path == "/api/laws":
            self.send_json({"laws": LAWS})
            return
        self.serve_static(parsed.path)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/auth/"):
            self.handle_auth(parsed.path)
            return
        if parsed.path == "/api/admin/set-role":
            user = self.current_user()
            if not user or user.get("role") != "admin":
                self.send_json({"error": "需要管理员权限"}, 403)
                return
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(content_length).decode("utf-8"))
                target = int(body.get("user_id"))
                role = str(body.get("role", "student"))
                if role not in {"student", "admin"}:
                    raise ValueError("角色只能是 student 或 admin")
                with auth_db() as connection:
                    connection.execute("UPDATE users SET role = ? WHERE id = ?", (role, target))
                    connection.commit()
                self.send_json({"ok": True})
            except (ValueError, json.JSONDecodeError) as exc:
                self.send_json({"error": str(exc)}, 400)
            return
        if parsed.path == "/api/extract":
            self.handle_extract()
            return
        if parsed.path != "/api/analyze":
            self.send_json({"error": "not_found"}, 404)
            return
        user = self.require_user()
        if not user:
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0 or content_length > MAX_BODY:
                raise ValueError("请求体为空或过大")
            body = json.loads(self.rfile.read(content_length).decode("utf-8"))
            text = str(body.get("text", "")).strip()
            if len(text) < 20:
                raise ValueError("文本过短")
            case_type = str(body.get("caseType", "劳动合同"))
            jurisdiction = str(body.get("jurisdiction", "全国规则"))
            language = str(body.get("language", "zh"))
            result = deterministic_analysis(
                text=text,
                case_type=case_type,
                jurisdiction=jurisdiction,
                language=language,
            )
            result = enhance_with_llm(result)
            save_case_record(user, result, case_type, jurisdiction, language)
            self.send_json(result)
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, 400)
        except Exception as exc:  # noqa: BLE001 - 本地服务需要返回可读错误
            self.send_json({"error": f"内部错误：{type(exc).__name__}"}, 500)

    def handle_extract(self) -> None:
        if not self.require_user():
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0 or content_length > MAX_BODY:
                raise ValueError("文件为空或超过12MB")
            body = json.loads(self.rfile.read(content_length).decode("utf-8"))
            filename = str(body.get("filename", "document"))
            language = str(body.get("language", "zh"))
            page_range = str(body.get("pageRange", ""))
            encoded = str(body.get("content_base64", ""))
            if not encoded:
                raise ValueError("缺少文件内容")
            data = base64.b64decode(encoded, validate=True)
            self.send_json(extract_document(filename, data, language=language, page_range=page_range))
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, 400)
        except Exception as exc:  # noqa: BLE001
            self.send_json({"error": f"提取失败：{type(exc).__name__}"}, 500)

    def serve_static(self, request_path: str) -> None:
        relative = unquote(request_path).lstrip("/") or "index.html"
        target = (BASE_DIR / relative).resolve()
        if target != BASE_DIR and BASE_DIR not in target.parents:
            self.send_error(403)
            return
        if target.is_dir():
            target = target / "index.html"
        if not target.exists() or not target.is_file():
            self.send_error(404)
            return

        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in {"application/javascript", "application/json"}:
            content_type += "; charset=utf-8"
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stdout.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))
        sys.stdout.flush()


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    llm_state = "已配置" if os.environ.get("LLM_API_URL") and os.environ.get("LLM_MODEL") else "未配置，使用本地规则链路"
    print("职安盾 VeriWork 已启动")
    print(f"地址: http://{HOST}:{PORT}")
    print(f"大模型: {llm_state}")
    print("按 Ctrl+C 停止服务")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n服务已停止")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
