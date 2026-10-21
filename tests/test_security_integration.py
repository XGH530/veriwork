import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class SecurityIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.db_path = Path(cls.temp_dir.name) / "veriwork-test.db"
        cls.port = free_port()
        env = os.environ.copy()
        env.update({
            "HOST": "127.0.0.1",
            "PORT": str(cls.port),
            "VERIWORK_DB_PATH": str(cls.db_path),
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD": "TestAdmin!2345",
            "REVIEW_ADMIN_USERNAME": "reviewer_admin",
            "REVIEW_ADMIN_PASSWORD": "ReviewerAdmin!2026",
            "DEMO_PASSWORD": "",
            "LLM_API_URL": "",
            "LLM_API_KEY": "",
            "LLM_MODEL": "",
            "SESSION_COOKIE_PATH": "/",
            "SESSION_COOKIE_SECURE": "0",
        })
        cls.process = subprocess.Popen(
            [sys.executable, str(ROOT / "server.py")],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        cls.base = f"http://127.0.0.1:{cls.port}"
        for _ in range(60):
            try:
                with urllib.request.urlopen(cls.base + "/api/health", timeout=1) as response:
                    if response.status == 200:
                        break
            except Exception:
                time.sleep(0.1)
        else:
            output = cls.process.stdout.read() if cls.process.stdout else ""
            raise RuntimeError("server did not start: " + output)

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        try:
            cls.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.process.kill()
        cls.temp_dir.cleanup()

    def opener(self):
        jar = CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        opener.cookie_jar = jar
        return opener

    def request(self, opener, path, payload=None, method=None):
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            self.base + path,
            data=data,
            method=method or ("POST" if data is not None else "GET"),
            headers={"Content-Type": "application/json"} if data is not None else {},
        )
        return opener.open(request, timeout=10)

    def test_sensitive_files_are_not_served(self):
        for path in ("/data/veriwork.db", "/.env", "/server.py", "/requirements.txt", "/README.md", "/assets/CREDITS.md"):
            with self.subTest(path=path):
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    urllib.request.urlopen(self.base + path, timeout=5)
                self.assertEqual(404, caught.exception.code)
        for path in ("/", "/styles.css", "/app.js", "/assets/logo-mark.svg"):
            with self.subTest(path=path):
                with urllib.request.urlopen(self.base + path, timeout=5) as response:
                    self.assertEqual(200, response.status)

    def test_business_api_requires_login(self):
        for path in ("/api/laws", "/api/cases", "/api/evidence"):
            with self.subTest(path=path):
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    urllib.request.urlopen(self.base + path, timeout=5)
                self.assertEqual(401, caught.exception.code)

    def test_cookie_session_hashed_in_database_and_role_boundary(self):
        student = self.opener()
        with self.request(student, "/api/auth/register", {"username": "student01", "password": "Student!2345"}) as response:
            body = json.loads(response.read().decode("utf-8"))
            set_cookie = response.headers.get("Set-Cookie", "")
        self.assertEqual("student", body["user"]["role"])
        self.assertNotIn("token", body)
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("SameSite=Lax", set_cookie)

        with self.request(student, "/api/auth/me") as response:
            self.assertTrue(json.loads(response.read().decode("utf-8"))["authenticated"])

        with self.request(student, "/api/analyze", {
            "text": "试用期工资为转正工资的60%，员工自愿放弃社会保险，公司收取2000元保证金。",
            "caseType": "劳动合同",
            "jurisdiction": "全国规则",
            "language": "zh",
        }) as response:
            result = json.loads(response.read().decode("utf-8"))
        self.assertTrue(result["risks"])

        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.request(student, "/api/admin/stats")
        self.assertEqual(403, caught.exception.code)

        raw_tokens = []
        for cookie in student.cookie_jar:
            if cookie.name == "veriwork_session":
                raw_tokens.append(cookie.value)
        self.assertEqual(1, len(raw_tokens))
        with sqlite3.connect(self.db_path) as connection:
            stored = connection.execute("SELECT token FROM sessions").fetchall()
        self.assertTrue(stored)
        self.assertTrue(all(len(row[0]) == 64 for row in stored))
        self.assertNotIn(raw_tokens[0], {row[0] for row in stored})

        with self.request(student, "/api/auth/logout", {}) as response:
            self.assertEqual(200, response.status)
        with self.request(student, "/api/auth/me") as response:
            self.assertFalse(json.loads(response.read().decode("utf-8"))["authenticated"])

    def test_reviewer_admin_is_read_only_and_skips_email_code(self):
        reviewer = self.opener()
        with self.request(reviewer, "/api/auth/login", {
            "username": "reviewer_admin",
            "password": "ReviewerAdmin!2026",
        }) as response:
            body = json.loads(response.read().decode("utf-8"))
        self.assertEqual("reviewer_admin", body["user"]["role"])
        self.assertFalse(body.get("requires2fa", False))
        with self.request(reviewer, "/api/admin/stats") as response:
            self.assertEqual(200, response.status)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.request(reviewer, "/api/admin/set-status", {"user_id": 1, "status": "disabled"})
        self.assertEqual(403, caught.exception.code)

    def test_admin_login_and_login_rate_limit(self):
        admin = self.opener()
        with self.request(admin, "/api/auth/login", {"username": "admin", "password": "TestAdmin!2345"}) as response:
            body = json.loads(response.read().decode("utf-8"))
        self.assertEqual("admin", body["user"]["role"])
        with self.request(admin, "/api/admin/stats") as response:
            self.assertEqual(200, response.status)

        attacker = self.opener()
        for _ in range(5):
            with self.assertRaises(urllib.error.HTTPError) as caught:
                self.request(attacker, "/api/auth/login", {"username": "nobody", "password": "wrong-pass"})
            self.assertEqual(401, caught.exception.code)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.request(attacker, "/api/auth/login", {"username": "nobody", "password": "wrong-pass"})
        self.assertEqual(429, caught.exception.code)


if __name__ == "__main__":
    unittest.main()

