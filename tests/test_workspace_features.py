import base64
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from http.cookiejar import CookieJar
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class WorkspaceFeatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.db_path = Path(cls.temp_dir.name) / "workspace.db"
        cls.evidence_dir = Path(cls.temp_dir.name) / "evidence"
        cls.port = free_port()
        env = os.environ.copy()
        env.update({
            "HOST": "127.0.0.1",
            "PORT": str(cls.port),
            "VERIWORK_DB_PATH": str(cls.db_path),
            "VERIWORK_EVIDENCE_DIR": str(cls.evidence_dir),
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD": "AdminFeature!2345",
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
        for _ in range(80):
            try:
                with urllib.request.urlopen(cls.base + "/api/health", timeout=1) as response:
                    if response.status == 200:
                        break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("server did not start")

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
        return opener.open(request, timeout=15)

    def test_complete_user_and_admin_lifecycle(self):
        user = self.opener()
        with self.request(user, "/api/auth/register", {"username": "flowuser", "password": "FlowUser!2345"}) as response:
            self.assertEqual("student", json.loads(response.read())["user"]["role"])

        with self.request(user, "/api/analyze", {
            "text": "试用期工资为转正工资的60%，员工自愿放弃社会保险，公司要求先交2000元保证金。",
            "caseType": "劳动合同",
            "jurisdiction": "全国规则",
            "language": "zh",
        }) as response:
            analysis = json.loads(response.read())
        case_id = analysis["caseId"]
        self.assertGreater(case_id, 0)

        with self.request(user, "/api/cases") as response:
            cases = json.loads(response.read())["cases"]
        self.assertEqual(1, len(cases))
        self.assertEqual(case_id, cases[0]["id"])

        with self.request(user, f"/api/cases/{case_id}") as response:
            detail = json.loads(response.read())["case"]
        self.assertTrue(detail["result"]["risks"])

        with self.request(user, f"/api/cases/{case_id}/report") as response:
            report = response.read().decode("utf-8")
            self.assertIn("text/html", response.headers.get("Content-Type", ""))
        self.assertIn("就业合同研判报告", report)
        self.assertIn("VW-", report)

        with self.request(user, f"/api/cases/{case_id}/report.pdf") as response:
            pdf = response.read()
            self.assertIn("application/pdf", response.headers.get("Content-Type", ""))
        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertGreater(len(pdf), 1000)

        evidence_bytes = "工资流水与入职通知".encode("utf-8")
        with self.request(user, "/api/evidence/upload", {
            "filename": "工资流水.txt",
            "caseId": case_id,
            "content_base64": base64.b64encode(evidence_bytes).decode("ascii"),
        }) as response:
            evidence = json.loads(response.read())["evidence"]
        evidence_id = evidence["id"]
        self.assertEqual(64, len(evidence["sha256"]))

        with self.request(user, "/api/evidence") as response:
            evidence_list = json.loads(response.read())["evidence"]
        self.assertEqual(1, len(evidence_list))

        with self.request(user, f"/api/evidence/{evidence_id}/download") as response:
            self.assertEqual(evidence_bytes, response.read())

        with self.request(user, "/api/evidence/package") as response:
            package = response.read()
        with zipfile.ZipFile(io.BytesIO(package)) as archive:
            self.assertIn("manifest.json", archive.namelist())
            manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
            self.assertEqual("flowuser", manifest["user"]["username"])

        with self.request(user, "/api/cases/status", {"case_id": case_id, "status": "resolved"}) as response:
            self.assertTrue(json.loads(response.read())["ok"])
        with self.request(user, f"/api/cases/{case_id}") as response:
            self.assertEqual("resolved", json.loads(response.read())["case"]["status"])

        with self.request(user, "/api/cases/delete", {"case_id": case_id}) as response:
            self.assertTrue(json.loads(response.read())["ok"])
        with self.request(user, "/api/evidence") as response:
            self.assertEqual([], json.loads(response.read())["evidence"])

        with self.request(user, "/api/auth/change-password", {
            "currentPassword": "FlowUser!2345",
            "newPassword": "FlowUser!6789",
        }) as response:
            self.assertTrue(json.loads(response.read())["ok"])
        old_login = self.opener()
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.request(old_login, "/api/auth/login", {"username": "flowuser", "password": "FlowUser!2345"})
        self.assertEqual(401, caught.exception.code)
        new_login = self.opener()
        with self.request(new_login, "/api/auth/login", {"username": "flowuser", "password": "FlowUser!6789"}) as response:
            self.assertEqual("student", json.loads(response.read())["user"]["role"])

        with self.request(new_login, "/api/auth/export", {"password": "FlowUser!6789"}) as response:
            exported = json.loads(response.read())
        self.assertEqual("flowuser", exported["user"]["username"])

        admin = self.opener()
        with self.request(admin, "/api/auth/login", {"username": "admin", "password": "AdminFeature!2345"}) as response:
            self.assertEqual("admin", json.loads(response.read())["user"]["role"])
        with self.request(admin, "/api/admin/stats") as response:
            stats = json.loads(response.read())
        self.assertGreaterEqual(stats["userCount"], 2)
        self.assertTrue(stats["auditLogs"])

        with self.request(admin, "/api/admin/set-status", {"user_id": 2, "status": "disabled"}) as response:
            self.assertTrue(json.loads(response.read())["ok"])
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.request(new_login, "/api/cases")
        self.assertEqual(401, caught.exception.code)

        with self.request(admin, "/api/admin/set-status", {"user_id": 2, "status": "active"}) as response:
            self.assertTrue(json.loads(response.read())["ok"])
        with self.request(admin, "/api/admin/reset-password", {"user_id": 2}) as response:
            temporary = json.loads(response.read())["temporaryPassword"]
        reset_login = self.opener()
        with self.request(reset_login, "/api/auth/login", {"username": "flowuser", "password": temporary}) as response:
            self.assertTrue(json.loads(response.read())["user"]["id"])

        delete_user = self.opener()
        with self.request(delete_user, "/api/auth/register", {"username": "deleteuser", "password": "DeleteUser!2345"}) as response:
            delete_user_id = json.loads(response.read())["user"]["id"]
        with self.request(delete_user, "/api/auth/delete", {"confirm": "deleteuser", "password": "DeleteUser!2345"}) as response:
            self.assertTrue(json.loads(response.read())["ok"])
        with self.request(delete_user, "/api/auth/me") as response:
            self.assertFalse(json.loads(response.read())["authenticated"])


if __name__ == "__main__":
    unittest.main()
