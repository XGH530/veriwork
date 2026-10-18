import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

TEST_DB = Path(tempfile.gettempdir()) / f"veriwork-unit-{os.getpid()}.db"
os.environ.setdefault("ADMIN_PASSWORD", "TestAdmin!2345")
os.environ.setdefault("DEMO_PASSWORD", "TestDemo!2345")
os.environ.setdefault("VERIWORK_DB_PATH", str(TEST_DB))
os.environ.setdefault("VERIWORK_EVIDENCE_DIR", str(TEST_DB.parent / f"veriwork-unit-evidence-{os.getpid()}"))

import server  # noqa: E402


class RuleEngineTests(unittest.TestCase):
    def test_risky_contract_detects_expected_rules(self):
        text = "试用期工资为转正工资的60%。员工自愿放弃社会保险，入职需缴纳2000元设备保证金。"
        result = server.deterministic_analysis(text, "劳动合同", "北京")
        ids = {item["id"] for item in result["risks"]}
        self.assertTrue({"probation_salary", "no_social_insurance", "employment_deposit"}.issubset(ids))
        self.assertEqual("高风险", result["riskLevel"])
        self.assertEqual("北京", result["jurisdictionProfile"]["id"])
        self.assertTrue(all(item["lawItems"] for item in result["risks"]))
        self.assertGreaterEqual(result["processingMs"], 1)

    def test_safe_clause_does_not_trigger_high_risk(self):
        text = "合同期限三年，试用期三个月，试用期工资为约定工资的85%，公司依法缴纳社会保险，工资每月十五日前支付。"
        result = server.deterministic_analysis(text, "劳动合同", "全国规则")
        high_risks = [item for item in result["risks"] if item["severity"] == "high"]
        self.assertEqual([], high_risks)

    def test_semantic_synonyms_are_detected(self):
        examples = {
            "被录用后需先交800元工装费才能上岗": "employment_deposit",
            "公司要求上交毕业证原件代为保管": "employment_deposit",
            "为获得岗位，需要先办理1万元技能提升贷款": "training_loan",
            "试用期按合同工资的78%结算": "probation_salary",
            "合同期限一年，试用期六个月": "probation_duration",
        }
        for text, expected in examples.items():
            with self.subTest(text=text):
                result = server.deterministic_analysis(text, "劳动合同", "全国规则")
                self.assertIn(expected, {item["id"] for item in result["risks"]})

    def test_review_and_negation_boundaries(self):
        review = server.deterministic_analysis("项目合作人员报酬按阶段结算，合作期限和社保尚未确定。", "劳动合同", "全国规则")
        self.assertTrue(review["requiresHumanReview"])

        safe = server.deterministic_analysis("公司承诺试用期工资不低于正式工资的80%，并依法缴纳社保。", "劳动合同", "全国规则")
        self.assertNotIn("probation_salary", {item["id"] for item in safe["risks"]})

    def test_llm_can_add_only_grounded_allowed_candidates(self):
        text = "公司要求上交毕业证原件，由人事保管。"
        result = server.deterministic_analysis(text, "劳动合同", "全国规则")
        model_content = json.dumps({
            "items": [{
                "id": "employment_deposit",
                "clause": "公司要求上交毕业证原件",
                "reason": "扣押证件存在风险",
                "action": "拒绝上交原件并保留沟通记录",
                "confidence": 0.9,
            }]
        }, ensure_ascii=False)
        response_payload = json.dumps({"choices": [{"message": {"content": model_content}}]}, ensure_ascii=False).encode("utf-8")

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return response_payload

        with patch.dict(os.environ, {"LLM_API_URL": "https://example.test/v1/chat/completions", "LLM_API_KEY": "test", "LLM_MODEL": "mock-model"}, clear=False), patch("urllib.request.urlopen", return_value=FakeResponse()):
            enhanced = server.enhance_with_llm(result)

        ids = {item["id"] for item in enhanced["risks"]}
        self.assertIn("employment_deposit", ids)
        self.assertEqual("rules+semantic+retrieval+llm", enhanced["engine"])
        self.assertTrue(enhanced["requiresHumanReview"] is False)

    def test_llm_payload_redacts_personal_data_and_restores_source_clause(self):
        text = "联系人手机13800138000，邮箱test@example.com，身份证110101199001011234，公司要求上交毕业证原件。"
        result = server.deterministic_analysis(text, "劳动合同", "全国规则")
        candidate = "联系人手机[手机号]，邮箱[邮箱]，身份证[身份证号]，公司要求上交毕业证原件"
        self.assertEqual(candidate.replace("[手机号]", "13800138000").replace("[邮箱]", "test@example.com").replace("[身份证号]", "110101199001011234"), server.ground_model_clause(candidate, text))

        captured = {}
        model_content = json.dumps({
            "items": [{
                "id": "employment_deposit",
                "clause": candidate,
                "reason": "联系人13800138000要求扣押证件",
                "action": "联系test@example.com并保留证据",
                "confidence": 0.9,
            }]
        }, ensure_ascii=False)
        response_payload = json.dumps({"choices": [{"message": {"content": model_content}}]}, ensure_ascii=False).encode("utf-8")

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return response_payload

        def fake_urlopen(request, timeout=0):
            captured["payload"] = request.data.decode("utf-8")
            return FakeResponse()

        with patch.dict(os.environ, {"LLM_API_URL": "https://example.test/v1/chat/completions", "LLM_API_KEY": "test", "LLM_MODEL": "mock-model"}, clear=False), patch("urllib.request.urlopen", side_effect=fake_urlopen):
            enhanced = server.enhance_with_llm(result)

        self.assertNotIn("13800138000", captured["payload"])
        self.assertNotIn("test@example.com", captured["payload"])
        self.assertNotIn("110101199001011234", captured["payload"])
        deposit = next(item for item in enhanced["risks"] if item["id"] == "employment_deposit")
        self.assertNotIn("13800138000", deposit.get("modelReason", ""))
        self.assertNotIn("test@example.com", deposit.get("modelAction", ""))

    def test_each_defined_risk_has_legal_basis(self):
        for risk in server.RISKS:
            self.assertTrue(risk["lawIds"], risk["id"])
            self.assertTrue(all(law_id in server.law_map() for law_id in risk["lawIds"]), risk["id"])


if __name__ == "__main__":
    unittest.main()
