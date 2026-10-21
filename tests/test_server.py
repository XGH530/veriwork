import base64
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime
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

    def test_all_frontend_jurisdictions_have_backend_profiles(self):
        expected = ["全国规则", "北京", "上海", "广东", "深圳", "重庆", "四川", "贵州", "云南", "陕西", "湖北", "湖南", "广西"]
        for name in expected:
            self.assertIn(name, server.JURISDICTIONS)
        result = server.deterministic_analysis(
            "实习补贴为140元/天，甲方安排标准工时并允许延长工作时间。",
            "实习协议",
            "重庆",
        )
        self.assertEqual("重庆", result["jurisdictionProfile"]["id"])
        self.assertEqual("最低工资已核验", result["jurisdictionProfile"]["status"])
        self.assertIn("2330", result["jurisdictionProfile"]["note"])

    def test_single_character_username_is_allowed(self):
        user = server.register_user("a", "Password!2345")
        self.assertEqual("a", user["username"])
        with self.assertRaises(ValueError):
            server.register_user("   ", "Password!2345")

    def test_email_challenge_round_trip(self):
        username = f"emailtest_{os.getpid()}"
        user = server.register_user(username, "EmailTest!2345", email="tester@example.com")
        self.assertEqual("tester@example.com", user["email"])
        challenge_id, code = server.create_email_challenge(user["id"], "verify_email")
        latest = server.latest_email_challenge(user["id"], "verify_email")
        ttl = (datetime.fromisoformat(latest["expires_at"]) - datetime.fromisoformat(latest["created_at"])).total_seconds()
        self.assertEqual(120, ttl)
        with self.assertRaisesRegex(ValueError, "过于频繁"):
            server.create_email_challenge(user["id"], "verify_email")
        self.assertEqual(user["id"], server.verify_email_challenge(challenge_id, code, "verify_email"))
        with self.assertRaises(ValueError):
            server.verify_email_challenge(challenge_id, code, "verify_email")

    def test_failed_auth_email_does_not_block_resend(self):
        username = f"emailfail_{os.getpid()}"
        user = server.register_user(username, "EmailFail!2345", email="fail@example.com")
        with patch("server.send_email_message", side_effect=RuntimeError("smtp unavailable")):
            with self.assertRaises(RuntimeError):
                server.send_auth_code(user, "admin_2fa", "fail@example.com")
        self.assertIsNone(server.latest_email_challenge(user["id"], "admin_2fa"))
        with patch("server.send_email_message", return_value=None):
            challenge_id, code = server.send_auth_code(user, "admin_2fa", "fail@example.com")
        self.assertGreater(challenge_id, 0)
        self.assertEqual(user["id"], server.verify_email_challenge(challenge_id, code, "admin_2fa", user["id"]))

    def test_each_defined_risk_has_legal_basis(self):
        for risk in server.RISKS:
            self.assertTrue(risk["lawIds"], risk["id"])
            self.assertTrue(all(law_id in server.law_map() for law_id in risk["lawIds"]), risk["id"])


class TripartiteAgreementTests(unittest.TestCase):
    def tripartite_text(self) -> str:
        return """全国普通高等学校毕业生就业协议书（三方协议）
甲方（用人单位）名称：深圳某科技有限公司
乙方（毕业生）姓名：张某
丙方（学校）名称：示例学院
第一条 乙方到甲方报到时间为2026年7月1日，工作地点为深圳市南山区，岗位为测试工程师。
第二条 试用期六个月，月工资5000元，岗位职责另行约定，薪资以实际发放为准。
第三条 甲方有权根据经营需要调整岗位；乙方未满服务期离职的，应支付违约金20000元。
第四条 甲方不负责档案和户口接收，档案转回原籍，户口自行处理。
第五条 本三方协议代替劳动合同，双方以本协议为准。
甲方（盖章）： 乙方（签字）： 丙方（学校）（盖章）：
"""

    def test_tripartite_is_identified_and_facts_are_extracted(self):
        result = server.deterministic_analysis(self.tripartite_text(), "劳动合同", "深圳")
        self.assertEqual("三方协议", result["documentType"])
        self.assertEqual("劳动合同", result["selectedCaseType"])
        facts = result["facts"]
        self.assertTrue(facts["isTripartite"])
        self.assertEqual("深圳某科技有限公司", facts["partyA"])
        self.assertEqual("示例学院", facts["school"])
        self.assertEqual("测试工程师", facts["position"])
        self.assertEqual("深圳市南山区", facts["workLocation"])
        self.assertEqual("深圳", facts["workCity"])
        self.assertEqual("2026年7月1日", facts["reportDeadline"])
        self.assertEqual("5000", facts["salary"])
        self.assertEqual("六个月", facts["probation"])
        self.assertEqual("20000", facts["liquidatedDamages"])
        self.assertEqual("深圳", facts["suggestedJurisdiction"])

    def test_tripartite_risks_and_review_items(self):
        result = server.deterministic_analysis(self.tripartite_text(), "劳动合同", "深圳")
        ids = {item["id"] for item in result["risks"]}
        self.assertTrue({
            "tripartite_not_labor_contract",
            "tripartite_penalty_overbroad",
            "tripartite_blank_terms",
            "tripartite_archive_household",
            "tripartite_service_period",
        }.issubset(ids))
        review_ids = {item["id"] for item in result["reviewItems"]}
        self.assertIn("tripartite_dispute_clause", review_ids)
        self.assertIn("tripartite_archive_missing", review_ids)
        self.assertIn("tripartite_household_missing", review_ids)
        self.assertTrue(result["requiresHumanReview"])
        self.assertEqual("高风险", result["riskLevel"])
        self.assertGreater(result["analysisStats"]["ruleHits"], 0)

    def test_image_extraction_returns_ocr_metadata(self):
        png = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Zl1sAAAAASUVORK5CYII="
        )
        with patch("server.ocr_image_text", return_value="三方协议\n甲方：深圳某科技有限公司\n乙方：张某\n丙方：示例学院"):
            result = server.extract_document("chat.png", png, language="zh")
        self.assertTrue(result["ocr"])
        self.assertEqual("chi_sim+eng", result["ocrLanguage"])
        self.assertGreaterEqual(result["ocrMs"], 1)
        self.assertEqual(1, result["pageCount"])
        self.assertIn("三方协议", result["text"])


class InternshipAgreementTests(unittest.TestCase):
    def internship_text(self) -> str:
        return """实习协议
湖南某人才服务有限公司（以下简称“甲方”），同意 示例学院 学校学生 张某，在甲方实习。双方协商一致，共同订立本协议。
第一条 乙方自 2026 年 6 月 16 日至 2026 年 12 月 15 日，被派驻至深圳市某科技有限公司，在测试部门实习，具体实习内容另行规定。
第二条 经双方协商，乙方的工作时间执行标准工时制，乙方应按规定时间准时上班。
第三条 乙方同意，甲方因生产（工作）需要，可依法安排乙方延长工作时间、休息日或节假日加班。
第五条 乙方同意按实际出勤日计薪，实习补贴为：140 元/天。乙方绩效津贴随乙方工作岗位的调整和工作表现变化。甲方委托其依法设立的湖南某人才服务有限公司湘江新区分公司作为薪酬发放主体，按月发放实习补贴。承诺入职后 10 个工作日内不会自动离职，如离职则工资不予核发。
第六条 甲方支付乙方的劳动报酬为税前收入，乙方同意甲方有权根据规定扣除有关款项并代缴。
第九条 乙方应对在甲方实习期间所掌握的所有甲方认为具有保密性质的信息进行最高限度的保密，在本协议终止后继续有效。
第十二条 乙方违反本协议规定的，甲方有权立即解除劳动合同并不支付赔偿金。
"""

    def test_internship_is_identified_and_facts_are_extracted(self):
        text = self.internship_text()
        result = server.deterministic_analysis(
            text,
            "劳动合同",
            "全国规则",
            source_pages=[{"page": 1, "text": text}],
        )
        self.assertEqual("实习协议", result["documentType"])
        self.assertEqual("劳动合同", result["selectedCaseType"])
        facts = result["facts"]
        self.assertEqual("湖南某人才服务有限公司", facts["partyA"])
        self.assertEqual("示例学院", facts["school"])
        self.assertEqual("深圳市某科技有限公司", facts["actualEmployer"])
        self.assertEqual("测试", facts["position"])
        self.assertEqual("2026年6月16日", facts["startDate"])
        self.assertEqual("2026年12月15日", facts["endDate"])
        self.assertEqual("140", facts["dailyPay"])
        self.assertEqual(17.5, facts["hourlyEquivalentAt8h"])
        self.assertEqual("深圳", facts["suggestedJurisdiction"])
        self.assertFalse(facts["hasAccidentInsurance"])
        self.assertFalse(facts["hasDisputeClause"])
        self.assertFalse(facts["hasJobAttachment"])

    def test_internship_risks_and_locations(self):
        text = self.internship_text()
        result = server.deterministic_analysis(
            text,
            "劳动合同",
            "全国规则",
            source_pages=[{"page": 1, "text": text}],
        )
        ids = {item["id"] for item in result["risks"]}
        self.assertTrue({
            "internship_wage_forfeit",
            "third_party_payor",
            "overtime_without_compensation",
            "performance_unilateral",
            "broad_deduction",
            "confidentiality_overbroad",
            "unilateral_termination",
            "internship_insurance_missing",
            "internship_relationship_mismatch",
        }.issubset(ids))
        self.assertEqual("高风险", result["riskLevel"])
        self.assertGreaterEqual(result["riskScore"], 78)
        self.assertGreater(result["analysisStats"]["ruleHits"], 0)
        self.assertGreater(result["analysisStats"]["factHits"], 0)
        self.assertTrue(result["requiresHumanReview"])
        self.assertTrue(any(item.get("location", {}).get("clause") not in ("", "未编号条款") for item in result["risks"]))
        wage_risk = next(item for item in result["risks"] if item["id"] == "internship_wage_forfeit")
        self.assertEqual(1, wage_risk["location"]["page"])

    def test_internship_report_contains_required_sections(self):
        text = self.internship_text()
        result = server.deterministic_analysis(
            text,
            "劳动合同",
            "全国规则",
            source_pages=[{"page": 1, "text": text}],
            source_document={
                "filename": "实习协议-脱敏.pdf",
                "format": "pdf",
                "chars": len(text),
                "sizeBytes": 2048,
                "sha256": "a" * 64,
                "pageCount": 1,
            },
        )
        case = {
            "id": 12,
            "case_type": "劳动合同",
            "jurisdiction": "全国规则",
            "document_language": "zh",
            "risk_score": result["riskScore"],
            "risk_level": result["riskLevel"],
            "result": result,
        }
        html = server.build_report_html({"username": "测试用户"}, case, [])
        for section in ("就业材料研判报告", "基本事实", "风险结论", "待核实事项", "可信研判轨迹", "证据文件清单", "后续行动", "原始文件"):
            self.assertIn(section, html)
        self.assertIn("实习协议-脱敏.pdf", html)
        pdf = server.build_report_pdf({"username": "测试用户"}, case, [])
        if pdf is not None:
            self.assertTrue(pdf.startswith(b"%PDF-"))
            self.assertGreater(len(pdf), 1000)


if __name__ == "__main__":
    unittest.main()
