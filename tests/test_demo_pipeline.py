# -*- coding: utf-8 -*-
"""
KIỂM THỬ TÍCH HỢP API PIPELINE CTI-SENTINEL + AGENT SKILLS + BENCHMARK
Đảm bảo các route SAST và Network Sentinel cũ đã được loại bỏ hoàn toàn.
"""
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from fastapi.testclient import TestClient
from src.automation.server import app

client = TestClient(app)


def test_sast_and_hardcoded_network_routes_removed():
    res_sast = client.post("/api/sast/scan", json={"code": "print(1)", "language": "python"})
    assert res_sast.status_code == 404

    res_net = client.get("/api/network-intel/feeds")
    assert res_net.status_code == 404


def test_full_cti_agent_skill_pipeline():
    res_status = client.get("/api/status")
    assert res_status.status_code == 200
    assert "ollama_health" in res_status.json()

    res_llm = client.get("/api/llm/status")
    assert res_llm.status_code == 200
    assert "configured_model" in res_llm.json()

    # Phân tích bài viết tùy chỉnh ở chế độ regex_only để test nhanh deterministic trong CI
    res_analyze = client.post(
        "/api/analyze",
        json={
            "custom_title": "Unit Test Lumma Stealer Advisory",
            "custom_text": (
                "Analysts tracked Lumma Stealer connecting to 91.240.118.172 "
                "and cdn-verify-human.site with payload SHA256 "
                "d8e8fca2dc64a589e472659021e90ef830026f83d9e4871b5853b0068579cf44 "
                "exploiting CVE-2024-3400."
            ),
            "mode": "regex_only",
        },
    )
    assert res_analyze.status_code == 200, res_analyze.text
    payload = res_analyze.json()
    report = payload["report"]
    skill = payload["agent_skill"]

    assert report["analysis_mode"] == "regex_only"
    assert "91.240.118.172" in report["iocs_summary"]["ips"]
    assert skill["execution_status"] == "SANDBOX_VERIFIED"
    assert skill["ast_safe"] is True

    # Kiểm chứng endpoint Sandbox Verify
    res_verify = client.post("/api/skills/verify", json=skill)
    assert res_verify.status_code == 200
    assert res_verify.json()["verification"]["sandbox_verified"] is True

    # Kiểm tra tải file Python Skill
    report_id = report["report_id"]
    res_dl = client.get(f"/api/download/{report_id}/skill")
    assert res_dl.status_code == 200
    assert "def execute_cti_defense_skill" in res_dl.text

    # Kiểm tra trang chủ Dashboard load HTTP 200
    res_web = client.get("/")
    assert res_web.status_code == 200
    assert "CTI-SENTINEL" in res_web.text
