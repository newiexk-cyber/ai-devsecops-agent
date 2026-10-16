# -*- coding: utf-8 -*-
"""
KIỂM THỬ TÍCH HỢP TOÀN BỘ PIPELINE CỦA WEB DEMO
"""
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
from fastapi.testclient import TestClient
from src.automation.server import app

client = TestClient(app)

def test_full_pipeline():
    print("[1/5] Kiểm tra API Status...")
    res = client.get("/api/status")
    assert res.status_code == 200, f"Status failed: {res.text}"
    status_data = res.json()
    print(f" -> OK: {status_data['stats']}")

    print("[2/5] Kiểm tra API Feeds...")
    res = client.get("/api/feeds")
    assert res.status_code == 200, f"Feeds failed: {res.text}"
    feeds_data = res.json()
    assert len(feeds_data["articles"]) > 0, "No articles found"
    first_art = feeds_data["articles"][0]
    print(f" -> OK: Tìm thấy {len(feeds_data['articles'])} bài báo. Bài 1: {first_art['title'][:40]}...")

    print("[3/5] Kích hoạt AI Agent ReAct Loop qua /api/analyze...")
    payload = {"article_id": first_art["id"]}
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 200, f"Analyze failed: {res.text}"
    report_data = res.json()["report"]
    report_id = report_data["report_id"]
    print(f" -> OK: Đã sinh báo cáo {report_id}")
    print(f" -> IoCs bóc tách: {len(report_data['enriched_iocs'])} chỉ số")
    print(f" -> MITRE ATT&CK: {[m['technique_id'] for m in report_data['mitre_attack_matrix']]}")
    print(f" -> Sigma rule: {len(report_data['defensive_rules']['sigma_rule'])} bytes")
    print(f" -> YARA rule: {len(report_data['defensive_rules']['yara_rule'])} bytes")

    print("[4/5] Kiểm tra tải file quy tắc phòng thủ...")
    res_sigma = client.get(f"/api/download/{report_id}/sigma")
    assert res_sigma.status_code == 200, "Download sigma failed"
    assert "CTI-Sentinel" in res_sigma.text, "Sigma rule content mismatch"
    print(" -> OK: Tải file Sigma rule thành công")

    print("[5/5] Kiểm tra Web Dashboard HTML...")
    res_web = client.get("/")
    assert res_web.status_code == 200, "Web dashboard failed"
    assert "CTI-SENTINEL" in res_web.text, "Web title mismatch"
    print(" -> OK: Web Dashboard load thành công (HTTP 200)")

    print("\n🎉 TẤT CẢ 5 BƯỚC KIỂM THỬ TÍCH HỢP ĐỀU THÀNH CÔNG VƯỢT TRỘI!")

if __name__ == "__main__":
    test_full_pipeline()
