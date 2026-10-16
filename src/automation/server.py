# -*- coding: utf-8 -*-
"""
FASTAPI SERVER & REST API (LÂM)
Cung cấp API điều khiển pipeline CTI, kích hoạt tác tử AI và phục vụ giao diện Web Dashboard.
"""
import os
import uuid
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Body
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.automation.storage.database import (
    init_database, get_all_articles, get_article_by_id, mark_article_analyzed,
    save_threat_report, get_all_reports, get_report_by_id, get_system_stats
)
from src.automation.collectors.rss_collector import fetch_rss_feeds
from src.automation.collectors.cisa_collector import fetch_cisa_kev
from src.core.ioc_extractor import extract_iocs_from_text
from src.core.mitre_mapper import map_mitre_techniques
from src.security.enrichment_service import enrich_ioc_list
from src.core.rule_generator import (
    generate_sigma_rule, generate_yara_rule, generate_firewall_blocklist, generate_stix_bundle
)

# Khởi tạo DB khi khởi động
init_database()

app = FastAPI(
    title="CTI-Sentinel API",
    description="REST API cho Hệ thống Tình báo Mạng và Sinh Quy tắc Phòng thủ AI Agent",
    version="1.0.0"
)

# Bật CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    article_id: Optional[int] = None
    custom_title: Optional[str] = None
    custom_text: Optional[str] = None

@app.on_event("startup")
def startup_event():
    # Tự động nạp dữ liệu mẫu ban đầu nếu DB chưa có bài nào
    articles = get_all_articles(limit=1)
    if not articles:
        fetch_rss_feeds()
        fetch_cisa_kev()

@app.get("/api/status")
def get_status():
    return {
        "status": "online",
        "system": "CTI-Sentinel Agentic Engine",
        "stats": get_system_stats()
    }

@app.get("/api/feeds")
def get_feeds(limit: int = 50):
    articles = get_all_articles(limit=limit)
    if not articles:
        fetch_rss_feeds()
        fetch_cisa_kev()
        articles = get_all_articles(limit=limit)
    return {"articles": articles, "total": len(articles)}

@app.post("/api/feeds/fetch")
def trigger_fetch():
    rss = fetch_rss_feeds()
    cisa = fetch_cisa_kev()
    return {
        "message": "Thu thập dữ liệu thành công!",
        "rss_count": len(rss),
        "cisa_count": len(cisa)
    }

@app.post("/api/analyze")
def run_ai_analysis(payload: AnalyzeRequest):
    """
    Kích hoạt chu trình Tác tử AI (ReAct Loop) phân tích toàn diện bài viết:
    1. Thu thập văn bản
    2. Bóc tách IOCs (Regex + LLM)
    3. Thẩm định danh tiếng (VirusTotal / AbuseIPDB)
    4. Ánh xạ ma trận MITRE ATT&CK
    5. Biên dịch 3 lớp luật phòng thủ (Sigma, YARA, Blocklist) + STIX 2.1
    """
    article_id = payload.article_id
    if article_id:
        article = get_article_by_id(article_id)
        if not article:
            raise HTTPException(status_code=404, detail="Không tìm thấy bài viết")
        title = article["title"]
        text = article["raw_content"]
    else:
        title = payload.custom_title or "Báo cáo Đe dọa Tùy chỉnh (Ad-hoc Threat Alert)"
        text = payload.custom_text
        if not text:
            raise HTTPException(status_code=400, detail="Vui lòng cung cấp nội dung bài viết cần phân tích")

    # 1. Trích xuất IOCs
    extracted = extract_iocs_from_text(text)
    
    # 2. Thẩm định danh tiếng qua Caching & VirusTotal/AbuseIPDB
    enriched = enrich_ioc_list(extracted["iocs"])
    
    # 3. Ánh xạ MITRE ATT&CK
    mitre_techniques = map_mitre_techniques(text)
    
    # 4. Sinh quy tắc phòng thủ
    sigma_code = generate_sigma_rule(title, enriched, mitre_techniques)
    yara_code = generate_yara_rule(title, enriched)
    blocklist_code = generate_firewall_blocklist(enriched)
    stix_bundle = generate_stix_bundle(title, enriched, mitre_techniques)
    
    report_id = f"CTI-REP-{uuid.uuid4().hex[:8].upper()}"
    
    report_data = {
        "report_id": report_id,
        "article_id": article_id,
        "title": title,
        "executive_summary": f"Chiến dịch đe dọa liên quan đến {', '.join(extracted['threat_actors']) if extracted['threat_actors'] else 'mối đe dọa không xác định'}. Bóc tách thành công {len(enriched)} chỉ số xâm nhập (IOCs) và ánh xạ {len(mitre_techniques)} kỹ thuật MITRE ATT&CK.",
        "threat_actors": extracted["threat_actors"],
        "targeted_sectors": ["Doanh nghiệp", "Hạ tầng trọng yếu", "Dịch vụ tài chính"],
        "enriched_iocs": enriched,
        "mitre_attack_matrix": mitre_techniques,
        "defensive_rules": {
            "sigma_rule": sigma_code,
            "yara_rule": yara_code,
            "firewall_blocklist": [ioc["value"] for ioc in enriched if ioc["type"] in ["IP", "DOMAIN"]]
        },
        "raw_blocklist_text": blocklist_code,
        "stix_json": stix_bundle
    }
    
    # Lưu báo cáo vào Database
    save_threat_report(report_data)
    if article_id:
        mark_article_analyzed(article_id)
        
    return {
        "status": "success",
        "report": report_data
    }

@app.get("/api/reports")
def list_reports(limit: int = 20):
    reports = get_all_reports(limit=limit)
    return {"reports": reports}

@app.get("/api/download/{report_id}/{rule_type}")
def download_rule_file(report_id: str, rule_type: str):
    report = get_report_by_id(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Báo cáo không tồn tại")
        
    if rule_type == "sigma":
        content = report["sigma_rule"]
        filename = f"{report_id}_sigma_rule.yml"
        media_type = "text/yaml"
    elif rule_type == "yara":
        content = report["yara_rule"]
        filename = f"{report_id}_endpoint.yar"
        media_type = "text/plain"
    elif rule_type == "firewall":
        content = report["firewall_blocklist"]
        filename = f"{report_id}_firewall_blocklist.txt"
        media_type = "text/plain"
    elif rule_type == "stix":
        content = report["stix_bundle_json"]
        filename = f"{report_id}_stix21_bundle.json"
        media_type = "application/json"
    else:
        raise HTTPException(status_code=400, detail="Loại quy tắc không hợp lệ")
        
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# Phục vụ thư mục Dashboard tĩnh
dashboard_dir = os.path.join(os.path.dirname(__file__), "dashboard")
if os.path.exists(dashboard_dir):
    app.mount("/static", StaticFiles(directory=dashboard_dir), name="static")

    @app.get("/")
    def serve_dashboard():
        index_file = os.path.join(dashboard_dir, "index.html")
        return FileResponse(index_file)
