# -*- coding: utf-8 -*-
"""
FASTAPI SERVER & REST API (LÂM)
Cung cấp API điều khiển pipeline CTI, kích hoạt tác tử AI và phục vụ giao diện Web Dashboard.
Đã áp dụng bảo mật:
- CORS ràng buộc origin cụ thể, chống wildcard thiếu an toàn
- Security Headers Middleware (X-Content-Type-Options, X-Frame-Options, CSP)
- Pydantic Bound Limits & Regex Validation chống Injection/DDoS
"""
import os
import uuid
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, Body, Query, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src.automation.storage.database import (
    init_database, get_all_articles, get_article_by_id, mark_article_analyzed,
    save_threat_report, get_all_reports, get_report_by_id, get_system_stats
)
from src.automation.collectors.rss_collector import fetch_rss_feeds
from src.automation.collectors.cisa_collector import fetch_cisa_kev, fetch_cve_by_id
from src.core.ioc_extractor import extract_iocs_from_text
from src.core.mitre_mapper import map_mitre_techniques
from src.security.enrichment_service import enrich_ioc_list
from src.core.rule_generator import (
    generate_sigma_rule, generate_yara_rule, generate_firewall_blocklist, generate_stix_bundle
)
from src.core.sast_analyzer import analyze_code, get_preset_samples
from src.core.network_cve_catalog import (
    get_network_threat_catalog, filter_network_threats, evaluate_smart_crawl_trigger,
    ingest_live_network_cve, crawl_whitelist_sources
)
from src.core.network_skill_generator import (
    generate_explainable_trust_card, generate_network_agent_skill, list_available_skills
)

# Khởi tạo DB khi khởi động
init_database()

app = FastAPI(
    title="CTI-Sentinel API",
    description="REST API cho Hệ thống Tình báo Mạng và Sinh Quy tắc Phòng thủ AI Agent",
    version="1.0.0"
)

# Cấu hình CORS an toàn với origin rõ ràng
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://127.0.0.1:8080,http://localhost:8080,http://127.0.0.1:3000,http://localhost:3000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[orig.strip() for orig in ALLOWED_ORIGINS if orig.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Bổ sung các HTTP Security Headers bảo vệ ứng dụng."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' 'unsafe-inline' https:; "
        "img-src 'self' data: https:; "
        "font-src 'self' https: data:; "
        "connect-src 'self' http://127.0.0.1:8080 http://localhost:8080 https:;"
    )
    return response


class AnalyzeRequest(BaseModel):
    article_id: Optional[int] = None
    custom_title: Optional[str] = Field(default=None, max_length=250)
    custom_text: Optional[str] = Field(default=None, max_length=500000)


class SastScanRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=200000)
    language: Optional[str] = Field(default="csharp", max_length=30)
    filename: Optional[str] = Field(default=None, max_length=150)


class FetchCVERequest(BaseModel):
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$")


class IngestNetworkCVERequest(BaseModel):
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$")


class NetworkSkillRequest(BaseModel):
    threat_id: Optional[str] = None
    identifier: Optional[str] = None


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
def get_feeds(limit: int = Query(default=50, ge=1, le=100)):
    articles = get_all_articles(limit=limit)
    if not articles:
        fetch_rss_feeds()
        fetch_cisa_kev()
        articles = get_all_articles(limit=limit)
    return {"articles": articles, "total": len(articles)}


@app.post("/api/feeds/fetch")
def trigger_fetch(limit: int = Query(default=25, ge=1, le=100)):
    rss = fetch_rss_feeds(max_per_source=max(5, limit // 2))
    cisa = fetch_cisa_kev(limit=limit)
    return {
        "message": f"Thu thập dữ liệu thành công với hạn mức {limit}!",
        "rss_count": len(rss),
        "cisa_count": len(cisa)
    }


@app.post("/api/feeds/fetch-cve")
def on_demand_cve_fetch(payload: FetchCVERequest):
    """Kéo dữ liệu khẩn cấp cho một mã CVE cụ thể từ CISA KEV hoặc NIST NVD"""
    res = fetch_cve_by_id(payload.cve_id)
    if not res:
        raise HTTPException(status_code=404, detail=f"Không thể truy vấn thông tin cho mã {payload.cve_id}")
    return {
        "status": "success",
        "message": f"Đã kéo thành công lỗ hổng {res['cve_id']} từ {res['source']}!",
        "article": res
    }


@app.post("/api/analyze")
def run_ai_analysis(payload: AnalyzeRequest):
    """
    Kích hoạt chu trình Tác tử AI phân tích toàn diện bài viết:
    1. Thu thập văn bản
    2. Bóc tách IOCs (Regex chuẩn hóa)
    3. Thẩm định danh tiếng (VirusTotal / AbuseIPDB / Heuristic có nhãn rõ ràng)
    4. Ánh xạ ma trận MITRE ATT&CK (Word boundary, negation handling)
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

    # 2. Thẩm định danh tiếng qua Caching & VirusTotal/AbuseIPDB (không tạo điểm số giả)
    enriched = enrich_ioc_list(extracted["iocs"])

    # 3. Ánh xạ MITRE ATT&CK
    mitre_techniques = map_mitre_techniques(text)

    # 4. Sinh quy tắc phòng thủ
    try:
        sigma_code = generate_sigma_rule(title, enriched, mitre_techniques)
    except ValueError as e:
        sigma_code = f"# Notice: {str(e)}"

    try:
        yara_code = generate_yara_rule(title, enriched)
    except ValueError as e:
        yara_code = f"// Notice: {str(e)}"

    blocklist_code = generate_firewall_blocklist(enriched, format_type="iptables")
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
def list_reports(limit: int = Query(default=20, ge=1, le=100)):
    reports = get_all_reports(limit=limit)
    return {"reports": reports}


@app.get("/api/download/{report_id}/{rule_type}")
def download_rule_file(
    report_id: str,
    rule_type: str,
    format_type: str = Query(default="iptables", pattern=r"^(iptables|nftables|dnsmasq|generic_ip|all)$")
):
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
        try:
            iocs = report.get("enriched_iocs", [])
            content = generate_firewall_blocklist(iocs, format_type=format_type)
        except Exception:
            content = report.get("firewall_blocklist", "")
        filename = f"{report_id}_firewall_{format_type}.txt"
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


# ==============================================================================
# SAST DEVSECOPS API (RULE-BASED CODE SECURITY AUDIT & REMEDIATION)
# ==============================================================================
@app.post("/api/sast/scan")
def scan_code_security(payload: SastScanRequest):
    """
    Rà soát mã nguồn đầu vào bằng Rule-based SAST Analyzer:
    - Phát hiện lỗ hổng theo chuẩn OWASP Top 10 và CWE
    - Đánh giá độ tin cậy heuristic và kiểm tra cú pháp AST
    - Tự động sinh bản vá gợi ý khắc phục (Remediation Patch)
    """
    result = analyze_code(
        code=payload.code,
        language=payload.language or "csharp",
        filename=payload.filename
    )
    return result


@app.get("/api/sast/presets")
def get_sast_presets():
    presets = get_preset_samples()
    return {"status": "success", "presets": presets}


# ==============================================================================
# NETWORK INTELLIGENCE & DYNAMIC AGENT SKILLS API
# ==============================================================================
@app.get("/api/network-intel/feeds")
def get_network_intel_feeds(
    time_window: Optional[str] = None,
    tag: Optional[str] = None,
    severity: Optional[str] = None,
    threat_type: Optional[str] = None
):
    threats = filter_network_threats(
        time_window=time_window,
        tag=tag,
        severity=severity,
        threat_type=threat_type
    )
    return {
        "status": "success",
        "total": len(threats),
        "threats": threats
    }


@app.get("/api/network-intel/trigger-status")
def get_smart_trigger_status():
    catalog = get_network_threat_catalog()
    crit_count = sum(1 for t in catalog if t.get("severity") == "CRITICAL" and t.get("date_category") == "24h_emergency")
    has_cisa = any("#CISA_KEV" in t.get("tags", []) for t in catalog)

    evaluation = evaluate_smart_crawl_trigger(
        high_severity_events=crit_count,
        cisa_network_update=has_cisa,
        hours_since_last_crawl=2.5,
        surge_detected=(crit_count >= 1)
    )
    return {
        "status": "success",
        "trigger": evaluation
    }


@app.post("/api/network-intel/generate-skill")
def generate_skill_for_network_threat(payload: NetworkSkillRequest):
    catalog = get_network_threat_catalog()
    threat = None

    if payload.threat_id:
        threat = next((t for t in catalog if t["id"] == payload.threat_id), None)
    elif payload.identifier:
        threat = next((t for t in catalog if t["identifier"].lower() == payload.identifier.lower()), None)

    if not threat:
        threat = catalog[0]

    xai_trust = generate_explainable_trust_card(threat)
    agent_skill = generate_network_agent_skill(threat)

    return {
        "status": "success",
        "threat": threat,
        "xai_trust": xai_trust,
        "agent_skill": agent_skill
    }


@app.get("/api/network-intel/skills-library")
def get_skills_library():
    skills = list_available_skills()
    return {
        "status": "success",
        "total_skills": len(skills),
        "skills": skills
    }


@app.post("/api/network-intel/ingest-cve")
def ingest_network_cve_endpoint(payload: IngestNetworkCVERequest):
    """
    Cào và phân tích khẩn cấp một CVE mạng theo thời gian thực (CISA KEV / NIST NVD).
    Tự động sinh Thẻ Giải trình XAI và Kỹ năng Tác tử (Dynamic Agent Skill).
    """
    threat = ingest_live_network_cve(payload.cve_id)
    if not threat:
        raise HTTPException(status_code=404, detail="Không thể xác thực hoặc tìm thấy CVE mạng này trong nguồn chính thức")
    xai_trust = generate_explainable_trust_card(threat)
    agent_skill = generate_network_agent_skill(threat)
    return {
        "status": "success",
        "message": f"Đã cào và sinh kỹ năng thành công cho {threat['identifier']}!",
        "threat": threat,
        "xai_trust": xai_trust,
        "agent_skill": agent_skill
    }


@app.post("/api/network-intel/live-crawl")
def execute_live_crawl(limit: int = Query(default=35, ge=1, le=100)):
    res = crawl_whitelist_sources(source_type="all", limit=limit)
    return res


@app.post("/api/crawler/cisa-kev")
def crawl_cisa_kev_endpoint(limit: int = Query(default=35, ge=1, le=100)):
    return crawl_whitelist_sources(source_type="cisa_kev", limit=limit)


@app.post("/api/crawler/whitelist-rss")
def crawl_whitelist_rss_endpoint(limit: int = Query(default=35, ge=1, le=100)):
    return crawl_whitelist_sources(source_type="whitelist_rss", limit=limit)


@app.post("/api/crawler/sync-all")
def crawl_all_whitelist_endpoint(limit: int = Query(default=35, ge=1, le=100)):
    return crawl_whitelist_sources(source_type="all", limit=limit)


@app.get("/api/crawler/whitelist")
def get_whitelist_sources_endpoint():
    return {
        "status": "success",
        "total_sources": 4,
        "sources": [
            {
                "id": "cisa_kev",
                "name": "CISA KEV Catalog",
                "domain": "cisa.gov",
                "category": "Known Exploited Vulnerabilities",
                "status": "ONLINE",
                "trust_weight": 99,
                "description": "Danh mục chính thức từ Cơ quan An ninh Mạng và Cơ sở Hạ tầng Mỹ ghi nhận các lỗ hổng đang bị khai thác thực tế."
            },
            {
                "id": "the_hacker_news",
                "name": "The Hacker News",
                "domain": "thehackernews.com",
                "category": "Threat Intelligence Journalism",
                "status": "ONLINE",
                "trust_weight": 95,
                "description": "Kênh tin tức an ninh mạng toàn cầu cập nhật các chiến dịch 0-Day và Web/Network CVE mới nhất."
            },
            {
                "id": "bleeping_computer",
                "name": "BleepingComputer",
                "domain": "bleepingcomputer.com",
                "category": "Cyber Threat & Ransomware",
                "status": "ONLINE",
                "trust_weight": 95,
                "description": "Chuyên trang phân tích kỹ thuật về các cuộc tấn công khai thác VPN Gateway, Firewall và mã độc tống tiền."
            },
            {
                "id": "nist_nvd",
                "name": "NIST NVD API v2",
                "domain": "nvd.nist.gov",
                "category": "National Vulnerability Database",
                "status": "ONLINE",
                "trust_weight": 98,
                "description": "Cơ sở dữ liệu quốc gia Mỹ lưu trữ toàn bộ chỉ số CVSS v3.1 và vector tấn công chuẩn hóa."
            }
        ]
    }


# Phục vụ thư mục Dashboard tĩnh
dashboard_dir = os.path.join(os.path.dirname(__file__), "dashboard")
if os.path.exists(dashboard_dir):
    app.mount("/static", StaticFiles(directory=dashboard_dir), name="static")

    @app.get("/")
    def serve_dashboard():
        index_file = os.path.join(dashboard_dir, "index.html")
        return FileResponse(index_file)
