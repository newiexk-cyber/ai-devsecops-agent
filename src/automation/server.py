# -*- coding: utf-8 -*-
"""
FASTAPI SERVER & REST API (LÂM)
Cung cấp REST API cho quy trình CTI chuẩn xác:
1. Thu thập bản tin CTI thật (RSS đa nguồn + CISA KEV / NVD)
2. Phân tích bằng Hybrid CTI Local Agent (Regex Context + Ollama Local LLM)
3. Làm giàu IOC đa nguồn thật (VirusTotal, AbuseIPDB, Shodan InternetDB, MalwareBazaar, OpenPhish)
4. Sinh Dynamic Agent Skill (Python + OpenAI/Claude/Gemini/LangChain schemas) & kiểm chứng AST/Sandbox
5. Quản lý tập 50 bài báo gán nhãn tay & chạy Benchmark đo Precision/Recall/F1 thực tế
"""
import json
import os
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src.automation.collectors.cisa_collector import fetch_cisa_kev, fetch_cve_by_id
from src.automation.collectors.rss_collector import fetch_rss_feeds
from src.automation.storage.database import (
    get_all_articles,
    get_all_reports,
    get_article_by_id,
    get_report_by_id,
    get_system_stats,
    init_database,
    mark_article_analyzed,
    save_threat_report,
)
from src.core.cti_agent import analyze_cti_article
from src.core.ioc_extractor import extract_iocs_from_text
from src.core.local_llm_client import check_ollama_health
from src.core.rule_generator import generate_stix_bundle
from src.core.skill_synthesizer import synthesize_cti_skill
from src.core.skill_verifier import run_skill_sandbox_probes, verify_skill_ast
from src.security.benchmark.corpus_manager import (
    DEFAULT_CORPUS_PATH,
    collect_real_cti_corpus,
    load_corpus,
    update_human_annotation,
)
from src.security.benchmark.evaluator import (
    DEFAULT_REPORT_JSON_PATH,
    evaluate_cti_benchmark,
)
from src.security.enrichment_service import enrich_ioc_list

init_database()


@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    articles = get_all_articles(limit=1)
    if not articles:
        fetch_rss_feeds(max_per_source=5)
        fetch_cisa_kev(limit=15)
    yield


app = FastAPI(
    title="CTI-Sentinel API",
    description="REST API cho Hệ thống Tình báo CTI với Local LLM Agent, Sinh Kỹ năng Phòng thủ & Benchmark",
    version="2.0.0",
    lifespan=lifespan,
)

ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://127.0.0.1:8080,http://localhost:8080,http://127.0.0.1:3000,http://localhost:3000",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[orig.strip() for orig in ALLOWED_ORIGINS if orig.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' 'unsafe-inline' https:; "
        "img-src 'self' data: https:; "
        "font-src 'self' https: data:; "
        "connect-src 'self' http: https: ws:;"
    )
    return response


class AnalyzeRequest(BaseModel):
    article_id: Optional[int] = None
    custom_title: Optional[str] = Field(default=None, max_length=250)
    custom_text: Optional[str] = Field(default=None, max_length=500000)
    mode: str = Field(default="hybrid", pattern=r"^(hybrid|regex_only)$")


class FetchCVERequest(BaseModel):
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$")


class SkillVerifyRequest(BaseModel):
    skill_name: Optional[str] = "custom_skill"
    execution_code: str = Field(..., min_length=1, max_length=150000)
    iocs_embedded: Dict[str, List[str]] = Field(default_factory=dict)


class AnnotateArticleRequest(BaseModel):
    annotated_by: str = Field(..., min_length=2, max_length=60)
    ips: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    md5: List[str] = Field(default_factory=list)
    sha256: List[str] = Field(default_factory=list)
    cves: List[str] = Field(default_factory=list)
    threat_actors: List[str] = Field(default_factory=list)
    malware_families: List[str] = Field(default_factory=list)
    notes: str = Field(default="", max_length=1000)


class BenchmarkRunRequest(BaseModel):
    modes: List[str] = Field(default_factory=lambda: ["regex_only", "hybrid"])
    include_pending: bool = False


@app.get("/api/status")
def get_status():
    corpus = load_corpus(DEFAULT_CORPUS_PATH)
    articles = corpus.get("articles", [])
    verified_count = sum(
        1 for a in articles if a.get("annotation_meta", {}).get("status") == "human_verified"
    )
    return {
        "status": "online",
        "system": "CTI-Sentinel Local Agent & Skill Synthesizer",
        "stats": get_system_stats(),
        "ollama_health": check_ollama_health(),
        "corpus_summary": {
            "total_articles": len(articles),
            "human_verified_count": verified_count,
        },
    }


@app.get("/api/llm/status")
def get_llm_status():
    return check_ollama_health()


@app.get("/api/feeds")
def get_feeds(
    limit: int = Query(default=50, ge=1, le=200),
    source: Optional[str] = None,
    q: Optional[str] = None,
):
    articles = get_all_articles(limit=limit)
    if not articles:
        fetch_rss_feeds(max_per_source=5)
        fetch_cisa_kev(limit=15)
        articles = get_all_articles(limit=limit)

    if source and source.upper() != "ALL":
        articles = [a for a in articles if source.lower() in (a.get("source_name") or "").lower()]
    if q and q.strip():
        kw = q.strip().lower()
        articles = [
            a for a in articles
            if kw in (a.get("title") or "").lower() or kw in (a.get("raw_content") or "").lower()
        ]

    return {"articles": articles, "total": len(articles)}


@app.post("/api/feeds/fetch")
def trigger_fetch(limit: int = Query(default=25, ge=1, le=100)):
    rss = fetch_rss_feeds(max_per_source=max(5, limit // 4))
    cisa = fetch_cisa_kev(limit=limit)
    return {
        "status": "success",
        "message": f"Đã thu thập {len(rss)} tin từ RSS đa nguồn và {len(cisa)} mục CISA KEV!",
        "rss_count": len(rss),
        "cisa_count": len(cisa),
    }


@app.post("/api/feeds/fetch-cve")
def on_demand_cve_fetch(payload: FetchCVERequest):
    res = fetch_cve_by_id(payload.cve_id)
    if not res or res.get("status") == "not_found":
        raise HTTPException(status_code=404, detail=f"Không tìm thấy dữ liệu xác thực cho {payload.cve_id}")
    return {
        "status": "success",
        "message": f"Đã kéo thành công lỗ hổng {res['cve_id']} từ {res['source']}!",
        "article": res,
    }


@app.post("/api/analyze")
def run_ai_analysis(payload: AnalyzeRequest):
    """
    Chạy quy trình Tác tử CTI đầy đủ:
    1. Trích xuất Regex kèm ngữ cảnh + Local LLM (Ollama) lọc nhiễu & giải trình XAI
    2. Làm giàu IOC đa nguồn thật (không tạo điểm giả)
    3. Sinh Dynamic Agent Skill (Python + đa chuẩn schema) & kiểm chứng AST/Sandbox
    """
    article_id = payload.article_id
    if article_id:
        article = get_article_by_id(article_id)
        if not article:
            raise HTTPException(status_code=404, detail="Không tìm thấy bài viết")
        title = article["title"]
        text = article["raw_content"]
    else:
        title = payload.custom_title or "Báo cáo CTI Tùy chỉnh"
        text = payload.custom_text
        if not text:
            raise HTTPException(status_code=400, detail="Vui lòng cung cấp nội dung bài viết cần phân tích")

    analysis = analyze_cti_article(title=title, raw_content=text, mode=payload.mode)
    enriched = enrich_ioc_list(analysis["iocs"])

    try:
        agent_skill = synthesize_cti_skill(analysis, enriched)
    except ValueError as exc:
        agent_skill = {
            "skill_name": "no_actionable_skill",
            "description": str(exc),
            "execution_status": "NOT_IMPLEMENTED",
            "code_compiled_successfully": False,
            "ast_safe": True,
            "execution_code": f"# {exc}",
            "model_schemas": {},
            "verification": {"syntax_valid": False, "ast_safe": True, "sandbox_verified": False, "error": str(exc)},
        }

    stix_bundle = generate_stix_bundle(title, enriched, analysis["mitre_techniques"])
    report_id = f"CTI-REP-{uuid.uuid4().hex[:8].upper()}"

    report_data = {
        "report_id": report_id,
        "article_id": article_id,
        "title": title,
        "analysis_mode": analysis["analysis_mode"],
        "llm_used": analysis["llm_used"],
        "llm_model": analysis["llm_model"],
        "llm_error": analysis["llm_error"],
        "executive_summary": analysis["executive_summary"],
        "threat_actors": analysis["threat_actors"],
        "malware_families": analysis["malware_families"],
        "targeted_sectors": [],
        "enriched_iocs": enriched,
        "dropped_iocs": analysis["dropped_iocs"],
        "iocs_summary": {
            "ips": analysis["ips"],
            "domains": analysis["domains"],
            "urls": analysis["urls"],
            "sha256": analysis["sha256"],
            "md5": analysis["md5"],
            "cves": analysis["cves"],
        },
        "mitre_attack_matrix": analysis["mitre_techniques"],
        "xai_report": analysis["xai_report"],
        "agent_skill": agent_skill,
        "stix_json": stix_bundle,
    }

    save_threat_report(report_data)
    if article_id:
        mark_article_analyzed(article_id)

    return {
        "status": "success",
        "report": report_data,
        "agent_skill": agent_skill,
    }


@app.get("/api/reports")
def list_reports(limit: int = Query(default=20, ge=1, le=100)):
    return {"reports": get_all_reports(limit=limit)}


@app.post("/api/skills/verify")
def verify_skill_endpoint(payload: SkillVerifyRequest):
    """Kiểm tra an toàn AST và chạy thử mẫu dương tính/âm tính trong sandbox cho Python Skill."""
    skill_dict = {
        "skill_name": payload.skill_name,
        "execution_code": payload.execution_code,
        "iocs_embedded": payload.iocs_embedded,
    }
    if any(payload.iocs_embedded.values()):
        verification = run_skill_sandbox_probes(skill_dict)
    else:
        ast_res = verify_skill_ast(payload.execution_code)
        verification = {
            **ast_res,
            "positive_probes_total": 0,
            "positive_probes_passed": 0,
            "negative_probe_passed": None,
            "sandbox_verified": False,
            "execution_status": "DRY_RUN" if ast_res["ast_safe"] else "FAILED",
            "probe_results": [],
        }
    return {"status": "success", "verification": verification}


@app.get("/api/download/{report_id}/{artifact_type}")
def download_artifact_file(report_id: str, artifact_type: str):
    report = get_report_by_id(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Báo cáo không tồn tại")

    if artifact_type == "skill":
        skill_raw = report.get("agent_skill_json")
        skill_obj = json.loads(skill_raw) if skill_raw else {}
        content = skill_obj.get("execution_code", "# No Python skill available")
        filename = f"{report_id}_agent_skill.py"
        media_type = "text/x-python"
    elif artifact_type == "stix":
        content = report.get("stix_bundle_json") or "{}"
        filename = f"{report_id}_stix21_bundle.json"
        media_type = "application/json"
    elif artifact_type == "report":
        content = json.dumps(report, indent=2, ensure_ascii=False)
        filename = f"{report_id}_report.json"
        media_type = "application/json"
    else:
        raise HTTPException(status_code=400, detail="Chỉ hỗ trợ tải skill, stix hoặc report")

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ==============================================================================
# CORPUS 50 BÀI BÁO GÁN NHÃN TAY & BENCHMARK ĐO ĐỘ CHÍNH XÁC AGENT
# ==============================================================================
@app.get("/api/corpus")
def get_corpus_summary():
    corpus = load_corpus(DEFAULT_CORPUS_PATH)
    articles = corpus.get("articles", [])
    summary_items = []
    verified = 0
    for art in articles:
        meta = art.get("annotation_meta", {})
        status = meta.get("status", "pending_human_review")
        if status == "human_verified":
            verified += 1
        gt = art.get("ground_truth", {})
        gt_count = sum(len(gt.get(k, [])) for k in ("ips", "domains", "md5", "sha256", "cves"))
        summary_items.append({
            "article_id": art.get("article_id"),
            "title": art.get("title"),
            "source": art.get("source"),
            "url": art.get("url"),
            "published_date": art.get("published_date"),
            "char_length": len(art.get("raw_content", "")),
            "status": status,
            "annotated_by": meta.get("annotated_by", ""),
            "reviewed_at": meta.get("reviewed_at", ""),
            "gt_ioc_count": gt_count,
        })
    return {
        "status": "success",
        "total_articles": len(articles),
        "human_verified_count": verified,
        "articles": summary_items,
    }


@app.get("/api/corpus/{article_id}")
def get_corpus_article_detail(article_id: str):
    corpus = load_corpus(DEFAULT_CORPUS_PATH)
    art = next((a for a in corpus.get("articles", []) if a.get("article_id") == article_id), None)
    if not art:
        raise HTTPException(status_code=404, detail=f"Không tìm thấy bài {article_id}")

    suggestions = extract_iocs_from_text(art.get("raw_content", ""))
    return {
        "status": "success",
        "article": art,
        "regex_suggestions": {
            "ips": suggestions["ips"],
            "domains": suggestions["domains"],
            "urls": suggestions["urls"],
            "md5": suggestions["md5"],
            "sha256": suggestions["sha256"],
            "cves": suggestions["cves"],
            "threat_actors": suggestions["threat_actors"],
            "malware_families": suggestions["malware_families"],
        },
    }


@app.post("/api/corpus/collect")
def collect_corpus_endpoint(limit: int = Query(default=50, ge=5, le=80)):
    corpus = collect_real_cti_corpus(target_count=limit, fetch_full_html=True, refresh_pending=False)
    return {
        "status": "success",
        "total_articles": corpus.get("total_articles", 0),
        "human_verified_count": corpus.get("human_verified_count", 0),
        "message": f"Đã cập nhật bộ {corpus.get('total_articles', 0)} bài CTI thật (giữ nguyên các bài đã gán tay).",
    }


@app.post("/api/corpus/{article_id}/annotate")
def annotate_corpus_article(article_id: str, payload: AnnotateArticleRequest):
    try:
        updated = update_human_annotation(
            article_id=article_id,
            ground_truth=payload.model_dump(exclude={"annotated_by", "notes"}),
            annotated_by=payload.annotated_by,
            notes=payload.notes,
            status="human_verified",
            path=DEFAULT_CORPUS_PATH,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "status": "success",
        "message": f"Đã lưu đáp án gán tay của '{payload.annotated_by}' cho bài {article_id}.",
        "article": updated,
    }


@app.post("/api/benchmark/run")
def run_benchmark_endpoint(payload: BenchmarkRunRequest):
    valid_modes = [m for m in payload.modes if m in {"regex_only", "hybrid"}]
    if not valid_modes:
        raise HTTPException(status_code=400, detail="modes phải chứa regex_only hoặc hybrid")

    results = evaluate_cti_benchmark(
        corpus_path=DEFAULT_CORPUS_PATH,
        modes=valid_modes,
        include_pending=payload.include_pending,
    )
    return {"status": "success", "results": results}


@app.get("/api/benchmark/latest")
def get_latest_benchmark():
    if not DEFAULT_REPORT_JSON_PATH.exists():
        return {"status": "not_run", "results": None}
    data = json.loads(DEFAULT_REPORT_JSON_PATH.read_text(encoding="utf-8"))
    return {"status": "success", "results": data}


dashboard_dir = os.path.join(os.path.dirname(__file__), "dashboard")
if os.path.exists(dashboard_dir):
    app.mount("/static", StaticFiles(directory=dashboard_dir), name="static")

    @app.get("/")
    def serve_dashboard():
        return FileResponse(os.path.join(dashboard_dir, "index.html"))
