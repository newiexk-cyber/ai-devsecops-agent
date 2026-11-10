# -*- coding: utf-8 -*-
"""
CORPUS MANAGER - QUẢN LÝ BỘ 50 BÀI BÁO CTI THẬT & ĐÁP ÁN GÁN NHÃN TAY (KHANG & LÂM)
- Kéo bài báo CTI thật (full-text) từ các nguồn RSS/Advisory công khai uy tín.
- Không tự ghép câu giả; giữ nguyên văn bản bài báo để thành viên tự đọc và gán tay đáp án.
- Quản lý trạng thái duyệt (`pending_human_review` vs `human_verified`) và xuất CSV đối chiếu.
"""
import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import feedparser
import httpx
from bs4 import BeautifulSoup

from src.core.ioc_extractor import clean_defanged, sanitize_domain

ROOT_DIR = Path(__file__).resolve().parents[3]
DEFAULT_CORPUS_PATH = ROOT_DIR / "data" / "benchmark" / "cti_50_corpus.json"

REAL_CTI_RSS_SOURCES = [
    {"name": "Cisco Talos", "url": "https://blog.talosintelligence.com/rss/", "max_items": 12},
    {"name": "Securelist (Kaspersky)", "url": "https://securelist.com/feed/", "max_items": 10},
    {"name": "Palo Alto Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "max_items": 12},
    {"name": "Malwarebytes Labs", "url": "https://www.malwarebytes.com/blog/feed/index.xml", "max_items": 12},
    {"name": "The DFIR Report", "url": "https://thedfirreport.com/feed/", "max_items": 8},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "max_items": 10},
]


def _empty_ground_truth() -> Dict[str, List[str]]:
    return {
        "ips": [],
        "domains": [],
        "urls": [],
        "md5": [],
        "sha256": [],
        "cves": [],
        "threat_actors": [],
        "malware_families": [],
    }


def _canonicalize_ground_truth(gt: Dict[str, Any]) -> Dict[str, List[str]]:
    base = _empty_ground_truth()
    if not isinstance(gt, dict):
        return base

    base["ips"] = sorted({str(x).strip() for x in gt.get("ips", []) if str(x).strip()})
    base["domains"] = sorted(
        {sanitize_domain(clean_defanged(str(x))) for x in gt.get("domains", []) if str(x).strip()}
    )
    base["urls"] = sorted({clean_defanged(str(x)).strip() for x in gt.get("urls", []) if str(x).strip()})
    base["md5"] = sorted({str(x).strip().lower() for x in gt.get("md5", []) if str(x).strip()})
    base["sha256"] = sorted({str(x).strip().lower() for x in gt.get("sha256", []) if str(x).strip()})
    base["cves"] = sorted({str(x).strip().upper() for x in gt.get("cves", []) if str(x).strip()})
    base["threat_actors"] = sorted({str(x).strip() for x in gt.get("threat_actors", []) if str(x).strip()})
    base["malware_families"] = sorted({str(x).strip() for x in gt.get("malware_families", []) if str(x).strip()})
    return base


def load_corpus(path: Path = DEFAULT_CORPUS_PATH) -> Dict[str, Any]:
    target = Path(path)
    if not target.exists():
        return {
            "dataset_name": "CTI 50-Article Manual Annotation Corpus",
            "created_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "articles": [],
        }
    return json.loads(target.read_text(encoding="utf-8"))


def save_corpus(data: Dict[str, Any], path: Path = DEFAULT_CORPUS_PATH) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return target


def update_human_annotation(
    article_id: str,
    ground_truth: Dict[str, Any],
    annotated_by: str,
    notes: str = "",
    status: str = "human_verified",
    path: Path = DEFAULT_CORPUS_PATH,
) -> Dict[str, Any]:
    """Lưu đáp án gán nhãn tay của thành viên cho 1 bài báo trong tập corpus."""
    corpus = load_corpus(path)
    articles = corpus.get("articles", [])
    target = next((a for a in articles if a.get("article_id") == article_id), None)
    if not target:
        raise KeyError(f"Article '{article_id}' not found in corpus")

    clean_reviewer = annotated_by.strip().lower()
    if status == "human_verified" and not clean_reviewer:
        raise ValueError("annotated_by is required when marking an article human_verified")

    target["ground_truth"] = _canonicalize_ground_truth(ground_truth)
    target["annotation_meta"] = {
        "status": status,
        "annotated_by": clean_reviewer,
        "reviewed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "notes": notes.strip(),
    }
    save_corpus(corpus, path)
    return target


def _extract_article_body_from_html(html_text: str) -> str:
    soup = BeautifulSoup(html_text, "html.parser")
    for tag in soup(["script", "style", "noscript", "header", "footer", "nav", "aside"]):
        tag.decompose()

    selectors = [
        "div.articlebody",
        "div.article_section",
        "article",
        "div.entry-content",
        "div.post-content",
        "main",
    ]
    best_text = ""
    for sel in selectors:
        node = soup.select_one(sel)
        if node:
            paragraphs = [p.get_text(" ", strip=True) for p in node.find_all(["p", "li", "pre", "code"])]
            joined = "\n\n".join(p for p in paragraphs if len(p) > 15)
            if len(joined) > len(best_text):
                best_text = joined

    if len(best_text) < 250:
        all_p = [p.get_text(" ", strip=True) for p in soup.find_all("p")]
        fallback = "\n\n".join(p for p in all_p if len(p) > 25)
        if len(fallback) > len(best_text):
            best_text = fallback

    return re.sub(r"[ \t]+", " ", best_text).strip()


def _fetch_full_article_text(url: str, rss_fallback: str) -> str:
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CTI-Research-Collector/1.0"
        }
        with httpx.Client(timeout=6.0, follow_redirects=True, headers=headers) as client:
            resp = client.get(url)
            if resp.status_code == 200 and "text/html" in resp.headers.get("content-type", ""):
                extracted = _extract_article_body_from_html(resp.text)
                if len(extracted) >= max(300, len(rss_fallback)):
                    return extracted[:16000]
    except Exception:
        pass
    return rss_fallback


def _rss_entry_text(entry: Any) -> str:
    parts: List[str] = []
    if entry.get("content"):
        for chunk in entry["content"]:
            val = chunk.get("value", "")
            if val:
                parts.append(BeautifulSoup(val, "html.parser").get_text(" ", strip=True))
    desc = entry.get("summary") or entry.get("description") or ""
    if desc:
        parts.append(BeautifulSoup(desc, "html.parser").get_text(" ", strip=True))
    combined = "\n\n".join(p for p in parts if p)
    return re.sub(r"[ \t]+", " ", combined).strip()


def collect_real_cti_corpus(
    target_count: int = 50,
    path: Path = DEFAULT_CORPUS_PATH,
    fetch_full_html: bool = True,
    refresh_pending: bool = False,
) -> Dict[str, Any]:
    """
    Thu thập đủ `target_count` bài báo CTI THẬT (full-text) từ các nguồn RSS công khai
    và nạp vào bộ corpus chờ nhóm tự đọc, gán tay đáp án. Luôn bảo toàn các bài đã `human_verified`.
    """
    existing = load_corpus(path)
    existing_articles = existing.get("articles", [])

    verified_articles: List[Dict[str, Any]] = []
    other_existing: List[Dict[str, Any]] = []
    seen_urls: Set[str] = set()

    for art in existing_articles:
        u = art.get("url", "").strip()
        if not u:
            continue
        if art.get("annotation_meta", {}).get("status") == "human_verified":
            verified_articles.append(art)
            seen_urls.add(u)
        elif not refresh_pending:
            other_existing.append(art)
            seen_urls.add(u)

    collected: List[Dict[str, Any]] = verified_articles + other_existing

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
    }
    with httpx.Client(timeout=8.0, follow_redirects=True, headers=headers) as client:
        for src in REAL_CTI_RSS_SOURCES:
            if len(collected) >= target_count:
                break
            try:
                resp = client.get(src["url"])
                if resp.status_code != 200:
                    continue
                parsed = feedparser.parse(resp.text)
            except Exception:
                continue

            added_from_src = 0
            src_limit = int(src.get("max_items", 12))
            for entry in parsed.entries:
                if len(collected) >= target_count or added_from_src >= src_limit:
                    break
                link = (entry.get("link") or "").strip()
                title = (entry.get("title") or "").strip()
                if not link or not title or link in seen_urls:
                    continue

                rss_text = _rss_entry_text(entry)
                full_text = _fetch_full_article_text(link, rss_text) if fetch_full_html else rss_text
                if len(full_text) < 120:
                    continue

                pub_date = (entry.get("published") or entry.get("updated") or "").strip()
                seen_urls.add(link)
                added_from_src += 1
                collected.append({
                    "article_id": "",
                    "title": title,
                    "source": src["name"],
                    "url": link,
                    "published_date": pub_date,
                    "raw_content": full_text,
                    "ground_truth": _empty_ground_truth(),
                    "annotation_meta": {
                        "status": "pending_human_review",
                        "annotated_by": "",
                        "reviewed_at": "",
                        "notes": "",
                    },
                })

    # Nếu các RSS chưa đủ target_count (mất mạng hoặc giới hạn feed), bổ sung từ CISA KEV advisories thật
    if len(collected) < target_count:
        try:
            with httpx.Client(timeout=8.0, follow_redirects=True) as client:
                r = client.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
                if r.status_code == 200:
                    vulns = list(reversed(r.json().get("vulnerabilities", [])))
                    for v in vulns:
                        if len(collected) >= target_count:
                            break
                        cve_id = (v.get("cveID") or "").strip().upper()
                        if not cve_id:
                            continue
                        kev_url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{cve_id}"
                        if kev_url in seen_urls:
                            continue
                        seen_urls.add(kev_url)
                        content = (
                            f"CISA KEV Advisory for {cve_id}: {v.get('vulnerabilityName', '')}.\n"
                            f"Affected Vendor/Product: {v.get('vendorProject', '')} {v.get('product', '')}.\n"
                            f"Description: {v.get('shortDescription', '')}\n"
                            f"Required Action: {v.get('requiredAction', '')}\n"
                            f"Known Ransomware Campaign Use: {v.get('knownRansomwareCampaignUse', 'Unknown')}."
                        )
                        collected.append({
                            "article_id": "",
                            "title": f"CISA KEV: {cve_id} - {v.get('vulnerabilityName', '')}",
                            "source": "CISA KEV",
                            "url": kev_url,
                            "published_date": v.get("dateAdded", ""),
                            "raw_content": content,
                            "ground_truth": _empty_ground_truth(),
                            "annotation_meta": {
                                "status": "pending_human_review",
                                "annotated_by": "",
                                "reviewed_at": "",
                                "notes": "",
                            },
                        })
        except Exception:
            pass

    # Cấp lại article_id tuần tự CTI-01 .. CTI-NN ổn định
    trimmed = collected[:target_count]
    for idx, art in enumerate(trimmed, start=1):
        if not art.get("article_id"):
            art["article_id"] = f"CTI-{idx:02d}"

    # Tránh trùng article_id nếu vừa giữ bài cũ vừa chèn bài mới
    used_ids: Set[str] = set()
    next_num = 1
    for art in trimmed:
        aid = art.get("article_id", "")
        if not aid or aid in used_ids:
            while f"CTI-{next_num:02d}" in used_ids:
                next_num += 1
            aid = f"CTI-{next_num:02d}"
            art["article_id"] = aid
        used_ids.add(aid)

    corpus_obj = {
        "dataset_name": "CTI 50-Article Manual Annotation Corpus",
        "updated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_articles": len(trimmed),
        "human_verified_count": sum(
            1 for a in trimmed if a.get("annotation_meta", {}).get("status") == "human_verified"
        ),
        "articles": trimmed,
    }
    save_corpus(corpus_obj, path)
    return corpus_obj


def export_corpus_csv(
    corpus_path: Path = DEFAULT_CORPUS_PATH,
    csv_path: Optional[Path] = None,
) -> Path:
    corpus = load_corpus(corpus_path)
    out_csv = Path(csv_path or Path(corpus_path).with_suffix(".csv"))
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow([
            "article_id", "status", "annotated_by", "source", "published_date",
            "title", "url", "gt_ips", "gt_domains", "gt_md5", "gt_sha256", "gt_cves", "notes"
        ])
        for a in corpus.get("articles", []):
            gt = a.get("ground_truth", {})
            meta = a.get("annotation_meta", {})
            writer.writerow([
                a.get("article_id", ""),
                meta.get("status", "pending_human_review"),
                meta.get("annotated_by", ""),
                a.get("source", ""),
                a.get("published_date", ""),
                a.get("title", ""),
                a.get("url", ""),
                "; ".join(gt.get("ips", [])),
                "; ".join(gt.get("domains", [])),
                "; ".join(gt.get("md5", [])),
                "; ".join(gt.get("sha256", [])),
                "; ".join(gt.get("cves", [])),
                meta.get("notes", ""),
            ])
    return out_csv
