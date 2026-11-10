# -*- coding: utf-8 -*-
"""
HYBRID CTI LOCAL AGENT (PHÚC)
Kết hợp trích xuất Regex kèm ngữ cảnh và Mô hình Ngôn ngữ Cục bộ (Ollama)
để đọc hiểu bản tin CTI:
- Lọc nhiễu (false positive) theo ngữ cảnh (domain nạn nhân/báo chí, ví dụ minh họa, phủ định)
- Giữ chặt Grounding Check: mọi IOC đầu ra bắt buộc phải xuất hiện trong văn bản gốc (chống LLM bịa)
- Sinh báo cáo giải trình XAI trích dẫn trực tiếp câu văn bản
- Fallback minh bạch về `regex_fallback` nếu Ollama offline
"""
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from src.core.ioc_extractor import (
    clean_defanged,
    extract_iocs_from_text,
    find_context_sentence,
    is_valid_public_ip,
    sanitize_domain,
)
from src.core.local_llm_client import OllamaClient
from src.core.mitre_mapper import map_mitre_techniques

CTI_SYSTEM_PROMPT = """You are a senior CTI Analyst. Given an article excerpt and Regex IOC candidates:
1. List ONLY false-positive candidates in `dropped_iocs` (editorial/media/vendor/benign domains, software versions, documentation examples, negated CVEs) with a short reason. Use one exact type per entry (`IP`, `DOMAIN`, `URL`, `MD5`, `SHA256`, or `CVE`) and do NOT repeat valid IOCs.
2. Output `threat_actors` (list), `malware_families` (list), `executive_summary` (1 concise Vietnamese sentence), `reasoning_chain` (2 short Vietnamese steps), and `evidence_quotes` (1 short verbatim quote from article).
Return compact single-line strict JSON only:
{"dropped_iocs":[{"type":"DOMAIN","value":"example.com","reason":"benign vendor domain"}],"threat_actors":[],"malware_families":[],"executive_summary":"...","reasoning_chain":["1. ..."],"evidence_quotes":["..."]}"""


def _build_smart_excerpt(title: str, cleaned_text: str, candidates: List[Dict[str, Any]], max_chars: int = 1800) -> str:
    """Rút gọn bài báo thông minh, ưu tiên phần mở đầu và các đoạn chứa ứng viên IOC để tối ưu tốc độ CPU."""
    if len(cleaned_text) <= max_chars:
        return f"Title: {title}\n\n{cleaned_text}"

    paragraphs = [p.strip() for p in re.split(r"\n{2,}", cleaned_text) if p.strip()]
    ioc_values = [c["value"].lower() for c in candidates]
    selected: List[str] = []
    total_len = 0

    if paragraphs:
        head = paragraphs[0][:500]
        selected.append(head)
        total_len += len(head)

    for p in paragraphs[1:]:
        p_low = p.lower()
        if any(val in p_low for val in ioc_values):
            chunk = p[:550]
            if total_len + len(chunk) <= max_chars:
                selected.append(chunk)
                total_len += len(chunk)

    for p in paragraphs[1:]:
        if len(selected) < 3 and total_len + len(p[:400]) <= max_chars:
            chunk = p[:400]
            if chunk not in selected:
                selected.append(chunk)
                total_len += len(chunk)

    return f"Title: {title}\n\n" + "\n\n".join(selected)


def _canonicalize_ioc(ioc_type: str, value: str) -> str:
    t = ioc_type.strip().upper()
    v = clean_defanged(value).strip()
    if t in {"DOMAIN", "MD5", "SHA256"}:
        return sanitize_domain(v) if t == "DOMAIN" else v.lower()
    if t == "CVE":
        return v.upper()
    return v


def _is_grounded_in_text(ioc_type: str, canonical_value: str, cleaned_text: str) -> bool:
    """Chống ảo giác LLM: mọi IOC phải thật sự xuất hiện trong văn bản nguồn đã khử defang."""
    if not canonical_value:
        return False
    t = ioc_type.upper()
    if t == "IP" and not is_valid_public_ip(canonical_value):
        return False
    if t == "CVE" and not re.match(r"^CVE-\d{4}-\d{4,7}$", canonical_value, re.IGNORECASE):
        return False
    if t == "SHA256" and not re.match(r"^[a-f0-9]{64}$", canonical_value, re.IGNORECASE):
        return False
    if t == "MD5" and not re.match(r"^[a-f0-9]{32}$", canonical_value, re.IGNORECASE):
        return False
    return canonical_value.lower() in cleaned_text.lower()


def _build_default_xai(
    title: str,
    extracted: Dict[str, Any],
    mitre_techniques: List[Dict[str, Any]],
    mode_label: str,
) -> Dict[str, Any]:
    iocs = extracted.get("iocs", [])
    quotes = [c.get("context_sentence") for c in iocs if c.get("context_sentence")][:3]
    steps = [
        f"1. Quét văn bản bản tin '{title[:80]}' ở chế độ {mode_label}.",
        f"2. Bóc tách {len(iocs)} chỉ số IOC gồm {len(extracted.get('ips', []))} IP, "
        f"{len(extracted.get('domains', []))} Domain, {len(extracted.get('sha256', [])) + len(extracted.get('md5', []))} Hash, "
        f"và {len(extracted.get('cves', []))} CVE.",
        f"3. Đối chiếu ngữ cảnh MITRE ATT&CK ghi nhận {len(mitre_techniques)} kỹ thuật liên quan.",
    ]
    return {
        "reasoning_chain": steps,
        "evidence_quotes": quotes,
        "trust_note": (
            "Kết quả được tổng hợp từ suy luận ngữ cảnh của Local LLM kết hợp Regex."
            if mode_label == "hybrid_local_llm"
            else "Chạy ở chế độ Regex (chưa dùng LLM lọc ngữ cảnh); cần kiểm chứng qua Enrichment."
        ),
    }


def _package_final_result(
    title: str,
    cleaned_text: str,
    kept_iocs: List[Dict[str, Any]],
    dropped_iocs: List[Dict[str, Any]],
    threat_actors: List[str],
    malware_families: List[str],
    mitre_techniques: List[Dict[str, Any]],
    analysis_mode: str,
    llm_model: Optional[str],
    llm_used: bool,
    llm_error: Optional[str],
    executive_summary: str,
    xai_report: Dict[str, Any],
) -> Dict[str, Any]:
    ips = sorted({x["value"] for x in kept_iocs if x["type"] == "IP"})
    domains = sorted({x["value"] for x in kept_iocs if x["type"] == "DOMAIN"})
    urls = sorted({x["value"] for x in kept_iocs if x["type"] == "URL"})
    sha256 = sorted({x["value"] for x in kept_iocs if x["type"] == "SHA256"})
    md5 = sorted({x["value"] for x in kept_iocs if x["type"] == "MD5"})
    cves = sorted({x["value"] for x in kept_iocs if x["type"] == "CVE"})

    return {
        "title": title,
        "analysis_mode": analysis_mode,
        "llm_used": llm_used,
        "llm_model": llm_model,
        "llm_error": llm_error,
        "iocs": kept_iocs,
        "dropped_iocs": dropped_iocs,
        "ips": ips,
        "domains": domains,
        "urls": urls,
        "sha256": sha256,
        "md5": md5,
        "cves": cves,
        "threat_actors": sorted(set(threat_actors)),
        "malware_families": sorted(set(malware_families)),
        "mitre_techniques": mitre_techniques,
        "executive_summary": executive_summary,
        "xai_report": xai_report,
    }


def analyze_cti_article(
    title: str,
    raw_content: str,
    mode: str = "hybrid",
    llm_client: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Chạy phân tích CTI cho 1 bài báo:
    - mode="regex_only": Baseline chỉ dùng Regex extractor + MITRE word-boundary mapper.
    - mode="hybrid": Regex extractor tạo ứng viên kèm ngữ cảnh + Local LLM (Ollama) lọc FP & giải trình XAI.
      Nếu Ollama lỗi/offline sẽ tự động chuyển về `regex_fallback` một cách minh bạch.
    """
    cleaned_text = clean_defanged(raw_content or "")
    regex_data = extract_iocs_from_text(raw_content or "")
    mitre_techniques = map_mitre_techniques(cleaned_text)

    if mode == "regex_only":
        xai = _build_default_xai(title, regex_data, mitre_techniques, "regex_only")
        summary = (
            f"Phân tích Regex Baseline cho '{title}': bóc tách {len(regex_data['iocs'])} IOC ứng viên "
            f"và {len(mitre_techniques)} kỹ thuật MITRE ATT&CK."
        )
        return _package_final_result(
            title=title,
            cleaned_text=cleaned_text,
            kept_iocs=regex_data["iocs"],
            dropped_iocs=[],
            threat_actors=regex_data["threat_actors"],
            malware_families=regex_data["malware_families"],
            mitre_techniques=mitre_techniques,
            analysis_mode="regex_only",
            llm_model=None,
            llm_used=False,
            llm_error=None,
            executive_summary=summary,
            xai_report=xai,
        )

    client = llm_client or OllamaClient()
    excerpt = _build_smart_excerpt(title, cleaned_text, regex_data["iocs"])
    candidates_for_prompt = [
        {
            "type": item["type"],
            "value": item["value"],
            "context": (item.get("context_sentence") or "")[:140],
        }
        for item in regex_data["iocs"][:25]
    ]

    user_prompt = (
        f"ARTICLE:\n{excerpt}\n\n"
        f"CANDIDATES:\n{json.dumps(candidates_for_prompt, ensure_ascii=False)}"
    )

    try:
        llm_output = client.chat_json(CTI_SYSTEM_PROMPT, user_prompt, temperature=0.1)
    except Exception as exc:
        xai = _build_default_xai(title, regex_data, mitre_techniques, "regex_fallback")
        summary = (
            f"Local LLM tạm thời không khả dụng ({exc}). Hệ thống tự động dùng Regex Fallback: "
            f"bóc tách {len(regex_data['iocs'])} IOC từ '{title}'."
        )
        return _package_final_result(
            title=title,
            cleaned_text=cleaned_text,
            kept_iocs=regex_data["iocs"],
            dropped_iocs=[],
            threat_actors=regex_data["threat_actors"],
            malware_families=regex_data["malware_families"],
            mitre_techniques=mitre_techniques,
            analysis_mode="regex_fallback",
            llm_model=getattr(client, "model", None),
            llm_used=False,
            llm_error=str(exc),
            executive_summary=summary,
            xai_report=xai,
        )

    # Đối chiếu quyết định LLM kèm Grounding Check nghiêm ngặt
    regex_map: Dict[Tuple[str, str], Dict[str, Any]] = {
        (item["type"].upper(), item["value"].lower()): item for item in regex_data["iocs"]
    }
    val_to_regex_type: Dict[str, str] = {
        item["value"].lower(): item["type"].upper() for item in regex_data["iocs"]
    }
    valid_types = {"IP", "DOMAIN", "URL", "MD5", "SHA256", "CVE"}

    dropped_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for d in llm_output.get("dropped_iocs", []):
        if not isinstance(d, dict) or not d.get("value"):
            continue
        raw_dval = clean_defanged(str(d["value"])).strip()
        raw_dtype = str(d.get("type", "")).strip().upper()
        # Chuẩn hóa lại type nếu LLM ghi dạng ghép hoặc thiếu type
        dtype = raw_dtype if raw_dtype in valid_types else val_to_regex_type.get(raw_dval.lower(), "")
        if not dtype:
            cleaned_dom = sanitize_domain(raw_dval).lower()
            dtype = val_to_regex_type.get(cleaned_dom, raw_dtype or "UNKNOWN")
        dval = _canonicalize_ioc(dtype, raw_dval)
        dropped_map[(dtype, dval.lower())] = {
            "type": dtype,
            "value": dval,
            "reason": str(d.get("reason", "Filtered out by Local LLM context review")),
        }

    kept_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for k in llm_output.get("kept_iocs", []):
        if not isinstance(k, dict) or not k.get("value"):
            continue
        ktype = str(k.get("type", "")).strip().upper()
        kval = _canonicalize_ioc(ktype, str(k["value"]))
        if not _is_grounded_in_text(ktype, kval, cleaned_text):
            continue
        key = (ktype, kval.lower())
        base = regex_map.get(key, {})
        kept_map[key] = {
            "type": ktype,
            "value": kval,
            "confidence": base.get("confidence", 0.90),
            "context_sentence": base.get("context_sentence") or find_context_sentence(cleaned_text, kval),
            "decision_reason": str(k.get("reason", "Verified in article context")),
        }

    # Giữ lại các ứng viên regex nếu LLM không bỏ sót sang danh sách dropped (tránh LLM lười bỏ qua hash/CVE)
    for key, base in regex_map.items():
        if key not in kept_map and key not in dropped_map:
            kept_map[key] = {
                **base,
                "decision_reason": "Preserved from deterministic regex extraction (not flagged as noise)",
            }

    kept_list = sorted(kept_map.values(), key=lambda x: (x["type"], x["value"]))
    dropped_list = sorted(dropped_map.values(), key=lambda x: (x["type"], x["value"]))

    actors = list(regex_data["threat_actors"])
    for a in llm_output.get("threat_actors", []):
        if isinstance(a, str) and a.strip():
            actors.append(a.strip())

    malwares = list(regex_data["malware_families"])
    for m in llm_output.get("malware_families", []):
        if isinstance(m, str) and m.strip():
            malwares.append(m.strip())

    raw_chain = [str(s).strip() for s in llm_output.get("reasoning_chain", []) if str(s).strip()]
    raw_quotes = [str(q).strip() for q in llm_output.get("evidence_quotes", []) if str(q).strip()]
    if not raw_chain:
        raw_chain = _build_default_xai(
            title,
            {"iocs": kept_list, "ips": [], "domains": [], "sha256": [], "md5": [], "cves": []},
            mitre_techniques,
            "hybrid_local_llm",
        )["reasoning_chain"]

    summary = str(llm_output.get("executive_summary") or "").strip()
    if not summary:
        summary = (
            f"Local Agent ({getattr(client, 'model', 'ollama')}) phân tích '{title}': "
            f"giữ lại {len(kept_list)} IOC hợp lệ, loại {len(dropped_list)} nhiễu ngữ cảnh."
        )

    xai_report = {
        "reasoning_chain": raw_chain,
        "evidence_quotes": raw_quotes,
        "trust_note": f"Phân tích bởi mô hình cục bộ {getattr(client, 'model', 'ollama')} kèm kiểm tra Grounding trong văn bản.",
    }

    return _package_final_result(
        title=title,
        cleaned_text=cleaned_text,
        kept_iocs=kept_list,
        dropped_iocs=dropped_list,
        threat_actors=actors,
        malware_families=malwares,
        mitre_techniques=mitre_techniques,
        analysis_mode="hybrid_local_llm",
        llm_model=getattr(client, "model", None),
        llm_used=True,
        llm_error=None,
        executive_summary=summary,
        xai_report=xai_report,
    )
