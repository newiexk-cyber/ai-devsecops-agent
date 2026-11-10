# -*- coding: utf-8 -*-
"""
BENCHMARK EVALUATOR - ĐO ĐỘ CHÍNH XÁC AGENT TRÍCH IOC & KIỂM CHỨNG SKILL (KHANG & PHÚC)
Đối chiếu kết quả phân tích của Agent (`regex_only` vs `hybrid` Local LLM)
với tập đáp án gán nhãn tay (`human_verified`) trong bộ 50 bài báo CTI.
Đo thực nghiệm:
1. TP, FP, FN, Precision, Recall, F1-Score theo từng loại IOC (IP, DOMAIN, MD5, SHA256, CVE) và tổng thể.
2. Tỷ lệ Agent Skill sinh ra hợp lệ cú pháp AST & compile().
3. Tỷ lệ Agent Skill bắt trúng mẫu thử dương tính và không báo nhầm mẫu sạch trong sandbox.
4. Báo cáo phân tích lỗi chi tiết từng bài (false positives & false negatives).
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from src.core.cti_agent import analyze_cti_article
from src.core.skill_synthesizer import synthesize_cti_skill
from src.security.benchmark.corpus_manager import DEFAULT_CORPUS_PATH, load_corpus

ROOT_DIR = Path(__file__).resolve().parents[3]
DEFAULT_REPORT_MD_PATH = ROOT_DIR / "data" / "benchmark" / "latest_benchmark_report.md"
DEFAULT_REPORT_JSON_PATH = ROOT_DIR / "data" / "benchmark" / "latest_benchmark_results.json"

IOC_EVAL_FIELDS = [
    ("IP", "ips"),
    ("DOMAIN", "domains"),
    ("MD5", "md5"),
    ("SHA256", "sha256"),
    ("CVE", "cves"),
]


def compute_prf(tp: int, fp: int, fn: int) -> Dict[str, Any]:
    precision = (tp / (tp + fp) * 100.0) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn) * 100.0) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 2),
        "recall": round(recall, 2),
        "f1": round(f1, 2),
    }


def _extract_gt_sets(gt: Dict[str, Any]) -> Dict[str, Set[str]]:
    return {
        "IP": {str(x).strip() for x in gt.get("ips", []) if str(x).strip()},
        "DOMAIN": {str(x).strip().lower() for x in gt.get("domains", []) if str(x).strip()},
        "MD5": {str(x).strip().lower() for x in gt.get("md5", []) if str(x).strip()},
        "SHA256": {str(x).strip().lower() for x in gt.get("sha256", []) if str(x).strip()},
        "CVE": {str(x).strip().upper() for x in gt.get("cves", []) if str(x).strip()},
    }


def _extract_pred_sets(analysis: Dict[str, Any]) -> Dict[str, Set[str]]:
    return {
        "IP": {str(x).strip() for x in analysis.get("ips", []) if str(x).strip()},
        "DOMAIN": {str(x).strip().lower() for x in analysis.get("domains", []) if str(x).strip()},
        "MD5": {str(x).strip().lower() for x in analysis.get("md5", []) if str(x).strip()},
        "SHA256": {str(x).strip().lower() for x in analysis.get("sha256", []) if str(x).strip()},
        "CVE": {str(x).strip().upper() for x in analysis.get("cves", []) if str(x).strip()},
    }


def _evaluate_single_mode(
    articles: List[Dict[str, Any]],
    mode: str,
    llm_client: Optional[Any] = None,
) -> Dict[str, Any]:
    per_type_counts: Dict[str, Dict[str, int]] = {
        label: {"tp": 0, "fp": 0, "fn": 0} for label, _ in IOC_EVAL_FIELDS
    }
    article_details: List[Dict[str, Any]] = []

    skills_eligible = 0
    skills_generated = 0
    skills_syntax_valid = 0
    skills_sandbox_matched = 0
    llm_fallback_count = 0

    for art in articles:
        title = art.get("title", "")
        raw_content = art.get("raw_content", "")
        gt_sets = _extract_gt_sets(art.get("ground_truth", {}))

        analysis = analyze_cti_article(
            title=title,
            raw_content=raw_content,
            mode=mode,
            llm_client=llm_client,
        )
        if analysis.get("analysis_mode") == "regex_fallback":
            llm_fallback_count += 1

        pred_sets = _extract_pred_sets(analysis)

        art_fp: List[Dict[str, str]] = []
        art_fn: List[Dict[str, str]] = []
        art_tp = 0

        for label, _ in IOC_EVAL_FIELDS:
            gt_items = gt_sets[label]
            pred_items = pred_sets[label]

            matched = gt_items & pred_items
            fps = sorted(pred_items - gt_items)
            fns = sorted(gt_items - pred_items)

            per_type_counts[label]["tp"] += len(matched)
            per_type_counts[label]["fp"] += len(fps)
            per_type_counts[label]["fn"] += len(fns)
            art_tp += len(matched)

            for v in fps:
                art_fp.append({"type": label, "value": v})
            for v in fns:
                art_fn.append({"type": label, "value": v})

        has_any_pred_ioc = any(len(pred_sets[label]) > 0 for label, _ in IOC_EVAL_FIELDS)
        skill_syntax_ok = None
        skill_sandbox_ok = None

        if has_any_pred_ioc:
            skills_eligible += 1
            try:
                skill_obj = synthesize_cti_skill(analysis)
                skills_generated += 1
                ver = skill_obj.get("verification", {})
                skill_syntax_ok = bool(ver.get("syntax_valid") and ver.get("ast_safe"))
                skill_sandbox_ok = bool(ver.get("sandbox_verified"))
                if skill_syntax_ok:
                    skills_syntax_valid += 1
                if skill_sandbox_ok:
                    skills_sandbox_matched += 1
            except Exception:
                skill_syntax_ok = False
                skill_sandbox_ok = False

        article_details.append({
            "article_id": art.get("article_id"),
            "title": title,
            "annotated_by": art.get("annotation_meta", {}).get("annotated_by", ""),
            "actual_analysis_mode": analysis.get("analysis_mode"),
            "tp": art_tp,
            "fp_count": len(art_fp),
            "fn_count": len(art_fn),
            "false_positives": art_fp,
            "false_negatives": art_fn,
            "skill_syntax_valid": skill_syntax_ok,
            "skill_sandbox_matched": skill_sandbox_ok,
        })

    total_tp = sum(v["tp"] for v in per_type_counts.values())
    total_fp = sum(v["fp"] for v in per_type_counts.values())
    total_fn = sum(v["fn"] for v in per_type_counts.values())

    per_type_metrics = {
        label: compute_prf(c["tp"], c["fp"], c["fn"]) for label, c in per_type_counts.items()
    }

    syntax_rate = (skills_syntax_valid / skills_generated * 100.0) if skills_generated > 0 else 0.0
    sandbox_rate = (skills_sandbox_matched / skills_generated * 100.0) if skills_generated > 0 else 0.0

    return {
        "mode": mode,
        "overall": compute_prf(total_tp, total_fp, total_fn),
        "per_type": per_type_metrics,
        "llm_fallback_count": llm_fallback_count,
        "skill_metrics": {
            "articles_with_iocs": skills_eligible,
            "skills_generated": skills_generated,
            "skills_syntax_valid": skills_syntax_valid,
            "skills_sandbox_matched": skills_sandbox_matched,
            "syntax_valid_rate": round(syntax_rate, 2),
            "sandbox_match_rate": round(sandbox_rate, 2),
        },
        "article_details": article_details,
    }


def _render_markdown_report(results: Dict[str, Any]) -> str:
    lines = [
        "# Báo Cáo Đánh Giá Thực Nghiệm Agent CTI & Sinh Kỹ Năng (Ground Truth Gán Tay)",
        "",
        f"- **Thời điểm chạy (UTC):** `{results['evaluated_at_utc']}`",
        f"- **Tổng bài trong corpus:** {results['total_corpus_articles']}",
        f"- **Số bài đã gán nhãn tay (`human_verified`) được chấm:** {results['verified_articles_evaluated']}",
        "",
        "## 1. So sánh Độ Chính Xác Trích Xuất IOC (Regex Baseline vs Local LLM Hybrid)",
        "",
        "| Chế độ phân tích | TP | FP | FN | Precision (%) | Recall (%) | F1-Score (%) | Skill Syntax (%) | Skill Sandbox Match (%) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]
    for mode_name, mdata in results.get("modes", {}).items():
        ov = mdata["overall"]
        sk = mdata["skill_metrics"]
        lines.append(
            f"| `{mode_name}` | {ov['tp']} | {ov['fp']} | {ov['fn']} | "
            f"{ov['precision']}% | {ov['recall']}% | {ov['f1']}% | "
            f"{sk['syntax_valid_rate']}% ({sk['skills_syntax_valid']}/{sk['skills_generated']}) | "
            f"{sk['sandbox_match_rate']}% ({sk['skills_sandbox_matched']}/{sk['skills_generated']}) |"
        )

    lines.extend(["", "## 2. Chi tiết theo từng loại IOC", ""])
    for mode_name, mdata in results.get("modes", {}).items():
        lines.append(f"### Chế độ `{mode_name}`")
        lines.append("| Loại IOC | TP | FP | FN | Precision (%) | Recall (%) | F1-Score (%) |")
        lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |")
        for ioc_type, stats in mdata["per_type"].items():
            lines.append(
                f"| {ioc_type} | {stats['tp']} | {stats['fp']} | {stats['fn']} | "
                f"{stats['precision']}% | {stats['recall']}% | {stats['f1']}% |"
            )
        lines.append("")

    return "\n".join(lines)


def evaluate_cti_benchmark(
    corpus_path: Path = DEFAULT_CORPUS_PATH,
    modes: Iterable[str] = ("regex_only", "hybrid"),
    include_pending: bool = False,
    llm_client: Optional[Any] = None,
    report_md_path: Path = DEFAULT_REPORT_MD_PATH,
    report_json_path: Path = DEFAULT_REPORT_JSON_PATH,
) -> Dict[str, Any]:
    """
    Chạy đánh giá thực nghiệm trên tập bài báo đã gán nhãn tay.
    Mặc định CHỈ chấm trên bài `annotation_meta.status == 'human_verified'`.
    """
    corpus = load_corpus(corpus_path)
    all_articles = corpus.get("articles", [])

    if include_pending:
        target_articles = all_articles
    else:
        target_articles = [
            a for a in all_articles
            if a.get("annotation_meta", {}).get("status") == "human_verified"
        ]

    verified_count = sum(
        1 for a in all_articles
        if a.get("annotation_meta", {}).get("status") == "human_verified"
    )

    mode_results: Dict[str, Any] = {}
    for m in modes:
        mode_results[m] = _evaluate_single_mode(target_articles, mode=m, llm_client=llm_client)

    results = {
        "evaluated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_corpus_articles": len(all_articles),
        "human_verified_total": verified_count,
        "verified_articles_evaluated": len(target_articles),
        "modes": mode_results,
    }

    md_target = Path(report_md_path)
    md_target.parent.mkdir(parents=True, exist_ok=True)
    md_target.write_text(_render_markdown_report(results), encoding="utf-8")

    json_target = Path(report_json_path)
    json_target.parent.mkdir(parents=True, exist_ok=True)
    json_target.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")

    return results
