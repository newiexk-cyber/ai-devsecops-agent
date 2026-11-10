# -*- coding: utf-8 -*-
"""
Unit tests cho Corpus Manager (50 bài gán nhãn tay) & Evaluator đo độ chính xác Agent + Skill.
"""
import json
from pathlib import Path

from src.security.benchmark.corpus_manager import (
    load_corpus,
    save_corpus,
    update_human_annotation,
)
from src.security.benchmark.evaluator import compute_prf, evaluate_cti_benchmark


def _make_sample_corpus(tmp_path: Path) -> Path:
    corpus_path = tmp_path / "cti_corpus.json"
    data = {
        "dataset_name": "CTI Manual Annotation Test Corpus",
        "articles": [
            {
                "article_id": "CTI-01",
                "title": "Akira VPN Intrusion",
                "source": "The Hacker News",
                "url": "https://example.org/cti-01",
                "published_date": "2026-10-01",
                "raw_content": (
                    "Analysts tracked Akira ransomware exploiting CVE-2023-20269. "
                    "Beacon traffic reached 185.220.101.5 and malicious domain akira-c2.top. "
                    "Dropped binary SHA256: 2a5d96b864d26f63f5873752e25d48721c81fa73e6d2bc656b6c00d463fae4bc. "
                    "Unrelated benign domain mentioned in footnotes: vendor-ref.org."
                ),
                "ground_truth": {
                    "ips": ["185.220.101.5"],
                    "domains": ["akira-c2.top"],
                    "urls": [],
                    "md5": [],
                    "sha256": ["2a5d96b864d26f63f5873752e25d48721c81fa73e6d2bc656b6c00d463fae4bc"],
                    "cves": ["CVE-2023-20269"],
                    "threat_actors": [],
                    "malware_families": ["Akira"],
                },
                "annotation_meta": {
                    "status": "human_verified",
                    "annotated_by": "lam",
                    "reviewed_at": "2026-11-10T10:00:00Z",
                    "notes": "Verified manual labels",
                },
            },
            {
                "article_id": "CTI-02",
                "title": "Pending Unreviewed Article",
                "source": "BleepingComputer",
                "url": "https://example.org/cti-02",
                "published_date": "2026-10-02",
                "raw_content": "Some article mentioning 91.240.118.172 not yet annotated.",
                "ground_truth": {
                    "ips": [], "domains": [], "urls": [], "md5": [], "sha256": [], "cves": [],
                    "threat_actors": [], "malware_families": []
                },
                "annotation_meta": {
                    "status": "pending_human_review",
                    "annotated_by": "",
                    "reviewed_at": "",
                    "notes": "",
                },
            },
        ],
    }
    save_corpus(data, path=corpus_path)
    return corpus_path


def test_compute_prf_math():
    metrics = compute_prf(tp=8, fp=2, fn=2)
    assert metrics["precision"] == 80.0
    assert metrics["recall"] == 80.0
    assert metrics["f1"] == 80.0


def test_update_human_annotation_canonicalizes_and_marks_verified(tmp_path):
    corpus_path = _make_sample_corpus(tmp_path)
    updated = update_human_annotation(
        article_id="CTI-02",
        ground_truth={
            "ips": ["91.240.118.172"],
            "domains": ["EVIL-C2.NET"],
            "cves": ["cve-2024-3400"],
        },
        annotated_by="khang",
        notes="Checked manually",
        path=corpus_path,
    )
    assert updated["annotation_meta"]["status"] == "human_verified"
    assert updated["annotation_meta"]["annotated_by"] == "khang"
    assert updated["ground_truth"]["domains"] == ["evil-c2.net"]
    assert updated["ground_truth"]["cves"] == ["CVE-2024-3400"]

    reloaded = load_corpus(corpus_path)
    art2 = next(a for a in reloaded["articles"] if a["article_id"] == "CTI-02")
    assert art2["annotation_meta"]["status"] == "human_verified"


def test_evaluate_cti_benchmark_compares_regex_vs_hybrid_and_skill_rates(tmp_path):
    corpus_path = _make_sample_corpus(tmp_path)

    class SmartMockLLM:
        model = "qwen2.5:3b"

        def chat_json(self, system_prompt, user_prompt, temperature=0.1):
            return {
                "kept_iocs": [
                    {"type": "IP", "value": "185.220.101.5", "reason": "C2 beacon IP"},
                    {"type": "DOMAIN", "value": "akira-c2.top", "reason": "Malicious C2 domain"},
                    {"type": "SHA256", "value": "2a5d96b864d26f63f5873752e25d48721c81fa73e6d2bc656b6c00d463fae4bc", "reason": "Payload"},
                    {"type": "CVE", "value": "CVE-2023-20269", "reason": "Exploited VPN CVE"},
                ],
                "dropped_iocs": [
                    {"type": "DOMAIN", "value": "vendor-ref.org", "reason": "Benign footnote reference"}
                ],
                "threat_actors": [],
                "malware_families": ["Akira"],
                "executive_summary": "Akira campaign summary",
                "reasoning_chain": ["1. C2 IP and domain identified"],
                "evidence_quotes": ["Beacon traffic reached 185.220.101.5"],
            }

    results = evaluate_cti_benchmark(
        corpus_path=corpus_path,
        llm_client=SmartMockLLM(),
        report_md_path=tmp_path / "report.md",
        report_json_path=tmp_path / "results.json",
    )

    assert results["total_corpus_articles"] == 2
    assert results["verified_articles_evaluated"] == 1  # Only CTI-01 is human_verified

    regex_overall = results["modes"]["regex_only"]["overall"]
    hybrid_overall = results["modes"]["hybrid"]["overall"]

    # Regex picks up vendor-ref.org as 1 FP; Hybrid drops it -> higher Precision!
    assert regex_overall["fp"] == 1
    assert hybrid_overall["fp"] == 0
    assert hybrid_overall["precision"] == 100.0
    assert hybrid_overall["recall"] == 100.0

    # Skill verification metrics should be measured for hybrid mode
    skills_stats = results["modes"]["hybrid"]["skill_metrics"]
    assert skills_stats["skills_generated"] == 1
    assert skills_stats["syntax_valid_rate"] == 100.0
    assert skills_stats["sandbox_match_rate"] == 100.0
    assert (tmp_path / "report.md").exists()
