# -*- coding: utf-8 -*-
r"""
Unit Tests cho toàn bộ module `src/security/` của Khang (Autonomous CTI).
Chạy kiểm thử:
    .\.venv\Scripts\pytest.exe src/security/test_security.py -v
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from shared.schemas import EnrichedIOC, ExtractedIOC, MitreTechnique
from src.security.benchmark.cti_benchmark import run_cti_benchmark
from src.security.enrichment_service import (
    SQLiteThreatCache,
    check_abuseipdb,
    check_virustotal,
    enrich_ioc,
)
from src.security.stix_converter import export_stix_package


def test_tool3_check_virustotal_and_sqlite_cache(tmp_path):
    cache = SQLiteThreatCache(tmp_path / "test_cache.sqlite")
    # Kiểm tra IP độc hại
    res1 = check_virustotal("185.220.101.14", ioc_type="IP", cache=cache)
    assert res1["is_malicious"] is True
    assert res1["reputation_score"] >= 70
    assert res1["cached"] is False

    # Lần gọi thứ 2 phải lấy từ SQLite Cache
    res2 = check_virustotal("185.220.101.14", ioc_type="IP", cache=cache)
    assert res2["cached"] is True
    assert res2["reputation_score"] == res1["reputation_score"]

    # Kiểm tra DNS hợp pháp (Benign Whitelist)
    benign = check_virustotal("8.8.8.8", ioc_type="IP", cache=cache)
    assert benign["is_malicious"] is False
    assert benign["reputation_score"] == 0


def test_tool4_check_abuseipdb(tmp_path):
    cache = SQLiteThreatCache(tmp_path / "test_abuse.sqlite")
    mal_ip = check_abuseipdb("185.220.101.14", cache=cache)
    assert mal_ip["is_malicious"] is True
    assert mal_ip["abuse_confidence_score"] > 80

    safe_ip = check_abuseipdb("192.168.1.1", cache=cache)
    assert safe_ip["is_malicious"] is False
    assert safe_ip["abuse_confidence_score"] == 0


def test_enrich_ioc_schema_compliance(tmp_path):
    cache = SQLiteThreatCache(tmp_path / "test_schema.sqlite")
    raw_ioc = ExtractedIOC(
        ioc_type="IP",
        value="185.220.101[.]14",
        context_sentence="Connected to C2 server 185.220.101[.]14",
        confidence=0.95,
    )
    enriched = enrich_ioc(raw_ioc, cache=cache)
    assert isinstance(enriched, EnrichedIOC)
    assert enriched.ioc.value == "185.220.101.14"
    assert enriched.is_malicious is True
    assert enriched.reputation_score > 80


def test_tool5_export_stix_package():
    ioc = EnrichedIOC(
        ioc=ExtractedIOC(
            ioc_type="DOMAIN",
            value="lockbit-decryptor-portal.top",
            context_sentence="Ransomware C2 domain",
        ),
        is_malicious=True,
        reputation_score=92,
        enrichment_source="VirusTotal",
    )
    mitre = MitreTechnique(
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        tactic="Impact",
        evidence="Encrypted files with .lockbit extension",
    )
    bundle = export_stix_package(
        report_or_title="LockBit 3.0 Campaign Analysis",
        enriched_iocs=[ioc],
        mitre_techniques=[mitre],
        threat_actors=["LockBit 3.0"],
    )
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    sdo_types = {obj["type"] for obj in bundle["objects"]}
    assert {"identity", "threat-actor", "indicator", "attack-pattern", "relationship", "report"}.issubset(sdo_types)


def test_cti_benchmark_30_apt_reports():
    summary = run_cti_benchmark()
    assert summary["total_reports"] == 30
    assert summary["enriched_metrics"]["TP"] == 120
    assert summary["enriched_metrics"]["FP"] == 0
    assert summary["enriched_metrics"]["Precision"] == 100.0
    assert summary["enriched_metrics"]["Recall"] == 100.0
    assert summary["valid_stix_bundles"] == 30
