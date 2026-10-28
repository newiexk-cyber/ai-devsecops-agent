# -*- coding: utf-8 -*-
r"""
TEST SUITE FOR SECURITY AUDIT & ARCHITECTURAL FIXES
Kiểm thử các điểm an toàn P0 và các cải tiến kiến trúc:
1. P0: Fallback Enrichment không sinh điểm số giả, trả về verdict 'unknown', confidence 0, is_verified False
2. P0: Xác thực định dạng CVE nghiêm ngặt (^CVE-\d{4}-\d{4,}$)
3. P0: Dynamic Skill thực thi trạng thái DRY_RUN an toàn và kiểm tra compile()
4. Phòng thủ: Sigma rule không chèn IOC giả (127.0.0.1) và raise ValueError khi không có IOC
5. Phòng thủ: YARA rule dùng module hash chuẩn, không ép header MZ cho non-PE
6. Phòng thủ: Firewall blocklist hỗ trợ phân tách định dạng iptables, nftables, dnsmasq
7. Chuẩn STIX 2.1: Đầy đủ relationship (indicates) liên kết indicator -> attack-pattern
8. SAST: Phân tích Rule-based Static Analysis, cờ needs_review và AST validation
9. MITRE: Word boundary matching và lọc câu phủ định (negation filter)
10. IOC Extractor: Khử defang đa dạng (case-insensitive), canonical casing và deterministic sort
11. Database: Cấu hình WAL, foreign keys, busy_timeout=5000 và composite unique key
"""
import pytest
import sqlite3
from src.security.enrichment_service import enrich_ioc
from src.automation.collectors.cisa_collector import fetch_cve_by_id
from src.core.rule_generator import (
    generate_sigma_rule, generate_yara_rule, generate_firewall_blocklist, generate_stix_bundle
)
from src.core.network_skill_generator import generate_network_agent_skill
from src.core.mitre_mapper import map_mitre_techniques
from src.core.ioc_extractor import extract_iocs_from_text, clean_defanged
from src.core.sast_analyzer import analyze_code
from src.automation.storage.database import get_db_connection


def test_enrichment_does_not_fabricate_fake_scores():
    """P0 Check: Khi không có API Key, hệ thống không được gán điểm độc hại giả."""
    result = enrich_ioc("IP", "198.51.100.1")
    
    assert result["verdict"] == "unknown"
    assert result["is_malicious"] is False
    assert result["confidence"] == 0
    assert result["is_verified"] is False
    assert result["enrichment_source"] == "no_verified_provider"


def test_cve_strict_validation():
    """P0 Check: CVE không đúng định dạng ^CVE-\\d{4}-\\d{4,}$ phải bị từ chối bằng ValueError."""
    with pytest.raises(ValueError, match="Định dạng mã CVE không hợp lệ"):
        fetch_cve_by_id("CVE-HELLO")

    with pytest.raises(ValueError, match="Định dạng mã CVE không hợp lệ"):
        fetch_cve_by_id("CVE-123")

    # Với CVE hợp lệ nhưng không tồn tại trên CISA KEV / NVD
    res_not_found = fetch_cve_by_id("CVE-2099-99999")
    assert res_not_found["status"] == "not_found"
    assert res_not_found["is_verified"] is False


def test_dynamic_skill_safe_execution_state_and_compilation():
    """P0 Check: Dynamic skill chỉ trả DRY_RUN / NOT_IMPLEMENTED, không trả ENFORCED khi chưa có phần cứng."""
    sample_threat = {
        "id": "NET-TEST-001",
        "identifier": "CVE-2024-3400",
        "threat_type": "FIREWALL_EXPLOIT",
        "title": "Palo Alto PAN-OS Test",
        "target_ip_range": "203.0.113.0/24",
        "protocol": "TCP/443"
    }
    skill = generate_network_agent_skill(sample_threat)
    assert skill["execution_status"] in ["DRY_RUN", "NOT_IMPLEMENTED"]
    assert "ENFORCED" not in skill["execution_status"]
    assert skill["code_compiled_successfully"] is True
    # Đảm bảo mã thực thi an toàn không gây lỗi biên dịch
    compiled = compile(skill["execution_code"], "<test_skill>", "exec")
    assert compiled is not None


def test_sigma_generator_rejects_empty_iocs():
    """Sinh Sigma rule không được chèn 127.0.0.1 hay malicious.example; phải raise ValueError nếu không có IOC."""
    with pytest.raises(ValueError, match="No valid network IOC"):
        generate_sigma_rule("Empty Threat", [], [])

    # Khi có IOC hợp lệ
    valid_iocs = [{"type": "IP", "value": "185.220.101.5"}]
    rule = generate_sigma_rule("Valid Threat", valid_iocs, [])
    assert "185.220.101.5" in rule
    assert "127.0.0.1" not in rule
    assert "malicious.example" not in rule


def test_yara_generator_uses_hash_module_and_no_forced_mz():
    """YARA rule phải dùng import 'hash' và hash.sha256/md5 thay vì tìm chuỗi thô, và không ép MZ header cho domain."""
    domain_iocs = [{"type": "DOMAIN", "value": "c2-command.org"}]
    rule_dom = generate_yara_rule("Domain Threat", domain_iocs, enforce_pe_header=False)
    assert "c2-command.org" in rule_dom
    assert "uint16(0) == 0x5A4D" not in rule_dom

    hash_iocs = [{"type": "SHA256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]
    rule_hash = generate_yara_rule("Hash Threat", hash_iocs)
    assert 'import "hash"' in rule_hash
    assert 'hash.sha256(0, filesize) ==' in rule_hash


def test_firewall_blocklist_formatting():
    """Hỗ trợ phân tách các định dạng iptables, nftables, dnsmasq."""
    iocs = [
        {"type": "IP", "value": "185.220.101.5"},
        {"type": "DOMAIN", "value": "evil-c2.net"}
    ]
    iptables = generate_firewall_blocklist(iocs, format_type="iptables")
    assert "iptables -A INPUT -s 185.220.101.5 -j DROP" in iptables

    nftables = generate_firewall_blocklist(iocs, format_type="nftables")
    assert "add rule inet filter input ip saddr 185.220.101.5 drop" in nftables

    dnsmasq = generate_firewall_blocklist(iocs, format_type="dnsmasq")
    assert "address=/evil-c2.net/0.0.0.0" in dnsmasq


def test_stix_bundle_contains_relationships():
    """STIX Bundle phải có đối tượng relationship liên kết indicator -> attack-pattern."""
    iocs = [{"type": "IP", "value": "185.220.101.5", "is_verified": True}]
    mitre = [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"}]
    bundle = generate_stix_bundle("Test Incident", iocs, mitre)

    objects = bundle["objects"]
    obj_types = [o["type"] for o in objects]
    assert "identity" in obj_types
    assert "indicator" in obj_types
    assert "attack-pattern" in obj_types
    assert "relationship" in obj_types
    assert "report" in obj_types

    rel = next(o for o in objects if o["type"] == "relationship")
    assert rel["relationship_type"] == "indicates"


def test_mitre_mapper_word_boundary_and_negation():
    """MITRE Mapper phải khớp từ khóa theo boundary và bỏ qua câu phủ định."""
    # Câu phủ định: không được ánh xạ
    negated_text = "The internal network has no evidence of ransomware and is not vulnerable to remote code execution."
    neg_res = map_mitre_techniques(negated_text)
    assert len(neg_res) == 0

    # Câu khẳng định: được ánh xạ chính xác
    affirmed_text = "The adversary deployed ransomware that encrypted files across internal network."
    aff_res = map_mitre_techniques(affirmed_text)
    assert len(aff_res) >= 1
    assert any(m["technique_id"] == "T1486" for m in aff_res)
    assert "evidence_sentence" in aff_res[0]


def test_ioc_extractor_defang_and_canonicalization():
    """Khử defang hoa thường (HXXP, [.]) và chuẩn hóa casing."""
    text = "Malware beaconing to HXXPS://EVIL-DOMAIN[.]COM:8443 from IP 185.220.101.5 exploiting cve-2024-21887"
    extracted = extract_iocs_from_text(text)

    assert "evil-domain.com" in extracted["domains"]
    assert "185.220.101.5" in extracted["ips"]
    assert "CVE-2024-21887" in extracted["cves"]


def test_sast_rule_based_mode():
    """SAST phải trả analysis_type là rule_based_heuristic và cờ needs_review."""
    py_code = """
import os
def run_command(cmd):
    return os.system(cmd)
"""
    res = analyze_code(py_code, language="python")
    assert res["status"] == "success"
    assert res["analysis_type"] == "rule_based_heuristic"
    assert res["needs_review"] is True
    assert res["confidence"] == 0.70
    assert res["is_syntax_valid"] is True


def test_database_connection_pragmas():
    """Database SQLite phải được cấu hình WAL, foreign keys, và busy_timeout."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode;")
        journal = cur.fetchone()[0]
        assert journal.lower() == "wal"

        cur.execute("PRAGMA foreign_keys;")
        fk = cur.fetchone()[0]
        assert fk == 1

        cur.execute("PRAGMA busy_timeout;")
        bt = cur.fetchone()[0]
        assert bt == 5000
    finally:
        conn.close()
