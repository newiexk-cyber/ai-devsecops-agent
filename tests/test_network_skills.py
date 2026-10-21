# -*- coding: utf-8 -*-
"""
Test Suite cho Network Sentinel:
Chuyên sâu An toàn Mạng, Timeline Date, Smart Trigger, Explainable AI (XAI) và Dynamic Agent Skills
"""
import pytest
from src.core.network_cve_catalog import (
    get_network_threat_catalog, filter_network_threats, evaluate_smart_crawl_trigger,
    ingest_live_network_cve, crawl_whitelist_sources
)
from src.core.network_skill_generator import (
    generate_explainable_trust_card, generate_network_agent_skill, list_available_skills
)

def test_network_threat_catalog_contains_network_only():
    threats = get_network_threat_catalog()
    assert len(threats) >= 5
    for item in threats:
        # Mọi threat phải gắn liền với mạng (Cisco, Fortinet, Palo Alto, Ivanti, C2 Botnet)
        assert item["threat_domain"] == "network"
        assert "date_category" in item
        assert "tags" in item
        assert "severity" in item
        assert "severity_color" in item

def test_filter_by_timeline_date():
    # Lọc 24h khẩn cấp
    threats_24h = filter_network_threats(time_window="24h_emergency")
    assert all(t["date_category"] == "24h_emergency" for t in threats_24h)

    # Lọc 30 ngày
    threats_30d = filter_network_threats(time_window="active_30d")
    assert all(t["date_category"] in ["24h_emergency", "active_30d"] for t in threats_30d)

    # Lọc 3 năm
    threats_3y = filter_network_threats(time_window="historical_3y")
    assert len(threats_3y) >= len(threats_30d)

def test_smart_crawl_trigger_evaluation():
    # Khi có 0-Day mới hoặc bùng nổ tấn công -> Nên cào ngay
    decision = evaluate_smart_crawl_trigger(
        high_severity_events=3,
        cisa_network_update=True,
        hours_since_last_crawl=4
    )
    assert decision["should_crawl"] is True
    assert decision["urgency_level"] in ["CRITICAL", "HIGH"]
    assert "reason" in decision

    # Khi không có sự kiện khẩn và mới cào cách đây 15 phút -> Không nên cào
    decision_idle = evaluate_smart_crawl_trigger(
        high_severity_events=0,
        cisa_network_update=False,
        hours_since_last_crawl=0.25
    )
    assert decision_idle["should_crawl"] is False
    assert decision_idle["urgency_level"] == "LOW"

def test_explainable_ai_trust_card():
    threat = get_network_threat_catalog()[0]
    xai_card = generate_explainable_trust_card(threat)
    
    assert "trust_score" in xai_card
    assert 80 <= xai_card["trust_score"] <= 100
    assert len(xai_card["reasoning_chain"]) >= 3
    assert len(xai_card["evidence_sources"]) >= 1
    assert "network_blast_radius" in xai_card

def test_dynamic_agent_skill_generation():
    threat = get_network_threat_catalog()[0]
    skill = generate_network_agent_skill(threat)
    
    assert "skill_name" in skill
    assert "description" in skill
    assert "parameters" in skill
    assert skill["parameters"]["type"] == "object"
    assert "execution_code" in skill
    assert "rollback_skill" in skill
    assert "target_devices" in skill

def test_list_available_skills():
    skills = list_available_skills()
    assert len(skills) >= 4
    skill_names = [s["skill_name"] for s in skills]
    assert "network_virtual_patching" in skill_names
    assert "network_containment_and_isolation" in skill_names
    assert "active_network_exposure_probe" in skill_names

def test_ingest_live_network_cve():
    # Ingest a live network CVE
    threat = ingest_live_network_cve("CVE-2024-38856")
    assert threat is not None
    assert threat["identifier"] == "CVE-2024-38856"
    assert threat["threat_domain"] == "network"
    assert threat["date_category"] in ["24h_emergency", "active_30d"]
    assert "tags" in threat
    assert any("CVE" in t or "Apache" in t or "Network" in t for t in threat["tags"])
    
    # Verify it was added to the catalog at the top
    catalog = get_network_threat_catalog()
    assert catalog[0]["identifier"] == "CVE-2024-38856"

def test_crawl_whitelist_sources_cisa_kev():
    result = crawl_whitelist_sources(source_type="cisa_kev", limit=5)
    assert result["status"] == "success"
    assert "crawled_count" in result
    assert result["crawled_count"] >= 1
    assert "ingested_cves" in result

def test_crawl_whitelist_sources_rss():
    result = crawl_whitelist_sources(source_type="whitelist_rss", limit=5)
    assert result["status"] == "success"
    assert "crawled_count" in result
    assert result["crawled_count"] >= 1


