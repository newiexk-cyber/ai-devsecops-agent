# -*- coding: utf-8 -*-
"""
Unit tests cho Hybrid CTI Agent (Regex Context Extractor + Local LLM Filtering & XAI).
"""
import pytest
from src.core.ioc_extractor import extract_iocs_from_text
from src.core.cti_agent import analyze_cti_article


SAMPLE_ARTICLE = """
Security teams observed the Akira ransomware group exploiting CVE-2023-20269 on perimeter VPN gateways.
According to the report published on thehackernews.com and bleepingcomputer.com, patched software version 11.2.4.5 is safe.
However, unpatched endpoints communicated with C2 server 185.220.101[.]5 and downloaded hxxps://evil-drop[.]top/stage.ps1.
Forensic triage recovered payload SHA256 2a5d96b864d26f63f5873752e25d48721c81fa73e6d2bc656b6c00d463fae4bc and contact example-victim.org in background logs.
"""


def test_ioc_extractor_attaches_context_and_filters_version_numbers():
    res = extract_iocs_from_text(SAMPLE_ARTICLE)
    assert "185.220.101.5" in res["ips"]
    assert "11.2.4.5" not in res["ips"], "Software version 11.2.4.5 must not be misclassified as an IP"
    assert "evil-drop.top" in res["domains"]
    assert "thehackernews.com" not in res["domains"]
    assert "CVE-2023-20269" in res["cves"]
    assert "2a5d96b864d26f63f5873752e25d48721c81fa73e6d2bc656b6c00d463fae4bc" in res["sha256"]
    assert any("185.220.101.5" in item["value"] and item.get("context_sentence") for item in res["iocs"])


def test_cti_agent_hybrid_mode_uses_local_llm_filtering_and_blocks_hallucination():
    class FakeLLM:
        model = "qwen2.5:3b"

        def chat_json(self, system_prompt, user_prompt, temperature=0.1):
            return {
                "kept_iocs": [
                    {"type": "IP", "value": "185.220.101.5", "reason": "Confirmed C2 server in article"},
                    {"type": "DOMAIN", "value": "evil-drop.top", "reason": "Malware download domain"},
                    {"type": "SHA256", "value": "2a5d96b864d26f63f5873752e25d48721c81fa73e6d2bc656b6c00d463fae4bc", "reason": "Recovered payload hash"},
                    {"type": "CVE", "value": "CVE-2023-20269", "reason": "Actively exploited vulnerability"},
                    # Hallucinated IP not present in source text -> MUST be blocked by grounding guard
                    {"type": "IP", "value": "99.99.99.99", "reason": "Hallucinated"},
                ],
                "dropped_iocs": [
                    {"type": "DOMAIN", "value": "example-victim.org", "reason": "Benign victim background log reference"}
                ],
                "threat_actors": ["Akira"],
                "malware_families": ["Akira Ransomware"],
                "executive_summary": "Akira ransomware exploited CVE-2023-20269 and beacons to 185.220.101.5.",
                "reasoning_chain": [
                    "1. Article explicitly links Akira campaign to CVE-2023-20269.",
                    "2. Endpoint connects to 185.220.101.5 and evil-drop.top."
                ],
                "evidence_quotes": [
                    "unpatched endpoints communicated with C2 server 185.220.101[.]5"
                ],
            }

    result = analyze_cti_article(
        title="Akira Campaign Report",
        raw_content=SAMPLE_ARTICLE,
        mode="hybrid",
        llm_client=FakeLLM(),
    )

    assert result["analysis_mode"] == "hybrid_local_llm"
    assert result["llm_used"] is True
    assert result["llm_model"] == "qwen2.5:3b"
    assert "185.220.101.5" in result["ips"]
    assert "99.99.99.99" not in result["ips"], "Hallucinated IP must be rejected"
    assert "example-victim.org" not in result["domains"], "LLM-filtered false positive should be dropped"
    assert any(d["value"] == "example-victim.org" for d in result["dropped_iocs"])
    assert "Akira" in result["threat_actors"]
    assert len(result["xai_report"]["reasoning_chain"]) >= 2


def test_cti_agent_graceful_fallback_when_ollama_offline():
    class OfflineLLM:
        model = "qwen2.5:3b"

        def chat_json(self, system_prompt, user_prompt, temperature=0.1):
            raise RuntimeError("Connection refused to 127.0.0.1:11434")

    result = analyze_cti_article(
        title="Akira Campaign Report",
        raw_content=SAMPLE_ARTICLE,
        mode="hybrid",
        llm_client=OfflineLLM(),
    )

    assert result["analysis_mode"] == "regex_fallback"
    assert result["llm_used"] is False
    assert "Connection refused" in result["llm_error"]
    assert "185.220.101.5" in result["ips"]
    assert "CVE-2023-20269" in result["cves"]


def test_cti_agent_drops_ioc_even_when_llm_returns_compound_type():
    class CompoundTypeLLM:
        model = "qwen2.5:3b"

        def chat_json(self, system_prompt, user_prompt, temperature=0.1):
            return {
                "dropped_iocs": [
                    {
                        "type": "IP|DOMAIN|URL|MD5|SHA256|CVE",
                        "value": "example-victim.org",
                        "reason": "Victim background reference",
                    }
                ],
                "threat_actors": ["Akira"],
                "malware_families": [],
                "executive_summary": "Akira C2 summary",
                "reasoning_chain": ["1. Retained C2 IOCs, dropped victim ref."],
                "evidence_quotes": ["C2 server 185.220.101[.]5"],
            }

    result = analyze_cti_article(
        title="Akira Campaign Report",
        raw_content=SAMPLE_ARTICLE,
        mode="hybrid",
        llm_client=CompoundTypeLLM(),
    )
    assert "example-victim.org" not in result["domains"]
    assert result["dropped_iocs"][0]["type"] == "DOMAIN"
    assert result["dropped_iocs"][0]["value"] == "example-victim.org"

