# -*- coding: utf-8 -*-
"""
Unit tests cho Enrichment Service (Hợp nhất Khang + Security Audit P0).
Đảm bảo không bao giờ bịa dữ liệu giả khi thiếu API key hoặc feed không xác nhận.
"""
import pytest
import httpx

import src.security.enrichment_service as enrich_mod


def test_enrichment_shodan_internetdb_verified_response(monkeypatch):
    class FakeResp:
        status_code = 200

        def json(self):
            return {
                "ip": "45.33.32.156",
                "ports": [22, 80, 443],
                "vulns": ["CVE-2023-1234", "CVE-2024-5678"],
                "hostnames": ["scanme.test"],
                "tags": ["cloud"],
            }

    class FakeClient:
        def __init__(self, timeout=3.0):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, url, **kwargs):
            return FakeResp()

    monkeypatch.setattr(httpx, "Client", FakeClient)
    # Use a fresh unique test IP to avoid stale cache
    res = enrich_mod.enrich_ioc("IP", "45.33.32.156", use_cache=False)

    assert res["is_verified"] is True
    assert res["enrichment_source"] == "Shodan InternetDB"
    assert res["reputation_score"] >= 60
    assert res["details"]["ports"] == [22, 80, 443]
    assert "CVE-2023-1234" in res["details"]["vulns"]


def test_enrichment_malwarebazaar_and_openphish_feed_lookup(monkeypatch):
    sample_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    sample_domain = "phish-login-portal.example"

    monkeypatch.setattr(enrich_mod, "_fetch_malwarebazaar_hashes", lambda: {sample_hash})
    monkeypatch.setattr(enrich_mod, "_fetch_openphish_domains", lambda: {sample_domain})

    hash_res = enrich_mod.enrich_ioc("SHA256", sample_hash, use_cache=False)
    assert hash_res["is_verified"] is True
    assert hash_res["is_malicious"] is True
    assert hash_res["enrichment_source"] == "Abuse.ch MalwareBazaar"

    dom_res = enrich_mod.enrich_ioc("DOMAIN", sample_domain, use_cache=False)
    assert dom_res["is_verified"] is True
    assert dom_res["is_malicious"] is True
    assert dom_res["enrichment_source"] == "OpenPhish Live Feed"


def test_enrichment_returns_unknown_when_no_provider_matches(monkeypatch):
    class NotFoundClient:
        def __init__(self, timeout=3.0):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, url, **kwargs):
            raise httpx.ConnectError("Offline")

    monkeypatch.setattr(httpx, "Client", NotFoundClient)
    monkeypatch.setattr(enrich_mod, "_fetch_malwarebazaar_hashes", lambda: set())
    monkeypatch.setattr(enrich_mod, "_fetch_openphish_domains", lambda: set())

    res = enrich_mod.enrich_ioc("IP", "198.51.100.77", use_cache=False)
    assert res["verdict"] == "unknown"
    assert res["is_malicious"] is False
    assert res["is_verified"] is False
    assert res["confidence"] == 0
    assert res["enrichment_source"] == "no_verified_provider"
