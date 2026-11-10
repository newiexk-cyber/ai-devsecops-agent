# -*- coding: utf-8 -*-
"""
==============================================================================
THREAT ENRICHMENT SERVICE (KHANG)
Tích hợp làm giàu dữ liệu IOC đa nguồn thật kèm bộ đệm SQLite Caching:
- Nguồn có API Key: VirusTotal v3, AbuseIPDB v2
- Nguồn mở không cần API Key: Shodan InternetDB, Abuse.ch MalwareBazaar, OpenPhish
- Bảo toàn tính trung thực dữ liệu: tuyệt đối không tự bịa điểm độc hại giả khi thiếu bằng chứng.
==============================================================================
"""
import ipaddress
import json
import os
import time
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import httpx

from src.automation.storage.database import get_db_connection

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() in ("true", "1", "yes")

_FEED_TTL_SEC = 1800
_MALWAREBAZAAR_CACHE: Optional[Set[str]] = None
_MALWAREBAZAAR_CACHE_AT: float = 0.0
_OPENPHISH_CACHE: Optional[Set[str]] = None
_OPENPHISH_CACHE_AT: float = 0.0

_DOCUMENTATION_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)


def _is_non_routable_or_test_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or ip_obj.is_link_local
            or ip_obj.is_unspecified
        ):
            return True
        if any(ip_obj in net for net in _DOCUMENTATION_NETS):
            return True
        return False
    except ValueError:
        return True


def _fetch_malwarebazaar_hashes() -> Set[str]:
    """Kéo danh sách SHA256 mã độc mới nhất từ Abuse.ch MalwareBazaar (có cache 30 phút)."""
    global _MALWAREBAZAAR_CACHE, _MALWAREBAZAAR_CACHE_AT
    now = time.time()
    if _MALWAREBAZAAR_CACHE is not None and (now - _MALWAREBAZAAR_CACHE_AT) < _FEED_TTL_SEC:
        return _MALWAREBAZAAR_CACHE

    hashes: Set[str] = set()
    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.get("https://bazaar.abuse.ch/export/txt/sha256/recent/")
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    h = line.strip().lower()
                    if len(h) == 64 and not h.startswith("#"):
                        hashes.add(h)
    except Exception:
        pass

    _MALWAREBAZAAR_CACHE = hashes
    _MALWAREBAZAAR_CACHE_AT = now
    return hashes


def _fetch_openphish_domains() -> Set[str]:
    """Kéo danh sách domain phishing hoạt động từ OpenPhish Live Feed (có cache 30 phút)."""
    global _OPENPHISH_CACHE, _OPENPHISH_CACHE_AT
    now = time.time()
    if _OPENPHISH_CACHE is not None and (now - _OPENPHISH_CACHE_AT) < _FEED_TTL_SEC:
        return _OPENPHISH_CACHE

    domains: Set[str] = set()
    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.get("https://openphish.com/feed.txt")
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    u = line.strip()
                    if u:
                        host = (urlparse(u).hostname or "").strip().lower()
                        if host:
                            domains.add(host)
    except Exception:
        pass

    _OPENPHISH_CACHE = domains
    _OPENPHISH_CACHE_AT = now
    return domains


def _query_shodan_internetdb(ip_str: str) -> Optional[Dict[str, Any]]:
    """Tra cứu miễn phí thông tin cổng mở và lỗ hổng CVE gắn trên IP từ Shodan InternetDB."""
    if _is_non_routable_or_test_ip(ip_str):
        return None
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(f"https://internetdb.shodan.io/{ip_str}")
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return None


def enrich_ioc(ioc_type: str, ioc_value: str, use_cache: bool = True) -> Dict[str, Any]:
    """
    Kiểm tra danh tiếng IOC kèm bộ đệm SQLite.
    Tuyệt đối không sinh dữ liệu giả khi thiếu API key hoặc không có nguồn xác thực.
    """
    clean_type = ioc_type.strip().upper()
    clean_val = ioc_value.strip()

    if use_cache:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM ioc_reputation_cache WHERE ioc_type = ? AND ioc_value = ?",
                (clean_type, clean_val),
            )
            cached = cursor.fetchone()
            if cached:
                details = json.loads(cached["details_json"]) if cached["details_json"] else {}
                is_verified = bool(cached["is_verified"]) if "is_verified" in cached.keys() else False
                is_demo = bool(cached["is_demo"]) if "is_demo" in cached.keys() else False
                return {
                    "type": cached["ioc_type"],
                    "value": cached["ioc_value"],
                    "verdict": "malicious" if bool(cached["is_malicious"]) else ("suspicious" if is_demo else "unknown"),
                    "is_malicious": bool(cached["is_malicious"]),
                    "reputation_score": cached["reputation_score"],
                    "confidence": round(cached["reputation_score"] / 100.0, 2),
                    "enrichment_source": cached["enrichment_source"],
                    "is_verified": is_verified,
                    "is_demo": is_demo,
                    "details": details,
                }
        finally:
            conn.close()

    score = 0
    is_mal = False
    source = "no_verified_provider"
    is_verified = False
    is_demo = False
    verdict = "unknown"
    details: Dict[str, Any] = {}

    vt_key = os.getenv("VIRUSTOTAL_API_KEY", VT_API_KEY)
    abuse_key = os.getenv("ABUSEIPDB_API_KEY", ABUSE_API_KEY)

    # 1. VirusTotal API v3 (Hash / Domain)
    if vt_key and clean_type in {"SHA256", "MD5", "DOMAIN"}:
        try:
            resource_kind = "files" if clean_type in {"SHA256", "MD5"} else "domains"
            endpoint = f"https://www.virustotal.com/api/v3/{resource_kind}/{clean_val}"
            with httpx.Client(timeout=4.0) as client:
                res = client.get(endpoint, headers={"x-apikey": vt_key})
                if res.status_code == 200:
                    data = res.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious_votes = stats.get("malicious", 0)
                    total_votes = sum(stats.values()) or 70
                    score = int((malicious_votes / total_votes) * 100)
                    is_mal = malicious_votes >= 3
                    verdict = "malicious" if is_mal else "clean"
                    source = "VirusTotal API v3"
                    is_verified = True
                    details = {"stats": stats, "provider": "VirusTotal v3"}
        except Exception as exc:
            details = {"provider_error": f"VirusTotal query failed: {exc}"}

    # 2. AbuseIPDB API v2 (IP)
    elif abuse_key and clean_type == "IP":
        try:
            with httpx.Client(timeout=4.0) as client:
                res = client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": abuse_key, "Accept": "application/json"},
                    params={"ipAddress": clean_val, "maxAgeInDays": "90"},
                )
                if res.status_code == 200:
                    data = res.json().get("data", {})
                    score = int(data.get("abuseConfidenceScore", 0))
                    is_mal = score >= 50
                    verdict = "malicious" if is_mal else "clean"
                    source = "AbuseIPDB API"
                    is_verified = True
                    details = data
        except Exception as exc:
            details = {"provider_error": f"AbuseIPDB query failed: {exc}"}

    # 3. Đối chiếu nguồn mở thật không cần API key
    if not is_verified:
        if clean_type == "IP":
            shodan_data = _query_shodan_internetdb(clean_val)
            if shodan_data:
                vulns = shodan_data.get("vulns", [])
                ports = shodan_data.get("ports", [])
                is_verified = True
                source = "Shodan InternetDB"
                if vulns:
                    score = min(90, 50 + len(vulns) * 10)
                    is_mal = len(vulns) >= 2
                    verdict = "malicious" if is_mal else "suspicious"
                else:
                    score = 15 if ports else 0
                    is_mal = False
                    verdict = "clean"
                details = {
                    "ports": ports,
                    "vulns": vulns,
                    "hostnames": shodan_data.get("hostnames", []),
                    "tags": shodan_data.get("tags", []),
                }

        elif clean_type == "SHA256":
            mb_hashes = _fetch_malwarebazaar_hashes()
            if clean_val.lower() in mb_hashes:
                is_verified = True
                is_mal = True
                score = 95
                verdict = "malicious"
                source = "Abuse.ch MalwareBazaar"
                details = {"status": "listed_in_recent_malware_feed"}

        elif clean_type in {"DOMAIN", "URL"}:
            host = (urlparse(clean_val).hostname or clean_val).strip().lower()
            op_domains = _fetch_openphish_domains()
            if host in op_domains:
                is_verified = True
                is_mal = True
                score = 92
                verdict = "malicious"
                source = "OpenPhish Live Feed"
                details = {"status": "listed_in_active_phishing_feed", "host": host}

    # 4. Nếu vẫn chưa có nhà cung cấp nào xác nhận: trả về unknown (không bịa điểm)
    if not is_verified:
        demo_enabled = os.getenv("DEMO_MODE", str(DEMO_MODE)).lower() in ("true", "1", "yes")
        if demo_enabled:
            score = 50
            is_mal = False
            verdict = "suspicious"
            source = "demo_heuristic"
            is_demo = True
            details = {
                "status": "demo_simulation",
                "note": "Dữ liệu mô phỏng do DEMO_MODE=true; không dùng để chặn production.",
            }
        else:
            score = 0
            is_mal = False
            verdict = "unknown"
            source = "no_verified_provider"
            is_demo = False
            details.setdefault("status", "unverified")
            details.setdefault(
                "reason",
                "Chưa có kết quả từ VirusTotal/AbuseIPDB hoặc các nguồn mở xác thực.",
            )

    if use_cache:
        conn = get_db_connection()
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO ioc_reputation_cache
                (ioc_type, ioc_value, is_malicious, reputation_score, enrichment_source, is_verified, is_demo, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (clean_type, clean_val, int(is_mal), score, source, int(is_verified), int(is_demo), json.dumps(details)),
            )
            conn.commit()
        except Exception:
            pass
        finally:
            conn.close()

    return {
        "type": clean_type,
        "value": clean_val,
        "verdict": verdict,
        "is_malicious": is_mal,
        "reputation_score": score,
        "confidence": round(score / 100.0, 2),
        "enrichment_source": source,
        "is_verified": is_verified,
        "is_demo": is_demo,
        "details": details,
    }


def enrich_ioc_list(iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [enrich_ioc(item.get("type", "UNKNOWN"), item.get("value", "")) for item in iocs]
