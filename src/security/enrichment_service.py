# -*- coding: utf-8 -*-
"""
==============================================================================
THREAT ENRICHMENT SERVICE (KHANG - SENIOR PRODUCTION REVISION)
Tích hợp làm giàu dữ liệu IoC với VirusTotal API v3 và AbuseIPDB API kèm bộ đệm SQLite Caching.
Bảo đảm tính toàn vẹn dữ liệu: Không tạo dữ liệu giả, phân biệt rõ Verified vs Demo vs Unknown.
==============================================================================
"""
import os
import sqlite3
import json
import httpx
from typing import List, Dict, Any
from src.automation.storage.database import get_db_connection

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() in ("true", "1", "yes")

def enrich_ioc(ioc_type: str, ioc_value: str) -> Dict[str, Any]:
    """
    Kiểm tra danh tiếng IOC kèm cơ chế bộ đệm SQLite để bảo vệ hạn mức API.
    Tuyệt đối không sinh dữ liệu giả khi thiếu API key.
    """
    clean_type = ioc_type.strip().upper()
    clean_val = ioc_value.strip()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM ioc_reputation_cache WHERE ioc_type = ? AND ioc_value = ?",
        (clean_type, clean_val)
    )
    cached = cursor.fetchone()
    
    if cached:
        conn.close()
        details = json.loads(cached["details_json"]) if cached["details_json"] else {}
        is_verified = bool(cached["is_verified"]) if "is_verified" in cached.keys() else False
        is_demo = bool(cached["is_demo"]) if "is_demo" in cached.keys() else False
        return {
            "type": cached["ioc_type"],
            "value": cached["ioc_value"],
            "verdict": "malicious" if bool(cached["is_malicious"]) else ("suspicious" if is_demo else "unknown"),
            "is_malicious": bool(cached["is_malicious"]),
            "reputation_score": cached["reputation_score"],
            "confidence": cached["reputation_score"] / 100.0,
            "enrichment_source": cached["enrichment_source"],
            "is_verified": is_verified,
            "is_demo": is_demo,
            "details": details
        }
        
    score = 0
    is_mal = False
    source = "no_verified_provider"
    is_verified = False
    is_demo = False
    verdict = "unknown"
    details = {}
    
    # 1. Nếu có VirusTotal API Key thật và là Hash/Domain
    if VT_API_KEY and clean_type in ["SHA256", "MD5", "DOMAIN"]:
        try:
            endpoint = f"https://www.virustotal.com/api/v3/{'files' if 'hash' in clean_type.lower() or clean_type in ['SHA256', 'MD5'] else 'domains'}/{clean_val}"
            headers = {"x-apikey": VT_API_KEY}
            with httpx.Client(timeout=4.0) as client:
                res = client.get(endpoint, headers=headers)
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
            details = {"provider_error": f"VirusTotal query failed: {str(exc)}"}
            
    # 2. Nếu có AbuseIPDB API Key và là IP
    elif ABUSE_API_KEY and clean_type == "IP":
        try:
            endpoint = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
            params = {"ipAddress": clean_val, "maxAgeInDays": "90"}
            with httpx.Client(timeout=4.0) as client:
                res = client.get(endpoint, headers=headers, params=params)
                if res.status_code == 200:
                    data = res.json()
                    score = data.get("data", {}).get("abuseConfidenceScore", 0)
                    is_mal = score >= 50
                    verdict = "malicious" if is_mal else "clean"
                    source = "AbuseIPDB API"
                    is_verified = True
                    details = data.get("data", {})
        except Exception as exc:
            details = {"provider_error": f"AbuseIPDB query failed: {str(exc)}"}
            
    # 3. Xử lý khi không có API Key hoặc API lỗi: Không được tạo dữ liệu độc hại giả!
    if not is_verified:
        if DEMO_MODE:
            # Chỉ khi người dùng chủ động cấu hình DEMO_MODE=true mới kích hoạt heuristic mô phỏng
            score = 50
            is_mal = False
            verdict = "suspicious"
            source = "demo_heuristic"
            is_demo = True
            details = {
                "status": "demo_simulation",
                "note": "Cảnh báo: Dữ liệu mô phỏng do DEMO_MODE=true được bật. Không sử dụng cho Firewall Blocklist production."
            }
        else:
            # Tiêu chuẩn an toàn: Trả về trạng thái Chưa xác minh (Unknown)
            score = 0
            is_mal = False
            verdict = "unknown"
            source = "no_verified_provider"
            is_demo = False
            details = {
                "status": "unverified",
                "reason": "Chưa cấu hình API Key (VirusTotal/AbuseIPDB) hoặc không kết nối được nhà cung cấp uy tín."
            }

    # Lưu vào SQLite Caching
    try:
        cursor.execute("""
        INSERT OR REPLACE INTO ioc_reputation_cache 
        (ioc_type, ioc_value, is_malicious, reputation_score, enrichment_source, is_verified, is_demo, details_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (clean_type, clean_val, int(is_mal), score, source, int(is_verified), int(is_demo), json.dumps(details)))
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
        "details": details
    }

def enrich_ioc_list(iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    enriched = []
    for item in iocs:
        res = enrich_ioc(item.get("type", "UNKNOWN"), item.get("value", ""))
        enriched.append(res)
    return enriched
