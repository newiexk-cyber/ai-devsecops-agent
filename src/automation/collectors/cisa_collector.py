# -*- coding: utf-8 -*-
"""
CISA KEV CATALOG COLLECTOR (LÂM)
Truy vấn danh mục lỗ hổng bị khai thác thực tế (Known Exploited Vulnerabilities - KEV) từ chính phủ Mỹ (CISA.gov).
"""
import os
import re
import httpx
from typing import List, Dict, Any, Optional
from src.automation.storage.database import save_raw_article

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Mẫu lỗ hổng KEV thực tế nổi bật
BUNDLED_CISA_VULNS = [
    {
        "cveID": "CVE-2024-3400",
        "vendorProject": "Palo Alto Networks",
        "product": "PAN-OS",
        "vulnerabilityName": "Palo Alto Networks PAN-OS Command Injection Vulnerability",
        "dateAdded": "2024-04-12",
        "shortDescription": "A command injection vulnerability in GlobalProtect feature of PAN-OS software for specific PAN-OS 10.2, 11.0, and 11.1 versions enables an unauthenticated attacker to execute arbitrary code with root privileges.",
        "requiredAction": "Apply mitigations per vendor instructions or discontinue use of the affected product.",
        "dueDate": "2024-04-19"
    },
    {
        "cveID": "CVE-2024-21887",
        "vendorProject": "Ivanti",
        "product": "Connect Secure and Policy Secure",
        "vulnerabilityName": "Ivanti Connect Secure Command Injection Vulnerability",
        "dateAdded": "2024-01-10",
        "shortDescription": "A command injection vulnerability in web components of Ivanti Connect Secure enables an authenticated administrator to send specially crafted requests and execute arbitrary commands on the appliance.",
        "requiredAction": "Apply vendor workarounds and updates immediately.",
        "dueDate": "2024-01-22"
    }
]

import time

_CACHED_CISA_KEV: Optional[List[Dict[str, Any]]] = None
_CACHED_CISA_KEV_TIME: float = 0.0

def get_cached_cisa_kev_data() -> List[Dict[str, Any]]:
    """Tải và lưu đệm danh mục CISA KEV (TTL 15 phút) nhằm tránh nghẽn mạng và timeout."""
    global _CACHED_CISA_KEV, _CACHED_CISA_KEV_TIME
    now = time.time()
    if _CACHED_CISA_KEV is not None and (now - _CACHED_CISA_KEV_TIME) < 900:
        return _CACHED_CISA_KEV

    try:
        with httpx.Client(timeout=6.0) as client:
            resp = client.get(CISA_KEV_URL)
            if resp.status_code == 200:
                data = resp.json()
                _CACHED_CISA_KEV = data.get("vulnerabilities", [])
                _CACHED_CISA_KEV_TIME = now
                return _CACHED_CISA_KEV
    except Exception:
        pass

    if _CACHED_CISA_KEV is not None:
        return _CACHED_CISA_KEV
    return BUNDLED_CISA_VULNS

def fetch_cisa_kev(limit: int = 35) -> List[Dict[str, Any]]:
    """Cập nhật dữ liệu từ CISA KEV Catalog và nạp vào SQLite."""
    collected = []
    vulns = get_cached_cisa_kev_data()

    # Nạp dữ liệu mẫu trước
    for item in BUNDLED_CISA_VULNS:
        content = (
            f"Vulnerability: {item['vulnerabilityName']} ({item['cveID']})\n"
            f"Vendor/Product: {item['vendorProject']} - {item['product']}\n"
            f"Description: {item['shortDescription']}\n"
            f"Required Action: {item['requiredAction']}\n"
            f"Remediation Due Date: {item['dueDate']}"
        )
        url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{item['cveID']}"
        save_raw_article(
            source_name="CISA KEV",
            source_url=url,
            title=f"CISA KEV Alert: {item['cveID']} - {item['vulnerabilityName']}",
            raw_content=content,
            published_date=item["dateAdded"]
        )
        collected.append(item)

    for item in vulns[:limit]:
        cve_id = item.get("cveID") or item.get("cve_id")
        if not cve_id:
            continue
        vuln_name = item.get("vulnerabilityName", "Vulnerability")
        content = (
            f"Vulnerability: {vuln_name} ({cve_id})\n"
            f"Vendor/Product: {item.get('vendorProject', 'Unknown')} - {item.get('product', 'Unknown')}\n"
            f"Description: {item.get('shortDescription', '')}\n"
            f"Required Action: {item.get('requiredAction', '')}\n"
            f"Remediation Due Date: {item.get('dueDate', '')}"
        )
        url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{cve_id}"
        save_raw_article(
            source_name="CISA KEV",
            source_url=url,
            title=f"CISA KEV Alert: {cve_id} - {vuln_name}",
            raw_content=content,
            published_date=item.get("dateAdded")
        )
        collected.append(item)

    return collected

def fetch_cve_by_id(cve_id: str) -> Dict[str, Any]:
    """
    Kéo lỗ hổng khẩn cấp theo mã CVE (On-Demand Fetching):
    1. Tra cứu siêu tốc trong bộ đệm CISA KEV Catalog
    2. Nếu không có, tra cứu trực tiếp sang Cơ sở dữ liệu quốc gia NIST NVD API
    3. Lưu ngay vào SQLite và trả về kết quả
    """
    clean_cve = cve_id.strip().upper()
    if not clean_cve.startswith("CVE-"):
        clean_cve = f"CVE-{clean_cve}"

    # Kiểm tra định dạng chuẩn CVE nghiêm ngặt (P0 Data Integrity)
    if not re.match(r"^CVE-\d{4}-\d{4,}$", clean_cve):
        raise ValueError(f"Định dạng mã CVE không hợp lệ: '{clean_cve}'. Chuẩn bắt buộc: CVE-YYYY-NNNN+")

    # 1. Tra cứu trong CISA KEV Catalog (dùng in-memory cache)
    vulns = get_cached_cisa_kev_data()
    for item in vulns:
        if (item.get("cveID") or item.get("cve_id") or "").strip().upper() == clean_cve:
            vuln_name = item.get("vulnerabilityName", "Known Exploited Vulnerability")
            content = (
                f"Vulnerability: {vuln_name} ({clean_cve})\n"
                f"Vendor/Product: {item.get('vendorProject', 'Vendor')} - {item.get('product', 'Product')}\n"
                f"Description: {item.get('shortDescription', '')}\n"
                f"Required Action: {item.get('requiredAction', 'Patch immediately')}\n"
                f"Remediation Due Date: {item.get('dueDate', 'N/A')}\n\n"
                f"Status: Actively Exploited in the Wild (Confirmed by CISA)"
            )
            url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{clean_cve}"
            art_id = save_raw_article(
                source_name="CISA KEV",
                source_url=url,
                title=f"CISA KEV Alert: {clean_cve} - {vuln_name}",
                raw_content=content,
                published_date=item.get("dateAdded")
            )
            return {
                "status": "success",
                "id": art_id,
                "cve_id": clean_cve,
                "source": "CISA KEV Catalog",
                "is_kev": True,
                "is_verified": True,
                "date_added_to_kev": item.get("dateAdded"),
                "published_date": item.get("dateAdded"),
                "title": f"CISA KEV Alert: {clean_cve} - {vuln_name}",
                "content": content,
                "url": url
            }

    # 2. Thử tìm trên NIST NVD API v2
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={clean_cve}"
    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.get(nvd_url)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    cve_item = vulns[0].get("cve", {})
                    descriptions = cve_item.get("descriptions", [])
                    desc_en = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "Không có mô tả chi tiết.")
                    metrics = cve_item.get("metrics", {})
                    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else {}
                    base_score = cvss_v3.get("baseScore", "N/A")
                    severity = cvss_v3.get("baseSeverity", "CRITICAL")
                    pub_date = cve_item.get("published", "")[:10]

                    content = (
                        f"NIST NVD Security Advisory for {clean_cve}\n"
                        f"CVSS v3.1 Base Score: {base_score} ({severity})\n"
                        f"Vector String: {cvss_v3.get('vectorString', 'N/A')}\n"
                        f"Description: {desc_en}\n"
                        f"National Vulnerability Database Reference: https://nvd.nist.gov/vuln/detail/{clean_cve}"
                    )
                    url = f"https://nvd.nist.gov/vuln/detail/{clean_cve}"
                    art_id = save_raw_article(
                        source_name="NIST NVD",
                        source_url=url,
                        title=f"NIST NVD Alert: {clean_cve} (CVSS: {base_score})",
                        raw_content=content,
                        published_date=pub_date
                    )
                    return {
                        "status": "success",
                        "id": art_id,
                        "cve_id": clean_cve,
                        "source": "NIST NVD",
                        "is_kev": False,
                        "is_verified": True,
                        "published_date": pub_date,
                        "cvss_score": base_score,
                        "title": f"NIST NVD Alert: {clean_cve} (CVSS: {base_score})",
                        "content": content,
                        "url": url
                    }
    except Exception:
        pass

    # 3. Khi không tìm thấy trên CISA KEV hoặc NIST NVD: Trả về trạng thái không tìm thấy (Không tạo dữ liệu giả)
    return {
        "status": "not_found",
        "cve_id": clean_cve,
        "is_verified": False,
        "is_kev": False,
        "source": "unverified",
        "message": f"Mã {clean_cve} không được tìm thấy trên CISA KEV Catalog hoặc NIST NVD."
    }

