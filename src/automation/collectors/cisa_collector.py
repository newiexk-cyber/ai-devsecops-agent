# -*- coding: utf-8 -*-
"""
CISA KEV CATALOG COLLECTOR (LÂM)
Truy vấn danh mục lỗ hổng bị khai thác thực tế (Known Exploited Vulnerabilities - KEV) từ chính phủ Mỹ (CISA.gov).
"""
import httpx
from typing import List, Dict, Any
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

def fetch_cisa_kev(limit: int = 5) -> List[Dict[str, Any]]:
    """Cập nhật dữ liệu từ CISA KEV Catalog và nạp vào SQLite"""
    collected = []
    
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
        
    # Thử gọi API CISA KEV trực tuyến nếu có mạng
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(CISA_KEV_URL)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])[:limit]
                for item in vulns:
                    content = (
                        f"Vulnerability: {item.get('vulnerabilityName')} ({item.get('cveID')})\n"
                        f"Vendor/Product: {item.get('vendorProject')} - {item.get('product')}\n"
                        f"Description: {item.get('shortDescription')}\n"
                        f"Required Action: {item.get('requiredAction')}\n"
                        f"Remediation Due Date: {item.get('dueDate')}"
                    )
                    url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{item.get('cveID')}"
                    save_raw_article(
                        source_name="CISA KEV",
                        source_url=url,
                        title=f"CISA KEV Alert: {item.get('cveID')} - {item.get('vulnerabilityName')}",
                        raw_content=content,
                        published_date=item.get("dateAdded")
                    )
                    collected.append(item)
    except Exception:
        pass
        
    return collected
