# -*- coding: utf-8 -*-
"""
IOC EXTRACTOR ENGINE (PHÚC)
Bóc tách tự động và chuẩn hóa các chỉ số xâm nhập (IOCs):
- IP (IPv4 với bộ lọc Private/Whitelist hạ tầng)
- Domain / Hostname (chuẩn hóa khử defang hxxp, [.])
- Mã băm MD5 / SHA256
- Mã định danh lỗ hổng CVE
- Tên nhóm tin tặc (Threat Actors) & Họ mã độc (Malware Families)
"""
import re
import ipaddress
from typing import List, Dict, Any

# Danh sách trắng hạ tầng mạng công cộng để phòng ngừa False Positive (Chặn nhầm)
PUBLIC_INFRASTRUCTURE_WHITELIST = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
    "127.0.0.1", "0.0.0.0", "cloudflare.com", "google.com",
    "microsoft.com", "paloaltonetworks.com", "cisco.com"
}

KNOWN_ACTORS = [
    "Akira", "LockBit", "Lazarus", "Volt Typhoon", "APT28", "APT29", "Cozy Bear",
    "Fancy Bear", "BlackCat", "ALPHV", "Scattered Spider", "Lumma", "RedLine"
]

def clean_defanged(text: str) -> str:
    """Khử defang phổ biến trong báo cáo an ninh: hxxp -> http, [.] -> ."""
    cleaned = text.replace("[.]", ".").replace("(.)", ".")
    cleaned = cleaned.replace("hxxp://", "http://").replace("hxxps://", "https://")
    cleaned = cleaned.replace("[at]", "@")
    return cleaned

def is_valid_public_ip(ip_str: str) -> bool:
    """Kiểm tra IP hợp lệ và không nằm trong dải Private (RFC 1918) hoặc Whitelist"""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast:
            return False
        if ip_str in PUBLIC_INFRASTRUCTURE_WHITELIST:
            return False
        return True
    except ValueError:
        return False

def extract_iocs_from_text(raw_text: str) -> Dict[str, Any]:
    text = clean_defanged(raw_text)
    
    # 1. Trích xuất IPv4
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    raw_ips = re.findall(ip_pattern, text)
    valid_ips = list(set([ip for ip in raw_ips if is_valid_public_ip(ip)]))
    
    # 2. Trích xuất Domains
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|top|biz|site|xyz|info|io|ru|cn|cc|me|live|online|tk)\b'
    raw_domains = re.findall(domain_pattern, text, re.IGNORECASE)
    valid_domains = list(set([
        d.lower() for d in raw_domains 
        if d.lower() not in PUBLIC_INFRASTRUCTURE_WHITELIST and not d.endswith(".exe") and not d.endswith(".png")
    ]))
    
    # 3. Trích xuất Mã băm SHA256 & MD5
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    sha256_hashes = list(set(re.findall(sha256_pattern, text)))
    
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    md5_hashes = list(set(re.findall(md5_pattern, text)))
    
    # 4. Trích xuất CVE
    cve_pattern = r'\bCVE-\d{4}-\d{4,7}\b'
    cves = list(set(re.findall(cve_pattern, text, re.IGNORECASE)))
    
    # 5. Nhận diện Threat Actors / Malware
    detected_actors = []
    for actor in KNOWN_ACTORS:
        if re.search(r'\b' + re.escape(actor) + r'\b', text, re.IGNORECASE):
            detected_actors.append(actor)
            
    # Đóng gói danh sách phẳng các IOCs có gán nhãn
    structured_iocs = []
    for ip in valid_ips:
        structured_iocs.append({"type": "IP", "value": ip, "confidence": 0.95})
    for d in valid_domains:
        structured_iocs.append({"type": "DOMAIN", "value": d, "confidence": 0.90})
    for h in sha256_hashes:
        structured_iocs.append({"type": "SHA256", "value": h, "confidence": 1.0})
    for h in md5_hashes:
        structured_iocs.append({"type": "MD5", "value": h, "confidence": 1.0})
    for c in cves:
        structured_iocs.append({"type": "CVE", "value": c.upper(), "confidence": 1.0})
        
    return {
        "iocs": structured_iocs,
        "ips": valid_ips,
        "domains": valid_domains,
        "sha256": sha256_hashes,
        "md5": md5_hashes,
        "cves": cves,
        "threat_actors": detected_actors
    }
