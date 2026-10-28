# -*- coding: utf-8 -*-
"""
IOC EXTRACTOR ENGINE (PHÚC & LÂM)
Bóc tách tự động, khử defang đa dạng và chuẩn hóa canonical các chỉ số xâm nhập (IOCs):
- IPv4 (loại trừ RFC 1918 Private, Loopback, Multicast, Public DNS)
- Domains (khử defang case-insensitive, strip port/path, canonical lowercase)
- Hashes (SHA256, MD5 chuẩn hóa lowercase)
- CVEs (chuẩn hóa uppercase CVE-YYYY-NNNN)
- Threat Actors & Malware Families
- Kết quả trả về luôn được sắp xếp deterministic (có thứ tự ổn định).
"""
import re
import ipaddress
from typing import List, Dict, Any, Set
from urllib.parse import urlparse

# Danh sách trắng hạ tầng mạng công cộng để phòng ngừa False Positive (Chặn nhầm)
PUBLIC_INFRASTRUCTURE_WHITELIST = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
    "127.0.0.1", "0.0.0.0", "cloudflare.com", "google.com",
    "microsoft.com", "paloaltonetworks.com", "cisco.com", "github.com",
    "cisa.gov", "nist.gov", "virustotal.com"
}

# Các phần mở rộng tệp tin không phải là TLD
FILE_EXT_BLACKLIST = {
    "exe", "dll", "bin", "sh", "bat", "ps1", "vbs", "js", "py",
    "png", "jpg", "jpeg", "gif", "svg", "webp", "pdf", "docx", "xlsx",
    "zip", "rar", "7z", "tar", "gz"
}

KNOWN_THREAT_ENTITIES = [
    {"name": "Akira", "type": "malware_family"},
    {"name": "LockBit", "type": "malware_family"},
    {"name": "Lazarus", "type": "threat_actor"},
    {"name": "Volt Typhoon", "type": "threat_actor"},
    {"name": "APT28", "type": "threat_actor"},
    {"name": "APT29", "type": "threat_actor"},
    {"name": "Cozy Bear", "type": "threat_actor"},
    {"name": "Fancy Bear", "type": "threat_actor"},
    {"name": "BlackCat", "type": "malware_family"},
    {"name": "ALPHV", "type": "malware_family"},
    {"name": "Scattered Spider", "type": "threat_actor"},
    {"name": "Lumma", "type": "malware_family"},
    {"name": "RedLine", "type": "malware_family"},
    {"name": "Cobalt Strike", "type": "tool"}
]


def clean_defanged(text: str) -> str:
    """
    Khử defang toàn diện, không phân biệt hoa thường (Case-insensitive):
    - hxxp://, hxxps://, fxp://
    - [.], (.), [dot], {.}
    - [:], [colon]
    - [@], [at]
    """
    if not text:
        return ""

    cleaned = text
    # Chuẩn hóa giao thức defang
    cleaned = re.sub(r'(?i)\bhxxps?://', lambda m: 'https://' if 's' in m.group(0).lower() else 'http://', cleaned)
    cleaned = re.sub(r'(?i)\bfxps?://', 'ftp://', cleaned)

    # Chuẩn hóa dấu chấm và 2 chấm defanged
    cleaned = re.sub(r'\[\.\]|\(\.\)|\{\.\}|\[dot\]', '.', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'\[:\]|\(:\)|\[colon\]', ':', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'\[@\]|\[at\]', '@', cleaned, flags=re.IGNORECASE)

    return cleaned


def is_valid_public_ip(ip_str: str) -> bool:
    """Kiểm tra IP hợp lệ và không nằm trong dải Private (RFC 1918) hoặc Whitelist"""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast or ip.is_link_local:
            return False
        if str(ip) in PUBLIC_INFRASTRUCTURE_WHITELIST:
            return False
        return True
    except ValueError:
        return False


def sanitize_domain(dom_raw: str) -> str:
    """Loại bỏ port, trailing dots, schema nếu lọt vào domain string."""
    dom = dom_raw.strip().lower()
    # Nếu có http/https scheme, parse bằng urllib
    if "://" in dom:
        parsed = urlparse(dom)
        dom = parsed.netloc or parsed.path
    # Bỏ port nếu có
    if ":" in dom:
        dom = dom.split(":")[0]
    # Bỏ dấu gạch chéo cuối
    dom = dom.rstrip("/.")
    return dom


def extract_iocs_from_text(raw_text: str) -> Dict[str, Any]:
    """
    Trích xuất và chuẩn hóa canonical toàn bộ IOCs từ văn bản thô.
    Toàn bộ danh sách trả về đều được sort deterministic.
    """
    if not raw_text:
        return {
            "iocs": [],
            "ips": [],
            "domains": [],
            "sha256": [],
            "md5": [],
            "cves": [],
            "threat_actors": [],
            "malware_families": []
        }

    text = clean_defanged(raw_text)

    # 1. Trích xuất IPv4
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    raw_ips = re.findall(ip_pattern, text)
    valid_ips_set: Set[str] = set()
    for ip in raw_ips:
        if is_valid_public_ip(ip):
            valid_ips_set.add(str(ipaddress.ip_address(ip)))
    valid_ips = sorted(list(valid_ips_set))

    # 2. Trích xuất Domains
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b'
    raw_domains = re.findall(domain_pattern, text)
    valid_domains_set: Set[str] = set()
    for d in raw_domains:
        clean_d = sanitize_domain(d)
        parts = clean_d.split(".")
        tld = parts[-1].lower() if parts else ""
        if (
            len(parts) >= 2
            and clean_d not in PUBLIC_INFRASTRUCTURE_WHITELIST
            and tld not in FILE_EXT_BLACKLIST
            and not re.match(r'^\d+\.\d+\.\d+\.\d+$', clean_d)
        ):
            valid_domains_set.add(clean_d)
    valid_domains = sorted(list(valid_domains_set))

    # 3. Trích xuất Mã băm SHA256 (canonical lowercase)
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    sha256_hashes = sorted(list(set([h.lower() for h in re.findall(sha256_pattern, text)])))

    # Trích xuất Mã băm MD5 (canonical lowercase)
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    md5_hashes = sorted(list(set([h.lower() for h in re.findall(md5_pattern, text)])))

    # 4. Trích xuất CVE (canonical uppercase)
    cve_pattern = r'\bCVE-\d{4}-\d{4,7}\b'
    raw_cves = re.findall(cve_pattern, text, re.IGNORECASE)
    cves = sorted(list(set([c.upper() for c in raw_cves])))

    # 5. Nhận diện Threat Actors & Malware Families
    detected_actors_set: Set[str] = set()
    detected_malware_set: Set[str] = set()
    for entity in KNOWN_THREAT_ENTITIES:
        name = entity["name"]
        etype = entity["type"]
        if re.search(r'\b' + re.escape(name) + r'\b', text, re.IGNORECASE):
            if etype == "threat_actor":
                detected_actors_set.add(name)
            else:
                detected_malware_set.add(name)

    detected_actors = sorted(list(detected_actors_set))
    detected_malware = sorted(list(detected_malware_set))

    # Đóng gói danh sách có cấu trúc
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
        structured_iocs.append({"type": "CVE", "value": c, "confidence": 1.0})

    return {
        "iocs": structured_iocs,
        "ips": valid_ips,
        "domains": valid_domains,
        "sha256": sha256_hashes,
        "md5": md5_hashes,
        "cves": cves,
        "threat_actors": detected_actors,
        "malware_families": detected_malware
    }
