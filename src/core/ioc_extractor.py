# -*- coding: utf-8 -*-
"""
IOC EXTRACTOR ENGINE (PHÚC & LÂM)
Bóc tách tự động, khử defang đa dạng, gắn câu ngữ cảnh gốc và chuẩn hóa canonical các chỉ số xâm nhập (IOCs):
- IPv4 (loại trừ RFC 1918 Private, Loopback, Multicast, Public DNS và chuỗi version phần mềm)
- Domains & URLs (khử defang case-insensitive, bỏ hậu tố file thực thi, loại domain nguồn tin/tài liệu)
- Hashes (SHA256, MD5 chuẩn hóa lowercase)
- CVEs (chuẩn hóa uppercase CVE-YYYY-NNNN)
- Threat Actors & Malware Families
"""
import ipaddress
import re
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

# Danh sách trắng hạ tầng công cộng để phòng ngừa chặn nhầm (False Positive)
PUBLIC_INFRASTRUCTURE_WHITELIST = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
    "127.0.0.1", "0.0.0.0", "cloudflare.com", "google.com",
    "microsoft.com", "paloaltonetworks.com", "cisco.com", "github.com",
    "cisa.gov", "nist.gov", "nvd.nist.gov", "virustotal.com",
    "mitre.org", "attack.mitre.org", "thehackernews.com",
    "bleepingcomputer.com", "www.bleepingcomputer.com", "feeds.feedburner.com",
    "securityweek.com", "krebsonsecurity.com", "therecord.media",
    "darkreading.com", "twitter.com", "x.com", "linkedin.com", "youtube.com",
}

# Các phần mở rộng tệp tin không phải là TLD của Domain
FILE_EXT_BLACKLIST = {
    "exe", "dll", "bin", "sh", "bat", "ps1", "vbs", "js", "py",
    "png", "jpg", "jpeg", "gif", "svg", "webp", "pdf", "doc", "docx",
    "xls", "xlsx", "zip", "rar", "7z", "tar", "gz", "txt", "log",
    "json", "yml", "yaml", "xml", "yar", "csv", "pdb", "lnk", "hta",
    "msi", "iso", "cfg", "conf", "ini", "tmp", "sys", "php", "asp", "aspx",
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
    {"name": "Cobalt Strike", "type": "tool"},
    {"name": "Play", "type": "malware_family"},
    {"name": "Qilin", "type": "malware_family"},
    {"name": "Rhysida", "type": "malware_family"},
    {"name": "MuddyWater", "type": "threat_actor"},
    {"name": "Kimsuky", "type": "threat_actor"},
    {"name": "Sandworm", "type": "threat_actor"},
]

_VERSION_PREFIX_RE = re.compile(
    r"(?i)(?:\bv(?:er(?:sion)?)?\.?\s*|\bbuild\s+|\brelease\s+|\bpatch\s+"
    r"|\bpan-os\s+|\bfortios\s+|\bchrome\s+|\bfirefox\s+|\bios\s+|\bmacos\s+"
    r"|\bwindows\s+|\bopenssl\s+|\bapache\s+|\bnginx\s+|\bsdk\s+)$"
)


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
    cleaned = re.sub(
        r"(?i)\bhxxps?://",
        lambda m: "https://" if "s" in m.group(0).lower() else "http://",
        cleaned,
    )
    cleaned = re.sub(r"(?i)\bfxps?://", "ftp://", cleaned)
    cleaned = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]", ".", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\[:\]|\(:\)|\[colon\]", ":", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\[@\]|\[at\]", "@", cleaned, flags=re.IGNORECASE)
    return cleaned


def is_valid_public_ip(ip_str: str) -> bool:
    """Kiểm tra IP hợp lệ và không nằm trong dải Private (RFC 1918) hoặc Whitelist."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_link_local
            or ip.is_unspecified
        ):
            return False
        if str(ip) in PUBLIC_INFRASTRUCTURE_WHITELIST:
            return False
        return True
    except ValueError:
        return False


def _is_version_like_ip(text: str, match_start: int) -> bool:
    """Kiểm tra xem chuỗi dạng x.x.x.x có đi ngay sau từ khóa version/sản phẩm không."""
    prefix_window = text[max(0, match_start - 24) : match_start]
    return bool(_VERSION_PREFIX_RE.search(prefix_window))


def sanitize_domain(dom_raw: str) -> str:
    """Loại bỏ port, trailing dots, scheme nếu lọt vào domain string."""
    dom = dom_raw.strip().lower()
    if "://" in dom:
        parsed = urlparse(dom)
        dom = parsed.netloc or parsed.path
    if ":" in dom:
        dom = dom.split(":")[0]
    dom = dom.rstrip("/.")
    return dom


def _is_whitelisted_host(host: str) -> bool:
    clean = host.strip().lower()
    return clean in PUBLIC_INFRASTRUCTURE_WHITELIST or any(
        clean.endswith(f".{w}") for w in PUBLIC_INFRASTRUCTURE_WHITELIST if "." in w and not w[0].isdigit()
    )


def find_context_sentence(text: str, needle: str) -> str:
    """Tìm câu chứa IOC trong văn bản để Agent đánh giá ngữ cảnh và xuất dẫn chứng XAI."""
    if not text or not needle:
        return ""
    sentences = re.split(r"(?<=[.!?\n])\s+", text.strip())
    low_needle = needle.lower()
    for sent in sentences:
        if low_needle in sent.lower():
            compact = re.sub(r"\s+", " ", sent).strip()
            return compact[:280]
    return ""


def extract_iocs_from_text(raw_text: str) -> Dict[str, Any]:
    """
    Trích xuất và chuẩn hóa canonical toàn bộ IOCs từ văn bản thô.
    Mỗi IOC đều gắn kèm câu ngữ cảnh gốc (`context_sentence`) và sắp xếp deterministic.
    """
    if not raw_text:
        return {
            "iocs": [],
            "ips": [],
            "domains": [],
            "urls": [],
            "sha256": [],
            "md5": [],
            "cves": [],
            "threat_actors": [],
            "malware_families": [],
        }

    text = clean_defanged(raw_text)

    # 1. Trích xuất IPv4 (bỏ qua version phần mềm và dải private/whitelist)
    ip_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    valid_ips_set: Set[str] = set()
    for match in re.finditer(ip_pattern, text):
        ip_str = match.group(0)
        if _is_version_like_ip(text, match.start()):
            continue
        if is_valid_public_ip(ip_str):
            valid_ips_set.add(str(ipaddress.ip_address(ip_str)))
    valid_ips = sorted(valid_ips_set)

    # 2. Trích xuất URLs độc hại (khử dấu câu thừa cuối câu)
    url_pattern = r"https?://[^\s<>\"'\)\]]+"
    valid_urls_set: Set[str] = set()
    for raw_url in re.findall(url_pattern, text, flags=re.IGNORECASE):
        clean_url = raw_url.rstrip(".,;:!?")
        parsed = urlparse(clean_url)
        host = (parsed.hostname or "").lower()
        if not host or _is_whitelisted_host(host):
            continue
        valid_urls_set.add(clean_url)
    valid_urls = sorted(valid_urls_set)

    # 3. Trích xuất Domains
    domain_pattern = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
    valid_domains_set: Set[str] = set()
    for d in re.findall(domain_pattern, text):
        clean_d = sanitize_domain(d)
        parts = clean_d.split(".")
        tld = parts[-1].lower() if parts else ""
        if (
            len(parts) >= 2
            and not _is_whitelisted_host(clean_d)
            and tld not in FILE_EXT_BLACKLIST
            and not re.match(r"^\d+\.\d+\.\d+\.\d+$", clean_d)
        ):
            valid_domains_set.add(clean_d)
    valid_domains = sorted(valid_domains_set)

    # 4. Trích xuất SHA256 & MD5
    sha256_hashes = sorted({h.lower() for h in re.findall(r"\b[a-fA-F0-9]{64}\b", text)})
    md5_hashes = sorted({h.lower() for h in re.findall(r"\b[a-fA-F0-9]{32}\b", text)})

    # 5. Trích xuất CVE
    cves = sorted({c.upper() for c in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, re.IGNORECASE)})

    # 6. Nhận diện Threat Actors & Malware Families
    detected_actors_set: Set[str] = set()
    detected_malware_set: Set[str] = set()
    for entity in KNOWN_THREAT_ENTITIES:
        name = entity["name"]
        etype = entity["type"]
        if re.search(r"\b" + re.escape(name) + r"\b", text, re.IGNORECASE):
            if etype == "threat_actor":
                detected_actors_set.add(name)
            else:
                detected_malware_set.add(name)

    detected_actors = sorted(detected_actors_set)
    detected_malware = sorted(detected_malware_set)

    # Đóng gói danh sách IOC kèm câu ngữ cảnh gốc
    structured_iocs: List[Dict[str, Any]] = []
    for ip in valid_ips:
        structured_iocs.append({
            "type": "IP",
            "value": ip,
            "confidence": 0.90,
            "context_sentence": find_context_sentence(text, ip),
        })
    for d in valid_domains:
        structured_iocs.append({
            "type": "DOMAIN",
            "value": d,
            "confidence": 0.85,
            "context_sentence": find_context_sentence(text, d),
        })
    for u in valid_urls:
        structured_iocs.append({
            "type": "URL",
            "value": u,
            "confidence": 0.88,
            "context_sentence": find_context_sentence(text, u),
        })
    for h in sha256_hashes:
        structured_iocs.append({
            "type": "SHA256",
            "value": h,
            "confidence": 0.98,
            "context_sentence": find_context_sentence(text, h),
        })
    for h in md5_hashes:
        structured_iocs.append({
            "type": "MD5",
            "value": h,
            "confidence": 0.95,
            "context_sentence": find_context_sentence(text, h),
        })
    for c in cves:
        structured_iocs.append({
            "type": "CVE",
            "value": c,
            "confidence": 0.95,
            "context_sentence": find_context_sentence(text, c),
        })

    return {
        "iocs": structured_iocs,
        "ips": valid_ips,
        "domains": valid_domains,
        "urls": valid_urls,
        "sha256": sha256_hashes,
        "md5": md5_hashes,
        "cves": cves,
        "threat_actors": detected_actors,
        "malware_families": detected_malware,
    }
