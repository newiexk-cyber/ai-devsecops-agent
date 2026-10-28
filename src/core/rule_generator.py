# -*- coding: utf-8 -*-
"""
DEFENSIVE RULES GENERATOR (PHÚC & KHANG)
Tự động sinh 4 sản phẩm phòng thủ thực chiến từ dữ liệu tình báo đã qua phân tích:
1. SigmaHQ Rule (.yml) cho SIEM/SOC (Wazuh, Splunk) - Tuân thủ cấu trúc YAML an toàn, loại bỏ IOC giả.
2. YARA Rule (.yar) quét máy trạm (Endpoint) - Dùng module 'hash' chuẩn cho digest SHA256/MD5, không ép MZ header cho script/URL.
3. Firewall Blocklist (.txt) nạp tường lửa - Phân tách định dạng rõ ràng (iptables, nftables, dnsmasq, generic_ip).
4. OASIS STIX 2.1 Bundle (.json) chia sẻ chuẩn quốc tế - Đầy đủ relationship (indicates), report, confidence.
"""
import uuid
import yaml
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


def generate_sigma_rule(report_title: str, enriched_iocs: List[Dict[str, Any]], mitre_techniques: List[Dict[str, Any]]) -> str:
    """
    Sinh Sigma rule chuẩn xác.
    YÊU CẦU: Không bao giờ chèn IOC giả (127.0.0.1, malicious.example).
    Nếu không có IOC IP hoặc Domain hợp lệ, báo lỗi rõ ràng hoặc trả chú thích an toàn.
    """
    ips = [ioc["value"] for ioc in enriched_iocs if ioc.get("type") == "IP" and ioc.get("value")]
    domains = [ioc["value"] for ioc in enriched_iocs if ioc.get("type") == "DOMAIN" and ioc.get("value")]

    if not ips and not domains:
        raise ValueError("No valid network IOC (IP or Domain) available to generate Sigma rule")

    rule_id = str(uuid.uuid4())
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    detection: Dict[str, Any] = {}
    conditions: List[str] = []

    if ips:
        detection["selection_ip"] = {
            "DestinationIp": sorted(list(set(ips)))
        }
        conditions.append("selection_ip")

    if domains:
        detection["selection_domain"] = {
            "QueryName|contains": [f"*{dom}*" for dom in sorted(list(set(domains)))]
        }
        conditions.append("selection_domain")

    detection["condition"] = " or ".join(conditions)

    mitre_tags = [f"attack.{t['technique_id'].lower()}" for t in mitre_techniques if "technique_id" in t]
    tags = mitre_tags if mitre_tags else ["attack.initial_access"]

    sigma_doc = {
        "title": f"CTI-Sentinel: Phát hiện kết nối C2 - {report_title.strip()}",
        "id": rule_id,
        "status": "experimental",
        "description": "Tự động sinh từ hệ thống CTI-Sentinel dựa trên báo cáo phân tích đe dọa mạng thời gian thực.",
        "references": [
            "https://cisa.gov",
            "https://attack.mitre.org"
        ],
        "author": "CTI-Sentinel Autonomous Agent",
        "date": date_str,
        "tags": tags,
        "logsource": {
            "category": "network_connection",
            "product": "windows"
        },
        "detection": detection,
        "falsepositives": [
            "Các máy chủ DNS công cộng hoặc dịch vụ CDN hợp pháp",
            "Hoạt động mạng đã được cấp phép nội bộ"
        ],
        "level": "high"
    }

    # Safe YAML serialization
    return yaml.dump(sigma_doc, sort_keys=False, allow_unicode=True, default_flow_style=False)


def generate_yara_rule(report_title: str, enriched_iocs: List[Dict[str, Any]], enforce_pe_header: bool = False) -> str:
    """
    Sinh YARA rule chuẩn xác.
    - Với hash: Sử dụng module 'hash' để so sánh digest thật (hash.sha256/hash.md5), không tìm chuỗi hex thô.
    - Không ép buộc 'uint16(0) == 0x5A4D' (MZ header) cho script hoặc domain rules trừ khi enforce_pe_header=True.
    """
    safe_title = "".join([c if c.isalnum() else "_" for c in report_title[:30]]).strip("_")
    rule_name = f"CTI_Sentinel_{safe_title}" if safe_title else "CTI_Sentinel_Threat_Detection"
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    sha256_hashes = [ioc["value"].lower() for ioc in enriched_iocs if ioc.get("type") == "SHA256" and ioc.get("value")]
    md5_hashes = [ioc["value"].lower() for ioc in enriched_iocs if ioc.get("type") == "MD5" and ioc.get("value")]
    domains = [ioc["value"] for ioc in enriched_iocs if ioc.get("type") == "DOMAIN" and ioc.get("value")]

    if not sha256_hashes and not md5_hashes and not domains:
        raise ValueError("No valid IOC (Hash or Domain) available to generate YARA rule")

    imports = []
    if sha256_hashes or md5_hashes:
        imports.append('import "hash"')

    strings_def: List[str] = []
    condition_parts: List[str] = []

    # Domain / String matching
    idx = 1
    for d in sorted(list(set(domains))):
        strings_def.append(f'        $domain_{idx} = "{d}" ascii wide nocase')
        condition_parts.append(f'$domain_{idx}')
        idx += 1

    # Real Hash comparison via YARA hash module
    for h in sorted(list(set(sha256_hashes))):
        condition_parts.append(f'hash.sha256(0, filesize) == "{h}"')

    for h in sorted(list(set(md5_hashes))):
        condition_parts.append(f'hash.md5(0, filesize) == "{h}"')

    imports_block = "\n".join(imports) + "\n\n" if imports else ""
    strings_block = "    strings:\n" + "\n".join(strings_def) + "\n\n" if strings_def else ""

    cond_expression = " or ".join(condition_parts)
    if enforce_pe_header:
        final_condition = f"uint16(0) == 0x5A4D and ({cond_expression})"
    else:
        final_condition = cond_expression

    clean_desc = report_title.replace('"', '\\"').replace("\n", " ").strip()

    return f"""{imports_block}rule {rule_name}
{{
    meta:
        description = "Nhận diện mã độc từ báo cáo: {clean_desc}"
        author = "CTI-Sentinel Autonomous AI Agent"
        date = "{date_str}"
        threat_level = "HIGH"
        tlp = "CLEAR"

{strings_block}    condition:
        {final_condition}
}}
"""


def generate_firewall_blocklist(enriched_iocs: List[Dict[str, Any]], format_type: str = "iptables") -> str:
    """
    Sinh danh sách chặn tường lửa phân tách rõ ràng định dạng:
    - iptables: Lệnh Linux iptables DROP
    - nftables: Cú pháp nftables inet filter
    - dnsmasq: Cú pháp DNS sinkhole dnsmasq
    - generic_ip: Chỉ danh sách IP thuần túy (mỗi IP một dòng)
    - all: Cả danh sách nhưng phân vùng rõ ràng theo khối riêng biệt
    """
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ips = sorted(list(set([ioc["value"] for ioc in enriched_iocs if ioc.get("type") == "IP" and ioc.get("value")])))
    domains = sorted(list(set([ioc["value"] for ioc in enriched_iocs if ioc.get("type") == "DOMAIN" and ioc.get("value")])))

    fmt = format_type.lower().strip()

    if fmt == "nftables":
        lines = [
            f"# ==========================================================================",
            f"# CTI-SENTINEL NFTABLES BLOCKLIST ({date_str})",
            f"# =========================================================================="
        ]
        for ip in ips:
            lines.append(f"add rule inet filter input ip saddr {ip} drop")
            lines.append(f"add rule inet filter output ip daddr {ip} drop")
        return "\n".join(lines)

    elif fmt == "dnsmasq":
        lines = [
            f"# ==========================================================================",
            f"# CTI-SENTINEL DNSMASQ SINKHOLE ({date_str})",
            f"# =========================================================================="
        ]
        for dom in domains:
            lines.append(f"address=/{dom}/0.0.0.0")
        return "\n".join(lines)

    elif fmt == "generic_ip":
        return "\n".join(ips)

    elif fmt == "all":
        lines = [
            f"# ==========================================================================",
            f"# CTI-SENTINEL MULTI-FORMAT BLOCKLIST ({date_str})",
            f"# ==========================================================================\n",
            "# [SECTION: IPTABLES COMMANDS]"
        ]
        for ip in ips:
            lines.append(f"iptables -A INPUT -s {ip} -j DROP")
            lines.append(f"iptables -A OUTPUT -d {ip} -j DROP")

        lines.append("\n# [SECTION: NFTABLES RULES]")
        for ip in ips:
            lines.append(f"add rule inet filter input ip saddr {ip} drop")

        lines.append("\n# [SECTION: DNS SINKHOLE (DNSMASQ)]")
        for dom in domains:
            lines.append(f"address=/{dom}/0.0.0.0")

        lines.append("\n# [SECTION: RAW IP LIST]")
        lines.extend(ips)

        return "\n".join(lines)

    else:
        # Default: iptables
        lines = [
            f"# ==========================================================================",
            f"# CTI-SENTINEL IPTABLES BLOCKLIST ({date_str})",
            f"# =========================================================================="
        ]
        for ip in ips:
            lines.append(f"iptables -A INPUT -s {ip} -j DROP")
            lines.append(f"iptables -A OUTPUT -d {ip} -j DROP")
        return "\n".join(lines)


def generate_stix_bundle(report_title: str, enriched_iocs: List[Dict[str, Any]], mitre_techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Sinh OASIS STIX 2.1 Bundle chuẩn quốc tế:
    - Bổ sung Identity, Report, Indicators, Attack-Patterns.
    - Đầy đủ Relationship objects 'indicates' liên kết Indicator -> Attack Pattern.
    - Escape ký tự đặc biệt trong STIX pattern strings.
    - Gán confidence score rõ ràng.
    """
    bundle_id = f"bundle--{uuid.uuid4()}"
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    identity_id = f"identity--{uuid.uuid4()}"
    objects: List[Dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now_iso,
            "modified": now_iso,
            "name": "CTI-Sentinel AI Agent",
            "identity_class": "system",
            "confidence": 85
        }
    ]

    attack_pattern_ids: List[str] = []
    for tech in mitre_techniques:
        tech_id = tech.get("technique_id", "T0000")
        tech_name = tech.get("technique_name", "Unknown Technique")
        ap_id = f"attack-pattern--{uuid.uuid4()}"
        attack_pattern_ids.append(ap_id)
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": ap_id,
            "created": now_iso,
            "modified": now_iso,
            "name": tech_name,
            "created_by_ref": identity_id,
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": tech_id,
                    "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}"
                }
            ]
        })

    indicator_ids: List[str] = []
    for ioc in enriched_iocs:
        ioc_val = str(ioc.get("value", "")).replace("'", "\\'")
        ioc_type = ioc.get("type")
        pattern = ""

        if ioc_type == "IP":
            pattern = f"[ipv4-addr:value = '{ioc_val}']"
        elif ioc_type == "DOMAIN":
            pattern = f"[domain-name:value = '{ioc_val}']"
        elif ioc_type == "SHA256":
            pattern = f"[file:hashes.'SHA-256' = '{ioc_val}']"
        elif ioc_type == "MD5":
            pattern = f"[file:hashes.'MD5' = '{ioc_val}']"

        if pattern:
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "created": now_iso,
                "modified": now_iso,
                "name": f"Indicator {ioc_type}: {ioc['value']}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now_iso,
                "confidence": 75 if ioc.get("is_verified") else 40,
                "created_by_ref": identity_id
            })

            # Tạo relationship: Indicator -> indicates -> Attack Pattern
            for ap_id in attack_pattern_ids:
                objects.append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{uuid.uuid4()}",
                    "created": now_iso,
                    "modified": now_iso,
                    "relationship_type": "indicates",
                    "source_ref": ind_id,
                    "target_ref": ap_id,
                    "created_by_ref": identity_id
                })

    # Tạo đối tượng Report chứa toàn bộ các đối tượng trên
    report_id = f"report--{uuid.uuid4()}"
    all_object_refs = [identity_id] + attack_pattern_ids + indicator_ids
    clean_title = report_title.replace('"', '').strip()
    objects.append({
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created": now_iso,
        "modified": now_iso,
        "name": f"CTI Report: {clean_title}",
        "published": now_iso,
        "object_refs": all_object_refs,
        "created_by_ref": identity_id,
        "confidence": 80
    })

    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects
    }
