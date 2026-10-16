# -*- coding: utf-8 -*-
"""
DEFENSIVE RULES GENERATOR (PHÚC & KHANG)
Tự động sinh 4 sản phẩm phòng thủ thực chiến từ dữ liệu tình báo đã qua phân tích:
1. SigmaHQ Rule (.yml) cho SIEM/SOC (Wazuh, Splunk)
2. YARA Rule (.yar) quét máy trạm (Endpoint)
3. Firewall Blocklist (.txt) nạp tường lửa
4. OASIS STIX 2.1 Bundle (.json) chia sẻ chuẩn quốc tế
"""
import uuid
from datetime import datetime
from typing import Dict, Any, List

def generate_sigma_rule(report_title: str, enriched_iocs: List[Dict[str, Any]], mitre_techniques: List[Dict[str, Any]]) -> str:
    rule_id = str(uuid.uuid4())
    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    
    ips = [ioc["value"] for ioc in enriched_iocs if ioc["type"] == "IP"]
    domains = [ioc["value"] for ioc in enriched_iocs if ioc["type"] == "DOMAIN"]
    
    mitre_tags = [f"attack.{t['technique_id'].lower()}" for t in mitre_techniques]
    tag_str = "\n".join([f"    - {t}" for t in mitre_tags]) if mitre_tags else "    - attack.initial_access"
    
    ip_str = "\n".join([f"            - '{ip}'" for ip in ips]) if ips else "            - '127.0.0.1'"
    domain_str = "\n".join([f"            - '*{dom}*'" for dom in domains]) if domains else "            - '*malicious.example*'"
    
    return f"""title: CTI-Sentinel: Phát hiện kết nối C2 - {report_title}
id: {rule_id}
status: experimental
description: Tự động sinh từ hệ thống CTI-Sentinel dựa trên báo cáo phân tích đe dọa mạng thời gian thực.
references:
    - https://cisa.gov
author: CTI-Sentinel Autonomous Agent
date: {date_str}
tags:
{tag_str}
logsource:
    category: network_connection
    product: windows
detection:
    selection_ip:
        DestinationIp:
{ip_str}
    selection_domain:
        QueryName|contains:
{domain_str}
    condition: selection_ip or selection_domain
falsepositives:
    - Các máy chủ DNS công cộng hoặc dịch vụ CDN hợp pháp
level: high
"""

def generate_yara_rule(report_title: str, enriched_iocs: List[Dict[str, Any]]) -> str:
    rule_name = "CTI_Sentinel_" + "".join([c if c.isalnum() else "_" for c in report_title[:25]]).strip("_")
    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    
    hashes = [ioc["value"] for ioc in enriched_iocs if ioc["type"] in ["SHA256", "MD5"]]
    domains = [ioc["value"] for ioc in enriched_iocs if ioc["type"] == "DOMAIN"]
    
    strings_def = []
    condition_def = []
    
    idx = 1
    for h in hashes:
        strings_def.append(f'        $hash_{idx} = "{h}" ascii wide nocase')
        condition_def.append(f'$hash_{idx}')
        idx += 1
        
    for d in domains:
        strings_def.append(f'        $domain_{idx} = "{d}" ascii wide nocase')
        condition_def.append(f'$domain_{idx}')
        idx += 1
        
    if not strings_def:
        strings_def.append('        $sig_payload = "malicious_payload_signature" ascii')
        condition_def.append('$sig_payload')
        
    strings_block = "\n".join(strings_def)
    cond_block = " or ".join(condition_def)
    
    return f"""rule {rule_name}
{{
    meta:
        description = "Nhận diện mã độc từ báo cáo: {report_title}"
        author = "CTI-Sentinel Autonomous AI Agent"
        date = "{date_str}"
        threat_level = "CRITICAL"
        tlp = "CLEAR"

    strings:
{strings_block}

    condition:
        uint16(0) == 0x5A4D and ({cond_block})
}}
"""

def generate_firewall_blocklist(enriched_iocs: List[Dict[str, Any]]) -> str:
    date_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"# ==========================================================================",
        f"# CTI-SENTINEL AUTOMATED FIREWALL BLOCKLIST",
        f"# Generated at: {date_str}",
        f"# Rule: Chặn kết nối C2 và độc hại khẩn cấp",
        f"# ==========================================================================\n",
        "# 1. DANH SÁCH ĐỊA CHỈ IP ĐỘC HẠI:"
    ]
    
    ips = [ioc["value"] for ioc in enriched_iocs if ioc["type"] == "IP"]
    for ip in ips:
        lines.append(f"DROP src {ip}")
        lines.append(f"iptables -A INPUT -s {ip} -j DROP")
        lines.append(f"iptables -A OUTPUT -d {ip} -j DROP")
        
    lines.append("\n# 2. DANH SÁCH DOMAIN ĐỘC HẠI (DNS SINKHOLE):")
    domains = [ioc["value"] for ioc in enriched_iocs if ioc["type"] == "DOMAIN"]
    for dom in domains:
        lines.append(f"0.0.0.0 {dom}")
        
    return "\n".join(lines)

def generate_stix_bundle(report_title: str, enriched_iocs: List[Dict[str, Any]], mitre_techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
    bundle_id = f"bundle--{uuid.uuid4()}"
    now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    
    objects = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": f"identity--{uuid.uuid4()}",
            "created": now_iso,
            "modified": now_iso,
            "name": "CTI-Sentinel AI Agent",
            "identity_class": "system"
        }
    ]
    
    # Tạo các Attack Pattern từ MITRE
    for tech in mitre_techniques:
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": f"attack-pattern--{uuid.uuid4()}",
            "created": now_iso,
            "modified": now_iso,
            "name": tech["technique_name"],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": tech["technique_id"]
                }
            ]
        })
        
    # Tạo các STIX Indicators
    for ioc in enriched_iocs:
        pattern = ""
        if ioc["type"] == "IP":
            pattern = f"[ipv4-addr:value = '{ioc['value']}']"
        elif ioc["type"] == "DOMAIN":
            pattern = f"[domain-name:value = '{ioc['value']}']"
        elif ioc["type"] == "SHA256":
            pattern = f"[file:hashes.'SHA-256' = '{ioc['value']}']"
        elif ioc["type"] == "MD5":
            pattern = f"[file:hashes.'MD5' = '{ioc['value']}']"
            
        if pattern:
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": now_iso,
                "modified": now_iso,
                "name": f"Indicator {ioc['type']}: {ioc['value']}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now_iso
            })
            
    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects
    }
