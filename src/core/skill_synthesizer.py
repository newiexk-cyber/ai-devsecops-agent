# -*- coding: utf-8 -*-
"""
DYNAMIC CTI AGENT SKILL SYNTHESIZER (PHÚC & LÂM)
Chuyển đổi kết quả phân tích bài báo CTI (IPs, Domains, URLs, Hashes, CVEs, MITRE ATT&CK)
thành Kỹ năng Phòng thủ Tác tử (Dynamic Agent Skill) có thể kiểm chứng AST và chạy thử trong sandbox.
- Không sinh dữ liệu/IOC giả khi bài báo không có chỉ số hành động.
- Không nhúng chuỗi thô chưa escape vào Python code (sử dụng json.dumps an toàn).
- Luôn giữ trạng thái thực thi `DRY_RUN` / `SANDBOX_VERIFIED`, không bao giờ báo `ENFORCED` giả.
"""
import json
import re
from typing import Any, Dict, List, Optional

from src.core.skill_verifier import run_skill_sandbox_probes


def _make_safe_skill_name(title: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", (title or "cti_threat").lower()).strip("_")
    slug = slug[:36].strip("_") or "cti_threat"
    return f"cti_defense_{slug}"


def _build_python_skill_code(
    skill_name: str,
    title: str,
    ips: List[str],
    domains: List[str],
    urls: List[str],
    sha256: List[str],
    md5: List[str],
    cves: List[str],
) -> str:
    """Sinh mã nguồn Python thực thi an toàn từ các IOC đã chuẩn hóa qua json.dumps."""
    safe_title = json.dumps(title or "CTI Threat Advisory", ensure_ascii=True)
    safe_skill = json.dumps(skill_name, ensure_ascii=True)
    ips_json = json.dumps(sorted(set(ips)), ensure_ascii=True)
    domains_json = json.dumps(sorted({d.lower() for d in domains}), ensure_ascii=True)
    urls_json = json.dumps(sorted(set(urls)), ensure_ascii=True)
    sha256_json = json.dumps(sorted({h.lower() for h in sha256}), ensure_ascii=True)
    md5_json = json.dumps(sorted({h.lower() for h in md5}), ensure_ascii=True)
    cves_json = json.dumps(sorted({c.upper() for c in cves}), ensure_ascii=True)

    return f'''# -*- coding: utf-8 -*-
"""
Auto-generated CTI Defense Agent Skill: {skill_name}
Source Advisory: {title.replace('"', "'")[:120]}
"""
from typing import Any, Dict, List

SKILL_NAME = {safe_skill}
ADVISORY_TITLE = {safe_title}
WATCH_IPS: List[str] = {ips_json}
WATCH_DOMAINS: List[str] = {domains_json}
WATCH_URLS: List[str] = {urls_json}
WATCH_SHA256: List[str] = {sha256_json}
WATCH_MD5: List[str] = {md5_json}
WATCH_CVES: List[str] = {cves_json}


def _collect_strings(obj: Any) -> List[str]:
    if isinstance(obj, str):
        return [obj.strip()]
    if isinstance(obj, list):
        out: List[str] = []
        for x in obj:
            out.extend(_collect_strings(x))
        return out
    return []


def execute_cti_defense_skill(telemetry: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """
    Đối chiếu telemetry đầu vào (network flow, DNS query, file hash, asset CVE)
    với tập IOC trích xuất từ bản tin CTI và xuất kế hoạch phản ứng ở chế độ DRY_RUN.
    """
    if not isinstance(telemetry, dict):
        raise ValueError("telemetry must be a dictionary")

    matched_iocs: List[Dict[str, str]] = []
    actions: List[str] = []
    dry_run_commands: List[str] = []

    ip_candidates = (
        _collect_strings(telemetry.get("dst_ip"))
        + _collect_strings(telemetry.get("src_ip"))
        + _collect_strings(telemetry.get("ip"))
        + _collect_strings(telemetry.get("ips"))
    )
    for ip_val in ip_candidates:
        if ip_val in WATCH_IPS:
            matched_iocs.append({{"type": "IP", "value": ip_val}})
            actions.append(f"Chặn kết nối ra vào IP C2 {{ip_val}} và rà soát phiên mạng đang mở.")
            dry_run_commands.append(f"iptables -A OUTPUT -d {{ip_val}} -j DROP")

    dom_candidates = (
        _collect_strings(telemetry.get("query_name"))
        + _collect_strings(telemetry.get("domain"))
        + _collect_strings(telemetry.get("domains"))
        + _collect_strings(telemetry.get("hostname"))
    )
    for dom_val in dom_candidates:
        dom_low = dom_val.lower().rstrip(".")
        if any(dom_low == d or dom_low.endswith("." + d) for d in WATCH_DOMAINS):
            matched_iocs.append({{"type": "DOMAIN", "value": dom_low}})
            actions.append(f"Sinkhole tên miền độc hại {{dom_low}} trên DNS nội bộ.")
            dry_run_commands.append(f"address=/{{dom_low}}/0.0.0.0")

    url_candidates = _collect_strings(telemetry.get("url")) + _collect_strings(telemetry.get("urls"))
    for url_val in url_candidates:
        if url_val in WATCH_URLS:
            matched_iocs.append({{"type": "URL", "value": url_val}})
            actions.append(f"Chặn truy cập HTTP/HTTPS tới URL phát tán payload {{url_val}}.")

    hash_candidates = (
        _collect_strings(telemetry.get("sha256"))
        + _collect_strings(telemetry.get("md5"))
        + _collect_strings(telemetry.get("file_hash"))
        + _collect_strings(telemetry.get("hashes"))
    )
    for h_val in hash_candidates:
        h_low = h_val.lower()
        if h_low in WATCH_SHA256:
            matched_iocs.append({{"type": "SHA256", "value": h_low}})
            actions.append(f"Cách ly tệp và dừng tiến trình khớp mã băm SHA256 {{h_low}}.")
        elif h_low in WATCH_MD5:
            matched_iocs.append({{"type": "MD5", "value": h_low}})
            actions.append(f"Cách ly tệp khớp mã băm MD5 {{h_low}}.")

    cve_candidates = (
        _collect_strings(telemetry.get("cve_id"))
        + _collect_strings(telemetry.get("cve"))
        + _collect_strings(telemetry.get("cves"))
    )
    for cve_val in cve_candidates:
        cve_up = cve_val.upper()
        if cve_up in WATCH_CVES:
            matched_iocs.append({{"type": "CVE", "value": cve_up}})
            actions.append(f"Đánh dấu tài sản có phơi nhiễm lỗ hổng {{cve_up}} cần vá khẩn.")

    # Khử trùng kết quả khớp giữ nguyên thứ tự
    unique_matches: List[Dict[str, str]] = []
    seen = set()
    for item in matched_iocs:
        key = (item["type"], item["value"])
        if key not in seen:
            seen.add(key)
            unique_matches.append(item)

    return {{
        "skill_name": SKILL_NAME,
        "advisory_title": ADVISORY_TITLE,
        "matched": len(unique_matches) > 0,
        "matched_iocs": unique_matches,
        "recommended_actions": actions,
        "dry_run_commands": dry_run_commands,
        "execution_status": "DRY_RUN" if dry_run else "PENDING_APPROVAL",
    }}
'''


def synthesize_cti_skill(
    analysis_result: Dict[str, Any],
    enriched_iocs: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Sinh Dynamic Agent Skill hoàn chỉnh từ kết quả phân tích bài báo CTI.
    Kiểm tra ngay bằng AST Guard & Sandbox Probes trước khi trả về.
    """
    title = analysis_result.get("title", "CTI Threat Advisory")
    ips = list(analysis_result.get("ips", []))
    domains = list(analysis_result.get("domains", []))
    urls = list(analysis_result.get("urls", []))
    sha256 = list(analysis_result.get("sha256", []))
    md5 = list(analysis_result.get("md5", []))
    cves = list(analysis_result.get("cves", []))

    if not any([ips, domains, urls, sha256, md5, cves]):
        raise ValueError("No actionable IOCs available to synthesize CTI defense skill")

    skill_name = _make_safe_skill_name(title)
    actors = ", ".join(analysis_result.get("threat_actors", [])) or "Unattributed Threat Activity"
    malwares = ", ".join(analysis_result.get("malware_families", [])) or "Unspecified Payload"
    mitre_ids = [
        m.get("technique_id")
        for m in analysis_result.get("mitre_techniques", [])
        if m.get("technique_id")
    ]

    description = (
        f"CTI detection and containment skill synthesized from advisory '{title}'. "
        f"Covers {len(ips)} IP(s), {len(domains)} domain(s), {len(sha256) + len(md5)} file hash(es), "
        f"and {len(cves)} CVE(s) linked to {actors} / {malwares}."
    )

    system_prompt = (
        f"Bạn là Autonomous CTI Defense Agent xử lý sự cố liên quan tới '{title}'.\n"
        f"- Thực thể ghi nhận: {actors} | Mã độc: {malwares} | MITRE ATT&CK: {', '.join(mitre_ids) or 'N/A'}.\n"
        f"- Luôn gọi `{skill_name}` với `dry_run=True` trước để kiểm chứng telemetry endpoint/SIEM.\n"
        f"- Chỉ đề xuất cô lập hoặc chặn sau khi đối chiếu trùng khớp ít nhất 1 IOC đã xác thực trong danh sách."
    )

    parameters_schema = {
        "type": "object",
        "properties": {
            "telemetry": {
                "type": "object",
                "description": "Event telemetry payload containing dst_ip, query_name, url, sha256, md5, or cve_id",
            },
            "dry_run": {
                "type": "boolean",
                "description": "Simulate detection and containment plan without modifying live devices",
            },
        },
        "required": ["telemetry", "dry_run"],
        "additionalProperties": False,
    }

    openai_schema = {
        "type": "function",
        "function": {
            "name": skill_name,
            "description": description,
            "parameters": parameters_schema,
            "strict": True,
        },
    }

    anthropic_schema = {
        "name": skill_name,
        "description": description,
        "input_schema": parameters_schema,
    }

    gemini_schema = {
        "name": skill_name,
        "description": description,
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "telemetry": {"type": "OBJECT", "description": parameters_schema["properties"]["telemetry"]["description"]},
                "dry_run": {"type": "BOOLEAN", "description": parameters_schema["properties"]["dry_run"]["description"]},
            },
            "required": ["telemetry", "dry_run"],
        },
    }

    langchain_wrapper = (
        f"from langchain_core.tools import tool\n"
        f"from typing import Dict, Any\n\n"
        f"@tool\n"
        f"def {skill_name}_tool(telemetry: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:\n"
        f'    """{description}"""\n'
        f"    return execute_cti_defense_skill(telemetry=telemetry, dry_run=dry_run)\n"
    )

    execution_code = _build_python_skill_code(
        skill_name=skill_name,
        title=title,
        ips=ips,
        domains=domains,
        urls=urls,
        sha256=sha256,
        md5=md5,
        cves=cves,
    )

    iocs_embedded = {
        "ips": sorted(set(ips)),
        "domains": sorted({d.lower() for d in domains}),
        "urls": sorted(set(urls)),
        "sha256": sorted({h.lower() for h in sha256}),
        "md5": sorted({h.lower() for h in md5}),
        "cves": sorted({c.upper() for c in cves}),
    }

    skill_obj: Dict[str, Any] = {
        "skill_name": skill_name,
        "description": description,
        "system_prompt": system_prompt,
        "parameters": parameters_schema,
        "iocs_embedded": iocs_embedded,
        "mitre_techniques": mitre_ids,
        "execution_code": execution_code,
        "model_schemas": {
            "openai": json.dumps(openai_schema, indent=2, ensure_ascii=False),
            "anthropic": json.dumps(anthropic_schema, indent=2, ensure_ascii=False),
            "gemini": json.dumps(gemini_schema, indent=2, ensure_ascii=False),
            "langchain": langchain_wrapper,
            "python": execution_code,
        },
        "requires_human_approval": True,
        "verification_step": "Chạy execute_cti_defense_skill trong sandbox cô lập với mẫu dương tính/âm tính trước khi cấp quyền áp dụng.",
    }

    verification = run_skill_sandbox_probes(skill_obj)
    skill_obj["verification"] = verification
    skill_obj["execution_status"] = verification["execution_status"]
    skill_obj["code_compiled_successfully"] = verification["syntax_valid"]
    skill_obj["ast_safe"] = verification["ast_safe"]

    return skill_obj
