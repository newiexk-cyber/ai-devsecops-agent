# -*- coding: utf-8 -*-
"""
Module: src/security/stix_converter.py
Phụ trách: KHANG (Threat Intel & Enrichment Lead)
Chức năng:
  - Tool 5 (`export_stix_package`): Chuyển đổi kết quả phân tích CTI (EnrichedIOC, MitreTechnique,
    Threat Actors, ThreatIntelReport) sang gói chuẩn quốc tế OASIS STIX 2.1 Bundle JSON
    để sẵn sàng import trực tiếp vào OpenCTI, MISP hoặc SIEM.
"""

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from shared.schemas import EnrichedIOC, MitreTechnique, ThreatIntelReport

NAMESPACE_CTI = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


def _stix_id(sdo_type: str, seed: str) -> str:
    """Sinh STIX 2.1 ID chuẩn định dạng `<type>--<uuidv5>` có tính tất định (deterministic)."""
    deterministic_uuid = uuid.uuid5(NAMESPACE_CTI, f"{sdo_type}:{seed.strip().lower()}")
    return f"{sdo_type}--{deterministic_uuid}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_stix_pattern(ioc_type: str, value: str) -> str:
    """Chuyển đổi giá trị IOC sang biểu thức mẫu STIX 2.1 Pattern chuẩn OASIS."""
    t = ioc_type.strip().upper()
    v = value.strip().replace("'", "\\'")
    if t == "IP":
        if ":" in v:
            return f"[ipv6-addr:value = '{v}']"
        return f"[ipv4-addr:value = '{v}']"
    if t == "DOMAIN":
        return f"[domain-name:value = '{v}']"
    if t == "URL":
        return f"[url:value = '{v}']"
    if t == "MD5":
        return f"[file:hashes.MD5 = '{v}']"
    if t == "SHA256":
        return f"[file:hashes.'SHA-256' = '{v}']"
    return f"[artifact:payload_bin = '{v}']"


# ============================================================================
# TOOL 5: ĐÓNG GÓI BÁO CÁO CHUẨN QUỐC TẾ STIX 2.1 JSON
# ============================================================================
def export_stix_package(
    report_or_title: Union[ThreatIntelReport, str],
    enriched_iocs: Optional[List[EnrichedIOC]] = None,
    mitre_techniques: Optional[List[MitreTechnique]] = None,
    threat_actors: Optional[List[str]] = None,
    executive_summary: str = "",
    output_file: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Tool 5: Đóng gói toàn bộ chiến dịch tấn công thành tệp STIX 2.1 Bundle JSON chuẩn OASIS.
    Có thể truyền trực tiếp đối tượng `ThreatIntelReport` hoặc truyền từng thành phần rời.
    """
    if isinstance(report_or_title, ThreatIntelReport):
        title = report_or_title.title
        summary = report_or_title.executive_summary
        iocs = report_or_title.enriched_iocs
        techniques = report_or_title.mitre_attack_matrix
        actors = report_or_title.threat_actors
        report_seed = report_or_title.report_id or title
    else:
        title = str(report_or_title)
        summary = executive_summary or f"Automated CTI Threat Report for {title}"
        iocs = enriched_iocs or []
        techniques = mitre_techniques or []
        actors = threat_actors or []
        report_seed = title

    timestamp = _now_iso()
    objects: List[Dict[str, Any]] = []
    object_refs: List[str] = []

    # 1. Tạo thực thể Identity đại diện cho Hệ thống AI CTI Agent
    author_id = _stix_id("identity", "autonomous-cti-ai-agent")
    objects.append(
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": author_id,
            "created": timestamp,
            "modified": timestamp,
            "name": "Autonomous CTI AI Agent System",
            "identity_class": "system",
        }
    )
    object_refs.append(author_id)

    # 2. Tạo các thực thể Threat Actor (nếu có)
    actor_ids: List[str] = []
    for actor_name in actors:
        actor_id = _stix_id("threat-actor", actor_name)
        actor_ids.append(actor_id)
        object_refs.append(actor_id)
        objects.append(
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": actor_id,
                "created": timestamp,
                "modified": timestamp,
                "name": actor_name,
                "threat_actor_types": ["nation-state", "hacker-group"],
            }
        )

    # 3. Tạo các thực thể Indicator / Vulnerability từ danh sách EnrichedIOC độc hại
    indicator_ids: List[str] = []
    for enriched in iocs:
        if not enriched.is_malicious:
            continue
        raw = enriched.ioc
        ioc_type = raw.ioc_type.strip().upper()

        if ioc_type == "CVE":
            vuln_id = _stix_id("vulnerability", raw.value)
            object_refs.append(vuln_id)
            objects.append(
                {
                    "type": "vulnerability",
                    "spec_version": "2.1",
                    "id": vuln_id,
                    "created": timestamp,
                    "modified": timestamp,
                    "name": raw.value.upper(),
                    "description": raw.context_sentence,
                    "external_references": [
                        {
                            "source_name": "cve",
                            "external_id": raw.value.upper(),
                        }
                    ],
                }
            )
            continue

        if ioc_type == "APT_ACTOR":
            continue

        ind_id = _stix_id("indicator", f"{ioc_type}:{raw.value}")
        indicator_ids.append(ind_id)
        object_refs.append(ind_id)
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "created": timestamp,
                "modified": timestamp,
                "name": f"Malicious {ioc_type}: {raw.value}",
                "description": (
                    f"{raw.context_sentence} | Source: {enriched.enrichment_source} "
                    f"(Reputation Score: {enriched.reputation_score}/100)"
                ),
                "indicator_types": ["malicious-activity"],
                "pattern": _build_stix_pattern(ioc_type, raw.value),
                "pattern_type": "stix",
                "valid_from": timestamp,
                "confidence": int(enriched.reputation_score),
            }
        )

    # 4. Tạo các thực thể Attack-Pattern từ danh sách MITRE ATT&CK
    attack_pattern_ids: List[str] = []
    for tech in techniques:
        ap_id = _stix_id("attack-pattern", tech.technique_id)
        attack_pattern_ids.append(ap_id)
        object_refs.append(ap_id)
        objects.append(
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": timestamp,
                "modified": timestamp,
                "name": f"{tech.technique_id} - {tech.technique_name}",
                "description": f"Tactic: {tech.tactic} | Evidence: {tech.evidence}",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tech.technique_id,
                        "url": f"https://attack.mitre.org/techniques/{tech.technique_id.replace('.', '/')}/",
                    }
                ],
            }
        )

    # 5. Tạo các liên kết Relationship (Indicator -> indicates -> Threat Actor / Attack Pattern)
    target_links = actor_ids or attack_pattern_ids
    for ind_id in indicator_ids:
        for target_id in target_links:
            rel_id = _stix_id("relationship", f"{ind_id}->indicates->{target_id}")
            object_refs.append(rel_id)
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": rel_id,
                    "created": timestamp,
                    "modified": timestamp,
                    "relationship_type": "indicates",
                    "source_ref": ind_id,
                    "target_ref": target_id,
                }
            )

    # 6. Tạo thực thể Report tổng hợp toàn bộ chiến dịch
    report_sdo_id = _stix_id("report", report_seed)
    objects.append(
        {
            "type": "report",
            "spec_version": "2.1",
            "id": report_sdo_id,
            "created": timestamp,
            "modified": timestamp,
            "name": title,
            "description": summary,
            "published": timestamp,
            "created_by_ref": author_id,
            "report_types": ["threat-report", "attack-pattern", "indicator"],
            "object_refs": object_refs,
        }
    )

    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle", report_seed),
        "spec_version": "2.1",
        "objects": objects,
    }

    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")

    return bundle
