# -*- coding: utf-8 -*-
"""
Unit tests cho Dynamic CTI Skill Synthesizer & AST/Sandbox Verifier.
"""
import pytest

from src.core.skill_synthesizer import synthesize_cti_skill
from src.core.skill_verifier import verify_skill_ast, run_skill_sandbox_probes


SAMPLE_ANALYSIS = {
    "title": "Lumma Stealer C2 and Payload Analysis",
    "ips": ["91.240.118.172"],
    "domains": ["cdn-verify-human.site"],
    "urls": ["https://cdn-verify-human.site/payload.bin"],
    "sha256": ["d8e8fca2dc64a589e472659021e90ef830026f83d9e4871b5853b0068579cf44"],
    "md5": [],
    "cves": ["CVE-2024-3400"],
    "threat_actors": [],
    "malware_families": ["Lumma"],
    "mitre_techniques": [{"technique_id": "T1059.001", "technique_name": "PowerShell"}],
    "analysis_mode": "hybrid_local_llm",
}


def test_synthesize_cti_skill_contains_multi_model_schemas_and_valid_code():
    skill = synthesize_cti_skill(SAMPLE_ANALYSIS)

    assert skill["skill_name"].startswith("cti_defense_")
    assert skill["execution_status"] in {"DRY_RUN", "SANDBOX_VERIFIED"}
    assert "ENFORCED" not in skill["execution_status"]
    assert set(["openai", "anthropic", "gemini", "langchain", "python"]).issubset(
        skill["model_schemas"].keys()
    )
    assert "91.240.118.172" in skill["execution_code"]
    assert "cdn-verify-human.site" in skill["execution_code"]
    assert "d8e8fca2dc64a589e472659021e90ef830026f83d9e4871b5853b0068579cf44" in skill["execution_code"]


def test_synthesize_cti_skill_rejects_empty_iocs_without_fabricating():
    empty_analysis = {
        "title": "General Commentary Without Indicators",
        "ips": [],
        "domains": [],
        "urls": [],
        "sha256": [],
        "md5": [],
        "cves": [],
    }
    with pytest.raises(ValueError, match="No actionable IOCs"):
        synthesize_cti_skill(empty_analysis)


def test_verify_skill_ast_blocks_dangerous_imports_and_calls():
    bad_code = """
import subprocess
def execute_cti_defense_skill(telemetry):
    subprocess.run(["rm", "-rf", "/"])
    return {"matched": False}
"""
    res = verify_skill_ast(bad_code)
    assert res["ast_safe"] is False
    assert any("subprocess" in v for v in res["violations"])

    eval_code = """
def execute_cti_defense_skill(telemetry):
    return eval(telemetry.get("cmd", "1"))
"""
    eval_res = verify_skill_ast(eval_code)
    assert eval_res["ast_safe"] is False
    assert any("eval" in v for v in eval_res["violations"])


def test_sandbox_probes_match_positive_and_ignore_negative_telemetry():
    skill = synthesize_cti_skill(SAMPLE_ANALYSIS)
    report = run_skill_sandbox_probes(skill)

    assert report["syntax_valid"] is True
    assert report["ast_safe"] is True
    assert report["positive_probes_total"] >= 4
    assert report["positive_probes_passed"] == report["positive_probes_total"]
    assert report["negative_probe_passed"] is True
    assert report["sandbox_verified"] is True
    assert report["execution_status"] == "SANDBOX_VERIFIED"
