# -*- coding: utf-8 -*-
"""
SKILL AST GUARD & SANDBOX VERIFIER (PHÚC & LÂM)
Kiểm tra an toàn mã nguồn Python của Agent Skill bằng AST (chặn lệnh nguy hiểm),
biên dịch kiểm tra cú pháp (`compile`) và thực thi kiểm thử trên mẫu thử dương tính/âm tính
trong namespace cô lập (sandbox) để đo tỷ lệ bắt mẫu thực tế.
"""
import ast
import builtins
from typing import Any, Dict, List, Set

ALLOWED_IMPORTS: Set[str] = {"json", "re", "ipaddress", "typing", "datetime"}
FORBIDDEN_CALLS: Set[str] = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "open",
    "input",
    "breakpoint",
    "globals",
    "locals",
    "vars",
    "getattr",
    "setattr",
    "delattr",
}
FORBIDDEN_ATTRS: Set[str] = {
    "system",
    "popen",
    "spawn",
    "__globals__",
    "__subclasses__",
    "__builtins__",
    "__code__",
    "__class__",
}


def verify_skill_ast(code: str) -> Dict[str, Any]:
    """
    Phân tích cú pháp và kiểm tra an toàn AST cho mã nguồn Python của Skill.
    Trả về `syntax_valid`, `ast_safe`, `violations` và `error`.
    """
    if not code or not code.strip():
        return {
            "syntax_valid": False,
            "ast_safe": False,
            "violations": ["Empty skill code"],
            "error": "Empty skill code",
        }

    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return {
            "syntax_valid": False,
            "ast_safe": False,
            "violations": [f"SyntaxError at line {exc.lineno}: {exc.msg}"],
            "error": str(exc),
        }

    violations: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_mod = alias.name.split(".")[0]
                if root_mod not in ALLOWED_IMPORTS:
                    violations.append(f"Disallowed import: {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            root_mod = (node.module or "").split(".")[0]
            if root_mod not in ALLOWED_IMPORTS:
                violations.append(f"Disallowed import-from: {node.module}")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_CALLS:
                violations.append(f"Forbidden builtin call: {node.func.id}")
            elif isinstance(node.func, ast.Attribute) and node.func.attr in FORBIDDEN_ATTRS:
                violations.append(f"Forbidden attribute call: {node.func.attr}")
        elif isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_ATTRS:
            violations.append(f"Forbidden dunder/system attribute access: {node.attr}")

    if violations:
        return {
            "syntax_valid": True,
            "ast_safe": False,
            "violations": sorted(set(violations)),
            "error": "; ".join(sorted(set(violations))),
        }

    try:
        compile(code, "<cti_agent_skill>", "exec")
    except Exception as exc:
        return {
            "syntax_valid": False,
            "ast_safe": False,
            "violations": [f"Compile error: {exc}"],
            "error": str(exc),
        }

    return {
        "syntax_valid": True,
        "ast_safe": True,
        "violations": [],
        "error": None,
    }


def _safe_import(name, globals=None, locals=None, fromlist=(), level=0):
    root_mod = name.split(".")[0]
    if root_mod not in ALLOWED_IMPORTS:
        raise ImportError(f"Module '{name}' is blocked inside CTI Skill Sandbox")
    return builtins.__import__(name, globals, locals, fromlist, level)


def _build_restricted_globals() -> Dict[str, Any]:
    safe_builtins = {
        "__import__": _safe_import,
        "dict": dict,
        "list": list,
        "set": set,
        "tuple": tuple,
        "str": str,
        "int": int,
        "float": float,
        "bool": bool,
        "len": len,
        "sorted": sorted,
        "any": any,
        "all": all,
        "enumerate": enumerate,
        "zip": zip,
        "min": min,
        "max": max,
        "isinstance": isinstance,
        "Exception": Exception,
        "ValueError": ValueError,
        "TypeError": TypeError,
    }
    return {"__builtins__": safe_builtins}


def build_sandbox_probes(iocs_summary: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    """Tạo các mẫu thử dương tính (chứa đúng IOC bài báo) để kiểm tra Skill."""
    probes: List[Dict[str, Any]] = []
    for ip in iocs_summary.get("ips", [])[:2]:
        probes.append({
            "probe_type": "IP",
            "expected_value": ip,
            "telemetry": {"dst_ip": ip, "protocol": "TCP", "port": 443},
        })
    for dom in iocs_summary.get("domains", [])[:2]:
        probes.append({
            "probe_type": "DOMAIN",
            "expected_value": dom,
            "telemetry": {"query_name": dom, "record_type": "A"},
        })
    for u in iocs_summary.get("urls", [])[:1]:
        probes.append({
            "probe_type": "URL",
            "expected_value": u,
            "telemetry": {"url": u},
        })
    for h in iocs_summary.get("sha256", [])[:2]:
        probes.append({
            "probe_type": "SHA256",
            "expected_value": h,
            "telemetry": {"sha256": h, "file_name": "sample.bin"},
        })
    for h in iocs_summary.get("md5", [])[:2]:
        probes.append({
            "probe_type": "MD5",
            "expected_value": h,
            "telemetry": {"md5": h, "file_name": "sample.bin"},
        })
    for c in iocs_summary.get("cves", [])[:2]:
        probes.append({
            "probe_type": "CVE",
            "expected_value": c,
            "telemetry": {"cve_id": c, "asset": "gateway"},
        })
    return probes


def run_skill_sandbox_probes(skill_obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    Kiểm tra AST + Biên dịch + Chạy thử Skill trong sandbox cô lập
    với các mẫu dương tính (IOC trích xuất) và mẫu âm tính (telemetry sạch).
    """
    code = skill_obj.get("execution_code", "")
    ast_check = verify_skill_ast(code)
    if not ast_check["syntax_valid"] or not ast_check["ast_safe"]:
        return {
            "syntax_valid": ast_check["syntax_valid"],
            "ast_safe": ast_check["ast_safe"],
            "violations": ast_check["violations"],
            "positive_probes_total": 0,
            "positive_probes_passed": 0,
            "negative_probe_passed": False,
            "sandbox_verified": False,
            "execution_status": "FAILED",
            "probe_results": [],
            "error": ast_check["error"],
        }

    ns = _build_restricted_globals()
    try:
        exec(compile(code, "<cti_agent_skill>", "exec"), ns, ns)
        fn = ns.get("execute_cti_defense_skill")
        if not callable(fn):
            raise ValueError("Missing callable execute_cti_defense_skill(telemetry)")
    except Exception as exc:
        return {
            "syntax_valid": True,
            "ast_safe": False,
            "violations": [f"Sandbox load error: {exc}"],
            "positive_probes_total": 0,
            "positive_probes_passed": 0,
            "negative_probe_passed": False,
            "sandbox_verified": False,
            "execution_status": "FAILED",
            "probe_results": [],
            "error": str(exc),
        }

    iocs_summary = skill_obj.get("iocs_embedded", {})
    probes = build_sandbox_probes(iocs_summary)
    probe_results: List[Dict[str, Any]] = []
    passed_positive = 0

    for probe in probes:
        try:
            out = fn(probe["telemetry"])
            matched_vals = [m.get("value", "").lower() for m in out.get("matched_iocs", [])]
            ok = bool(out.get("matched")) and (probe["expected_value"].lower() in matched_vals)
            if ok:
                passed_positive += 1
            probe_results.append({
                "probe_type": probe["probe_type"],
                "expected_value": probe["expected_value"],
                "passed": ok,
                "output": out,
            })
        except Exception as exc:
            probe_results.append({
                "probe_type": probe["probe_type"],
                "expected_value": probe["expected_value"],
                "passed": False,
                "error": str(exc),
            })

    # Kiểm tra mẫu âm tính (dữ liệu hợp pháp sạch không được phép bắt nhầm)
    clean_telemetry = {
        "dst_ip": "8.8.8.8",
        "query_name": "google.com",
        "url": "https://google.com/",
        "sha256": "0" * 64,
        "md5": "0" * 32,
        "cve_id": "CVE-1999-0001",
    }
    negative_ok = False
    try:
        clean_out = fn(clean_telemetry)
        negative_ok = (clean_out.get("matched") is False) and (len(clean_out.get("matched_iocs", [])) == 0)
    except Exception:
        negative_ok = False

    sandbox_verified = (len(probes) > 0) and (passed_positive == len(probes)) and negative_ok
    return {
        "syntax_valid": True,
        "ast_safe": True,
        "violations": [],
        "positive_probes_total": len(probes),
        "positive_probes_passed": passed_positive,
        "negative_probe_passed": negative_ok,
        "sandbox_verified": sandbox_verified,
        "execution_status": "SANDBOX_VERIFIED" if sandbox_verified else "DRY_RUN",
        "probe_results": probe_results,
        "error": None,
    }
