# -*- coding: utf-8 -*-
"""
Test Suite cho SAST Analyzer (AI DevSecOps Code Security Audit)
"""
import pytest
from src.core.sast_analyzer import analyze_code, get_preset_samples

def test_sast_detects_csharp_sql_injection():
    vulnerable_csharp = '''
    public Product GetProductByName(string name) {
        string query = $"SELECT * FROM Products WHERE Name = '{name}'";
        return _context.Products.FromSqlRaw(query).FirstOrDefault();
    }
    '''
    result = analyze_code(vulnerable_csharp, language="csharp")
    assert result["status"] == "success"
    assert len(result["findings"]) > 0
    cwe_list = [f["cwe"] for f in result["findings"]]
    assert "CWE-89" in cwe_list
    assert result["severity_counts"]["CRITICAL"] >= 1
    assert "SqlParameter" in result["patched_code"] or "FromSqlInterpolated" in result["patched_code"]

def test_sast_detects_python_command_injection():
    vulnerable_py = '''
    import os
    def ping_host(host):
        cmd = f"ping -c 4 {host}"
        return os.system(cmd)
    '''
    result = analyze_code(vulnerable_py, language="python")
    assert result["status"] == "success"
    cwe_list = [f["cwe"] for f in result["findings"]]
    assert "CWE-78" in cwe_list
    assert "subprocess.run" in result["patched_code"]

def test_sast_detects_hardcoded_jwt_secret():
    vulnerable_js = '''
    const jwt = require("jsonwebtoken");
    const secret = "SUPER_SECRET_KEY_12345_DO_NOT_SHARE";
    function createToken(user) {
        return jwt.sign({ id: user.id }, secret, { expiresIn: '1h' });
    }
    '''
    result = analyze_code(vulnerable_js, language="javascript")
    assert result["status"] == "success"
    cwe_list = [f["cwe"] for f in result["findings"]]
    assert "CWE-798" in cwe_list
    assert "process.env" in result["patched_code"]

def test_sast_clean_code_has_no_critical_findings():
    safe_csharp = '''
    public Product GetProductById(int id) {
        return _context.Products.FirstOrDefault(p => p.Id == id);
    }
    '''
    result = analyze_code(safe_csharp, language="csharp")
    assert result["status"] == "success"
    assert len(result["findings"]) == 0
    assert result["severity_counts"]["CRITICAL"] == 0

def test_get_preset_samples():
    presets = get_preset_samples()
    assert len(presets) >= 4
    for key, item in presets.items():
        assert "title" in item
        assert "language" in item
        assert "code" in item
