# -*- coding: utf-8 -*-
"""
==============================================================================
RULE-BASED SAST ANALYZER & CODE VULNERABILITY AUDITOR ENGINE (LÂM / DEVSECOPS)
Bộ máy phân tích tĩnh theo luật (Rule-based SAST) phát hiện lỗ hổng OWASP Top 10,
phân loại CWE, ước tính độ tin cậy heuristic và đề xuất bản vá remediation.
Lưu ý: Đây là hệ thống phân tích tĩnh heuristic, các bản vá cần được lập trình viên
review và biên dịch/kiểm thử trước khi đưa vào production.
==============================================================================
"""
import ast
import re
from typing import Dict, Any, List, Optional, Tuple

# Danh mục các mẫu lỗ hổng phổ biến (Rule Catalog)
RULES = [
    {
        "id": "RULE-SQLI-01",
        "title": "SQL Injection (Nối chuỗi truy vấn trực tiếp)",
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "severity": "CRITICAL",
        "languages": ["csharp", "python", "javascript", "php", "sql"],
        "patterns": [
            r"FromSqlRaw\s*\(\s*\$?\s*[\"'].*?\{.*?\}",
            r"ExecuteSqlRaw\s*\(\s*\$?\s*[\"'].*?\{.*?\}",
            r"SELECT\s+.*?\s+FROM\s+.*?WHERE\s+.*?(\+\s*\w+|\{\w+\}|\%s|\$\{\w+\})",
            r"cursor\.execute\s*\(\s*f[\"'].*?\{.*?\}",
            r"db\.query\s*\(\s*[\"'].*?\+\s*\w+",
            r"mysqli_query\s*\(.*?\$.*?\.\s*\$",
        ],
        "description": "Câu lệnh SQL được hình thành bằng cách cộng chuỗi trực tiếp từ biến đầu vào của người dùng mà không qua cơ chế tham số hóa (Parameterized Query). Kẻ tấn công có thể chèn các payload như `' OR '1'='1` để bypass xác thực hoặc trích xuất toàn bộ cơ sở dữ liệu.",
        "remediation_advice": "Sử dụng Parameterized Query (SqlParameter / FromSqlInterpolated trong C# .NET, parameterized tuple (%s, ?) trong Python DB-API, hoặc Prepared Statements trong PHP/Node.js).",
        "patch_hint": "parameterized_query"
    },
    {
        "id": "RULE-XSS-01",
        "title": "Reflected / Stored Cross-Site Scripting (XSS)",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "severity": "HIGH",
        "languages": ["csharp", "javascript", "php"],
        "patterns": [
            r"@Html\.Raw\s*\(",
            r"dangerouslySetInnerHTML\s*=",
            r"\.innerHTML\s*=\s*(?![\"'])",
            r"document\.write\s*\(",
            r"echo\s+\$_GET\[",
            r"echo\s+\$_POST\[",
        ],
        "description": "Dữ liệu người dùng được hiển thị trực tiếp ra DOM/HTML mà không qua mã hóa (HTML Encode). Kẻ tấn công có thể chèn các thẻ `<script>` hoặc mã JavaScript độc hại để đánh cắp Cookie, phiên đăng nhập (Session Hijacking) hoặc chiếm quyền điều khiển trình duyệt của nạn nhân.",
        "remediation_advice": "Sử dụng các cơ chế tự động encode của framework (ví dụ `@Model.Property` trong Razor, `textContent` trong JavaScript hoặc hàm `HttpUtility.HtmlEncode()` / `DOMPurify.sanitize()`).",
        "patch_hint": "html_encode"
    },
    {
        "id": "RULE-CMDI-01",
        "title": "OS Command Injection (Thực thi lệnh hệ điều hành)",
        "cwe": "CWE-78",
        "owasp": "A03:2021 - Injection",
        "severity": "CRITICAL",
        "languages": ["csharp", "python", "javascript", "php"],
        "patterns": [
            r"os\.system\s*\(",
            r"subprocess\.Popen\s*\(.*?shell\s*=\s*True",
            r"Process\.Start\s*\(.*?[\+\$]",
            r"exec\s*\(.*?\$",
            r"child_process\.exec\s*\(",
        ],
        "description": "Ứng dụng gọi các lệnh hệ thống (System Shell) và nối trực tiếp tham số người dùng nhập. Kẻ tấn công có thể dùng toán tử ghép lệnh như `;`, `&&`, `|` để thực thi mã tùy ý (RCE) trên máy chủ.",
        "remediation_advice": "Tránh gọi shell trực tiếp. Trong Python sử dụng `subprocess.run(['command', arg], shell=False)`. Trong C# sử dụng `ProcessStartInfo` với mảng `ArgumentList`.",
        "patch_hint": "safe_subprocess"
    },
    {
        "id": "RULE-SECRET-01",
        "title": "Hardcoded Secrets / Credentials (Lộ thông tin nhạy cảm)",
        "cwe": "CWE-798",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "severity": "HIGH",
        "languages": ["csharp", "python", "javascript", "php", "sql"],
        "patterns": [
            r"(?i)(secret|password|api_key|jwt_secret|private_key)\s*[:=]\s*[\"'][a-zA-Z0-9_\-\.]{12,}[\"']",
            r"(?i)Server=.*?;Database=.*?;User\s*Id=.*?;Password=[^;]+;",
            r"(?i)mongodb(\+srv)?:\/\/[^:]+:[^@]+@",
        ],
        "description": "Khóa bí mật (API Key, JWT Secret, Database Password) bị ghi cứng trực tiếp vào mã nguồn. Khi mã nguồn được đẩy lên Git hoặc chia sẻ, kẻ xấu có thể trích xuất và chiếm đoạt toàn bộ hạ tầng backend.",
        "remediation_advice": "Chuyển toàn bộ mật khẩu, khóa bí mật ra biến môi trường (`.env`, `Environment.GetEnvironmentVariable()` hoặc dịch vụ quản lý như Azure Key Vault / AWS Secrets Manager).",
        "patch_hint": "env_secret"
    },
    {
        "id": "RULE-PATH-01",
        "title": "Path Traversal / Arbitrary File Access",
        "cwe": "CWE-22",
        "owasp": "A01:2021 - Broken Access Control",
        "severity": "HIGH",
        "languages": ["csharp", "python", "javascript", "php"],
        "patterns": [
            r"File\.(ReadAllText|OpenRead|WriteAllText)\s*\(\s*.*?(\+|\$)",
            r"open\s*\(\s*.*?f[\"'].*?\{",
            r"res\.sendFile\s*\(\s*.*?req\.(query|params)",
        ],
        "description": "Đường dẫn file được nối trực tiếp từ tham số người dùng mà không chuẩn hóa. Kẻ tấn công có thể truyền payload chứa `../../../../etc/passwd` hoặc `..\\..\\Windows\\win.ini` để đọc trộm các file nhạy cảm trên máy chủ.",
        "remediation_advice": "Sử dụng `Path.GetFileName()` để chỉ lấy tên file an toàn, kết hợp kiểm tra `Path.GetFullPath()` phải nằm trong thư mục gốc cho phép (Canonical Path Validation).",
        "patch_hint": "safe_filepath"
    },
    {
        "id": "RULE-DESER-01",
        "title": "Insecure Deserialization (Giải tuần tự hóa không an toàn)",
        "cwe": "CWE-502",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "severity": "CRITICAL",
        "languages": ["csharp", "python"],
        "patterns": [
            r"BinaryFormatter\s*\.\s*Deserialize",
            r"pickle\.loads\s*\(",
            r"yaml\.load\s*\(.*?Loader\s*=\s*yaml\.Loader",
        ],
        "description": "Giải tuần tự hóa nhị phân dữ liệu không đáng tin cậy cho phép đối tượng độc hại ghi đè gadget chains dẫn đến thực thi mã từ xa (RCE).",
        "remediation_advice": "Dùng định dạng an toàn như JSON (`System.Text.Json` hoặc `json.loads` trong Python) hoặc `yaml.safe_load()`.",
        "patch_hint": "safe_deserialization"
    }
]


def analyze_code(code: str, language: str = "csharp", filename: Optional[str] = None) -> Dict[str, Any]:
    """
    Rà soát mã nguồn đầu vào bằng Rule-based SAST.
    Trả về danh sách findings, đánh giá độ tin cậy heuristic và đề xuất remediation patch.
    """
    if not code or not code.strip():
        return {
            "status": "error",
            "message": "Mã nguồn trống. Vui lòng nhập đoạn mã cần rà soát.",
            "analysis_type": "rule_based_heuristic",
            "confidence": 0.0,
            "needs_review": False,
            "findings": [],
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "agent_trace": [],
            "original_code": "",
            "patched_code": "",
            "diff_summary": "",
            "is_syntax_valid": True
        }

    lang = language.lower().strip()
    if lang in ["csharp", "c#", "cs", "dotnet", ".net"] or lang.startswith("cs") or "dotnet" in lang:
        normalized_lang = "csharp"
    elif "py" in lang:
        normalized_lang = "python"
    elif any(k in lang for k in ["javascript", "js", "typescript", "ts", "node"]):
        normalized_lang = "javascript"
    elif "php" in lang:
        normalized_lang = "php"
    elif "sql" in lang:
        normalized_lang = "sql"
    else:
        normalized_lang = "csharp"

    lines = code.split("\n")
    findings = []

    # Quét từng quy tắc regex/mẫu tĩnh
    for rule in RULES:
        if normalized_lang not in rule["languages"] and "all" not in rule["languages"]:
            continue

        for pattern_str in rule["patterns"]:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            for idx, line in enumerate(lines, start=1):
                # Bỏ qua comment đơn dòng cơ bản để giảm false positive
                stripped = line.strip()
                if normalized_lang == "python" and stripped.startswith("#"):
                    continue
                if normalized_lang in ["csharp", "javascript", "php"] and (stripped.startswith("//") or stripped.startswith("/*")):
                    continue
                if normalized_lang == "sql" and stripped.startswith("--"):
                    continue

                match = pattern.search(line)
                if match:
                    already_found = any(f["line"] == idx and f["cwe"] == rule["cwe"] for f in findings)
                    if not already_found:
                        finding = {
                            "id": f"VULN-{len(findings) + 1:02d}",
                            "title": rule["title"],
                            "cwe": rule["cwe"],
                            "owasp": rule["owasp"],
                            "severity": rule["severity"],
                            "line": idx,
                            "vulnerable_code": line.strip(),
                            "description": rule["description"],
                            "remediation_advice": rule["remediation_advice"],
                            "patch_hint": rule.get("patch_hint", ""),
                            "confidence": 0.70  # Heuristic rule match confidence
                        }
                        findings.append(finding)

    # Đếm số lượng theo mức độ nghiêm trọng
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f["severity"].upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Tạo trace nhận diện theo các bước quy tắc
    agent_trace = _generate_agent_trace(findings, normalized_lang)

    # Sinh mã nguồn đã gợi ý vá lỗi
    patched_code, diff_summary = _synthesize_safe_patch(code, findings, normalized_lang)

    # Kiểm tra cú pháp (đặc biệt với Python bằng ast.parse)
    is_syntax_valid = True
    if normalized_lang == "python" and patched_code:
        try:
            ast.parse(patched_code)
            is_syntax_valid = True
        except SyntaxError:
            is_syntax_valid = False

    return {
        "status": "success",
        "analysis_type": "rule_based_heuristic",
        "confidence": 0.70 if findings else 1.0,
        "needs_review": True if findings else False,
        "language": normalized_lang,
        "filename": filename or f"Snippet.{_get_ext(normalized_lang)}",
        "total_issues": len(findings),
        "severity_counts": severity_counts,
        "findings": findings,
        "agent_trace": agent_trace,
        "original_code": code,
        "patched_code": patched_code,
        "diff_summary": diff_summary,
        "is_syntax_valid": is_syntax_valid
    }


def _get_ext(lang: str) -> str:
    mapping = {"csharp": "cs", "python": "py", "javascript": "js", "php": "php", "sql": "sql"}
    return mapping.get(lang, "txt")


def _generate_agent_trace(findings: List[Dict[str, Any]], lang: str) -> List[Dict[str, Any]]:
    """Quy trình đánh giá tĩnh Rule-based SAST theo 3 giai đoạn."""
    if not findings:
        return [
            {
                "step": 1,
                "phase": "🔍 Bước 1: Quét Mẫu Quy Tắc (Rule-based Scanning)",
                "detail": f"Rà soát cấu trúc mã nguồn {lang.upper()} với bộ mẫu OWASP/CWE. Không phát hiện vi phạm quy tắc tĩnh."
            },
            {
                "step": 2,
                "phase": "🧠 Bước 2: Kiểm Tra Ngữ Cảnh Heuristic",
                "detail": "Không phát hiện lời gọi trực tiếp tới các Sink nhạy cảm không được kiểm soát."
            },
            {
                "step": 3,
                "phase": "🛡️ Bước 3: Đánh Giá & Khuyến Nghị",
                "detail": "Mã nguồn đạt chuẩn tĩnh ban đầu. Khuyến nghị kết hợp thêm Unit Test và Dynamic Testing (DAST)."
            }
        ]

    cwe_names = ", ".join(sorted(list(set(f["cwe"] for f in findings))))
    return [
        {
            "step": 1,
            "phase": "🔍 Bước 1: Quét Mẫu Quy Tắc (Rule-based Pattern Matching)",
            "detail": f"Khớp mẫu tĩnh tại các dòng ({', '.join(str(f['line']) for f in findings)}). Phát hiện dấu hiệu thuộc nhóm: {cwe_names}."
        },
        {
            "step": 2,
            "phase": "🧠 Bước 2: Phân Tích Mức Độ Khớp Mẫu (Heuristic Matching)",
            "detail": f"Đánh giá sơ bộ: Phát hiện {len(findings)} điểm nghi vấn không tuân thủ mẫu an toàn chuẩn. Cần lập trình viên review ngữ cảnh luồng dữ liệu."
        },
        {
            "step": 3,
            "phase": "🛡️ Bước 3: Đề Xuất Khắc Phục (Remediation Guidance)",
            "detail": "Đã tạo đoạn mã gợi ý vá lỗi (Remediation Suggestion) sử dụng mẫu thiết kế phòng thủ (Parameterized Query, Text Content, Subprocess không shell, Biến môi trường)."
        }
    ]


def _synthesize_safe_patch(code: str, findings: List[Dict[str, Any]], lang: str) -> Tuple[str, str]:
    """
    Tạo bản vá đề xuất (Remediation Suggestion) bảo tồn ngữ cảnh tối đa.
    """
    if not findings:
        return code, "Mã nguồn đã an toàn, không cần thay đổi."

    lines = code.split("\n")
    diff_notes = []

    for f in findings:
        idx = f["line"] - 1
        if 0 <= idx < len(lines):
            orig_line = lines[idx]
            indent = orig_line[:len(orig_line) - len(orig_line.lstrip())]
            hint = f.get("patch_hint", "")
            patched_line = orig_line

            if hint == "parameterized_query":
                if lang == "csharp":
                    if "FromSqlRaw" in orig_line:
                        patched_line = re.sub(
                            r"FromSqlRaw\s*\(\s*\$?\s*[\"'](.*?)[\"']\s*\)",
                            r'FromSqlInterpolated($"\1") /* [REMEDIATION]: Parameterized Query via Entity Framework Core */',
                            orig_line
                        )
                    elif "ExecuteSqlRaw" in orig_line:
                        patched_line = re.sub(
                            r"ExecuteSqlRaw\s*\(\s*\$?\s*[\"'](.*?)[\"']\s*\)",
                            r'ExecuteSqlInterpolated($"\1") /* [REMEDIATION]: Chống SQL Injection bằng SqlParameter */',
                            orig_line
                        )
                    else:
                        patched_line = f'{indent}// [REMEDIATION]: Sử dụng Parameterized Query với SqlParameter hoặc FromSqlInterpolated\n{indent}/* TODO: Thay thế chuỗi ghép bằng SqlParameter: new SqlParameter("@param", paramValue) */\n{orig_line}'
                elif lang == "python":
                    if "cursor.execute" in orig_line and "f\"" in orig_line or "f'" in orig_line:
                        patched_line = f'{indent}# [REMEDIATION]: Dùng parameterized tuple (%s) thay vì f-string\n{indent}# cursor.execute("SELECT ... WHERE col = %s", (param,))\n{orig_line}'
                    else:
                        patched_line = f'{indent}# [REMEDIATION]: Dùng parameterized tuple (%s) thay vì f-string\n{indent}cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))'
                elif lang == "javascript":
                    patched_line = f'{indent}// [REMEDIATION]: Sử dụng Prepared Statement với tham số $1, $2 an toàn\n{indent}const result = await db.query("SELECT * FROM users WHERE id = $1", [userId]);'

            elif hint == "html_encode":
                if lang == "csharp":
                    patched_line = orig_line.replace("@Html.Raw(", "@Html.DisplayFor(m => ").replace(")", ")") + " // [REMEDIATION]: Tự động HTML Encode chống XSS"
                elif lang == "javascript":
                    patched_line = orig_line.replace(".innerHTML =", ".textContent =") + " // [REMEDIATION]: Thay innerHTML bằng textContent an toàn"

            elif hint == "safe_subprocess":
                if lang == "python":
                    patched_line = f'{indent}# [REMEDIATION]: Tắt shell=True và truyền argument dạng mảng\n{indent}res = subprocess.run(["ping", "-c", "4", host], capture_output=True, text=True, check=False)'
                elif lang == "csharp":
                    patched_line = f'{indent}// [REMEDIATION]: Dùng ArgumentList để tránh chèn lệnh Command Injection\n{indent}var psi = new ProcessStartInfo("ping") {{ ArgumentList = {{ host }} }}; Process.Start(psi);'

            elif hint == "env_secret":
                if lang == "csharp":
                    patched_line = f'{indent}// [REMEDIATION]: Đọc secret từ IConfiguration / appsettings thay vì hardcode\n{indent}var secretKey = configuration["Jwt:SecretKey"] ?? throw new InvalidOperationException("Secret missing!");'
                elif lang == "python":
                    patched_line = f'{indent}# [REMEDIATION]: Đọc secret từ biến môi trường\n{indent}secret_key = os.getenv("JWT_SECRET_KEY")'
                elif lang == "javascript":
                    patched_line = f'{indent}// [REMEDIATION]: Lấy secret an toàn qua process.env\n{indent}const secret = process.env.JWT_SECRET || process.env.APP_SECRET;'

            elif hint == "safe_filepath":
                if lang == "csharp":
                    patched_line = f'{indent}// [REMEDIATION]: Canonical Path Validation ngăn chặn Path Traversal\n{indent}string safeFileName = Path.GetFileName(userInput);\n{indent}string fullPath = Path.Combine(baseDirectory, safeFileName);'
                elif lang == "python":
                    patched_line = f'{indent}# [REMEDIATION]: Ngăn chặn Path Traversal\n{indent}safe_name = os.path.basename(user_input)\n{indent}safe_path = os.path.join(BASE_DIR, safe_name)'

            elif hint == "safe_deserialization":
                if lang == "csharp":
                    patched_line = f'{indent}// [REMEDIATION]: Thay BinaryFormatter bằng System.Text.Json\n{indent}var data = JsonSerializer.Deserialize<MyModel>(jsonString);'
                elif lang == "python":
                    patched_line = f'{indent}# [REMEDIATION]: Dùng yaml.safe_load thay vì yaml.load\n{indent}data = yaml.safe_load(user_content)'

            lines[idx] = patched_line
            diff_notes.append(f"- Dòng {f['line']}: Đề xuất sửa [{f['cwe']}] {f['title']}")

    patched_code = "\n".join(lines)
    diff_summary = "\n".join(diff_notes)
    return patched_code, diff_summary


def get_preset_samples() -> Dict[str, Dict[str, Any]]:
    """Trả về 5 đoạn mã nguồn có sẵn lỗ hổng thực tế để sinh viên và giảng viên test ngay."""
    return {
        "csharp_sqli": {
            "title": "C# ASP.NET Core - SQL Injection (Raw Query)",
            "language": "csharp",
            "cwe": "CWE-89",
            "severity": "CRITICAL",
            "description": "Nối chuỗi trực tiếp từ tham số người dùng nhập vào DbContext.FromSqlRaw",
            "code": """using System;
using System.Linq;
using Microsoft.EntityFrameworkCore;

namespace ProductStore.Repositories
{
    public class ProductRepository
    {
        private readonly ApplicationDbContext _context;

        public ProductRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        // LỖ HỔNG: Nối chuỗi trực tiếp biến 'searchTerm' vào câu lệnh SQL
        public Product SearchProduct(string searchTerm)
        {
            string rawSql = $"SELECT * FROM Products WHERE Name = '{searchTerm}' AND IsActive = 1";
            return _context.Products.FromSqlRaw(rawSql).FirstOrDefault();
        }
    }
}"""
        },
        "csharp_xss": {
            "title": "C# ASP.NET MVC Razor - Stored XSS (@Html.Raw)",
            "language": "csharp",
            "cwe": "CWE-79",
            "severity": "HIGH",
            "description": "Render bình luận của người dùng bằng @Html.Raw mà không escape",
            "code": """@model ProductStore.Models.ProductReview

<div class="review-box">
    <h4>Bình luận của khách hàng:</h4>
    <!-- LỖ HỔNG: @Html.Raw cho phép render trực tiếp mã <script>alert(1)</script> -->
    <p class="comment-content">
        @Html.Raw(Model.UserComment)
    </p>
    <span class="user-badge">Đăng bởi: @Model.AuthorName</span>
</div>"""
        },
        "python_cmdi": {
            "title": "Python Flask - Command Injection (os.system)",
            "language": "python",
            "cwe": "CWE-78",
            "severity": "CRITICAL",
            "description": "Chạy lệnh ping máy chủ với tham số nhận từ client qua os.system",
            "code": """import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# LỖ HỔNG: Kẻ tấn công có thể truyền IP: '8.8.8.8; cat /etc/passwd'
@app.route("/api/network/ping", methods=["GET"])
def check_connection():
    target_host = request.args.get("host", "127.0.0.1")
    command = f"ping -c 3 {target_host}"
    exit_code = os.system(command)
    return jsonify({"status": "completed", "code": exit_code})

if __name__ == "__main__":
    app.run(port=5000)"""
        },
        "nodejs_secret": {
            "title": "Node.js Express - Lộ JWT Secret & Hardcoded Key",
            "language": "javascript",
            "cwe": "CWE-798",
            "severity": "HIGH",
            "description": "Hardcode bí mật ký token JWT và chuỗi kết nối trực tiếp trong file code",
            "code": """const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

// LỖ HỔNG: Hardcoded secret key và database password trong mã nguồn
const JWT_SECRET = "MY_SUPER_SECRET_PRODUCTION_KEY_2026_XYZ";
const DB_URL = "Server=db.company.com;Database=SecOps;User Id=sa;Password=SuperSecretAdminPassword123;";

app.post('/api/auth/login', (req, res) => {
    const user = { id: req.body.username, role: 'admin' };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '2h' });
    res.json({ token });
});

app.listen(3000);"""
        },
        "csharp_pathtraversal": {
            "title": "C# .NET - Path Traversal (File.ReadAllText)",
            "language": "csharp",
            "cwe": "CWE-22",
            "severity": "HIGH",
            "description": "Đọc file log theo tên file do người dùng truyền vào mà không validate đường dẫn",
            "code": """using System;
using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace SecureApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class LogViewerController : ControllerBase
    {
        // LỖ HỔNG: Nhận fileName: '../../../../Windows/win.ini' hoặc '../../appsettings.json'
        [HttpGet("view")]
        public IActionResult ViewLog([FromQuery] string fileName)
        {
            string baseFolder = @"C:\\AppLogs\\";
            string targetPath = baseFolder + fileName;
            string content = File.ReadAllText(targetPath);
            return Ok(content);
        }
    }
}"""
        }
    }
