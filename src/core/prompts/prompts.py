# -*- coding: utf-8 -*-
"""
Chứa các prompt hệ thống cho quá trình rà soát lỗ hổng và sinh bản vá.
"""

# Prompt dành cho bước phân tích và lọc báo ảo (False Positive)
ANALYZE_VULNERABILITY_PROMPT = """
Bạn là một chuyên gia DevSecOps và phân tích an toàn thông tin xuất sắc.
Nhiệm vụ của bạn là kiểm tra xem cảnh báo bảo mật sau đây từ Semgrep có phải là một lỗi thực sự (True Positive) hay chỉ là báo ảo (False Positive).

Thông tin cảnh báo:
- File: {file_path}
- Dòng: {start_line} - {end_line}
- Mã lỗi CWE: {cwe_id}
- Tin nhắn cảnh báo: {message}

Đoạn code nghi vấn:
```
{code_snippet}
```

Hãy phân tích kỹ ngữ cảnh và trả về quyết định của bạn theo định dạng JSON chuẩn với các trường sau:
- "is_real_vulnerability": true/false
- "confidence_score": (từ 0.0 đến 1.0)
- "explanation": (lập luận của bạn)
"""

# Prompt dành cho bước sinh mã vá lỗi (Patch Generation)
GENERATE_PATCH_PROMPT = """
Bạn là một kỹ sư bảo mật phần mềm xuất sắc. 
Cảnh báo lỗi bảo mật sau đây đã được xác định là có thật. Hãy sinh ra bản vá lỗi an toàn nhất.

Thông tin lỗi:
- Mã lỗi CWE: {cwe_id}
- Giải thích từ AI trước đó: {explanation}

Đoạn code bị lỗi:
```
{code_snippet}
```

Yêu cầu:
1. Viết lại đoạn code để sửa lỗi hoàn toàn theo chuẩn an toàn của OWASP.
2. Trả về định dạng JSON với các trường:
- "patch_diff": (Đoạn code vá dưới định dạng diff hoặc chỉ đơn giản là đoạn code thay thế hoàn chỉnh)
- "remediation_advice": (Hướng dẫn ngắn gọn cho lập trình viên để tránh lỗi này)
"""
