# -*- coding: utf-8 -*-
"""
GIAO ƯỚC DỮ LIỆU CHUNG (SHARED SCHEMAS)
Nơi quy định cấu trúc dữ liệu trao đổi giữa KHANG, PHÚC và LÂM.
Không ai được tự ý đổi cấu trúc này khi chưa thảo luận chung.
"""
from pydantic import BaseModel, Field
from typing import List, Optional

# ============================================================================
# 1. KHANG XUẤT RA CHO PHÚC DÙNG (KẾT QUẢ QUÉT SEMGREP)
# ============================================================================
class RawAlert(BaseModel):
    tool: str = Field(default="Semgrep", description="Tên công cụ quét")
    rule_id: str = Field(..., description="Mã rule, ví dụ: cwe-89-sql-injection")
    cwe_id: str = Field(..., description="Mã CWE, ví dụ: CWE-89")
    severity: str = Field(..., description="Mức độ nghiêm trọng: ERROR / WARNING / INFO")
    file_path: str = Field(..., description="Đường dẫn tương đối tới file lỗi")
    start_line: int = Field(..., description="Dòng bắt đầu lỗi")
    end_line: int = Field(..., description="Dòng kết thúc lỗi")
    code_snippet: str = Field(..., description="Đoạn mã code bị nghi vấn")
    message: str = Field(..., description="Mô tả cảnh báo của Semgrep")

class ScannerOutput(BaseModel):
    repo_name: str
    commit_hash: str
    total_alerts: int
    alerts: List[RawAlert] = []

# ============================================================================
# 2. PHÚC XUẤT RA CHO LÂM DÙNG (KẾT QUẢ AI LỌC BÁO ẢO VÀ SINH BẢN VÁ)
# ============================================================================
class PatchResult(BaseModel):
    file_path: str
    cwe_id: str
    is_real_vulnerability: bool = Field(..., description="True = Lỗi thật, False = Báo ảo")
    confidence_score: float = Field(..., description="Độ tin cậy của AI (0.0 đến 1.0)")
    explanation: str = Field(..., description="Lập luận phân tích ngữ cảnh của AI")
    patch_diff: Optional[str] = Field(None, description="Đoạn code sửa dạng Git Diff (nếu là lỗi thật)")
    remediation_advice: Optional[str] = Field(None, description="Hướng dẫn phòng ngừa theo chuẩn OWASP")

class AgentRunOutput(BaseModel):
    commit_hash: str
    total_real_vulnerabilities: int
    total_false_positives: int
    results: List[PatchResult] = []
