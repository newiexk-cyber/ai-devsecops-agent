# -*- coding: utf-8 -*-
"""
GIAO ƯỚC DỮ LIỆU CHUNG (SHARED CTI SCHEMAS)
Nơi quy định cấu trúc dữ liệu Tình báo An ninh mạng (CTI) trao đổi giữa LÂM, KHANG và PHÚC.
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

# ============================================================================
# 1. LÂM XUẤT RA CHO PHÚC VÀ KHANG DÙNG (DỮ LIỆU THÔ THU THẬP TỪ ĐA NGUỒN)
# ============================================================================
class RawThreatData(BaseModel):
    source_id: str = Field(..., description="ID nguồn, ví dụ: bleepingcomputer-123")
    source_name: str = Field(..., description="Tên nguồn: TheHackerNews / CISA / BleepingComputer / GitHub")
    source_url: str = Field(..., description="Đường link bài báo cáo gốc")
    title: str = Field(..., description="Tiêu đề bài viết / báo cáo")
    raw_content: str = Field(..., description="Toàn bộ nội dung văn bản cần phân tích")
    published_date: Optional[str] = Field(None, description="Thời gian xuất bản")

# ============================================================================
# 2. PHÚC TRÍCH XUẤT IOC & ÁNH XẠ MITRE ATT&CK (BỘ NÃO AI AGENT)
# ============================================================================
class ExtractedIOC(BaseModel):
    ioc_type: str = Field(..., description="Loại IOC: IP | DOMAIN | URL | MD5 | SHA256 | CVE | APT_ACTOR")
    value: str = Field(..., description="Giá trị chỉ số: ví dụ 192.168.1.1, evil.com, CVE-2024-1234")
    context_sentence: str = Field(..., description="Câu văn bản chứa IOC trong bài viết")
    confidence: float = Field(default=0.9, description="Độ tin cậy của AI (0.0 đến 1.0)")

class MitreTechnique(BaseModel):
    technique_id: str = Field(..., description="Mã kỹ thuật: ví dụ T1059.001")
    technique_name: str = Field(..., description="Tên kỹ thuật: PowerShell")
    tactic: str = Field(..., description="Chiến thuật: ví dụ Execution, Initial Access")
    evidence: str = Field(..., description="Bằng chứng trích xuất từ văn bản")

# ============================================================================
# 3. KHANG LÀM GIÀU DỮ LIỆU (THREAT ENRICHMENT QUA VIRUSTOTAL / ABUSEIPDB)
# ============================================================================
class EnrichedIOC(BaseModel):
    ioc: ExtractedIOC
    is_malicious: bool = Field(..., description="True = Độc hại thực sự, False = An toàn / False Alarm")
    reputation_score: int = Field(default=0, description="Điểm đe dọa (0 - 100)")
    enrichment_source: str = Field(..., description="VirusTotal / AbuseIPDB / Shodan / OTX")
    raw_lookup_details: Dict[str, Any] = Field(default_factory=dict, description="Dữ liệu chi tiết từ API")

# ============================================================================
# 4. KẾT QUẢ CUỐI CÙNG: BÁO CÁO TÌNH BÁO & QUY TẮC PHÒNG THỦ (SIGMA / YARA)
# ============================================================================
class DefensiveRules(BaseModel):
    yara_rule: Optional[str] = Field(None, description="Quy tắc YARA để rà quét mã độc endpoint")
    sigma_rule: Optional[str] = Field(None, description="Quy tắc Sigma để cấu hình SIEM/WAF")
    firewall_blocklist: List[str] = Field(default_factory=list, description="Danh sách IP/Domain cần chặn khẩn cấp")

class ThreatIntelReport(BaseModel):
    report_id: str = Field(..., description="Mã báo cáo tình báo")
    title: str = Field(..., description="Tiêu đề chiến dịch tấn công")
    executive_summary: str = Field(..., description="Bản tóm tắt cho lãnh đạo do AI sinh")
    threat_actors: List[str] = Field(default_factory=list, description="Tên nhóm tin tặc nghi vấn (APT28, Lazarus...)")
    targeted_sectors: List[str] = Field(default_factory=list, description="Ngành nghề bị nhắm tới (Ngân hàng, Y tế, Chính phủ...)")
    enriched_iocs: List[EnrichedIOC] = Field(default_factory=list)
    mitre_attack_matrix: List[MitreTechnique] = Field(default_factory=list)
    defensive_rules: DefensiveRules
    stix_json: Optional[Dict[str, Any]] = Field(None, description="Gói dữ liệu chuẩn STIX 2.1 xuất ra")
