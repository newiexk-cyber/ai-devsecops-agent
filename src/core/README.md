# 👑 LÃNH THỔ CỦA PHÚC (Trưởng nhóm - AI Core & CTI Reasoning Lead)

Thư mục này dành riêng cho PHÚC phát triển bộ não Multi-Agent phân tích Tình báo Mối đe dọa (CTI):
- `cti_agent_graph.py`: Đồ thị trạng thái LangGraph điều phối quy trình phân tích CTI.
- `prompts/`: Chứa các prompt chuyên dụng:
  * `ioc_extractor.txt`: Trích xuất thực thể IOC (IP, Domain, Hash, CVE, APT Actors) từ văn bản phi cấu trúc.
  * `mitre_mapper.txt`: Ánh xạ hành vi mô tả trong bài viết sang kỹ thuật ma trận MITRE ATT&CK.
  * `rule_generator.txt`: Tự động sinh mã quy tắc phòng thủ Sigma Rules và YARA Rules.
- `llm_reasoning.py`: Module kết nối mô hình ngôn ngữ lớn (DeepSeek / Qwen 2.5 / Claude 3.5).

👉 **Quy ước:** 
- Nhận input: `RawThreatData` từ `shared.schemas`
- Phối hợp với Khang để nhận `EnrichedIOC`
- Trả output: `ThreatIntelReport` sang `shared.schemas`
- Các thành viên khác chỉ gọi hàm trong thư mục này, không sửa file bên trong.
