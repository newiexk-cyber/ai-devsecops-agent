# Nhật ký Tuần 01 — Khảo sát đề tài CTI, dựng repo & chia module nhóm

- **Thời gian:** 06/10/2026 – 12/10/2026
- **Nhánh Git liên quan:** `main`, `feat/phuc-dev`, `feat/khang-dev`
- **GVHD:** ThS. Đinh Phương Nam

## 1. Công việc nhóm đã làm
- Đọc tài liệu về quy trình Cyber Threat Intelligence (CTI), chuẩn mô tả thực thể STIX 2.1 và ma trận kỹ thuật MITRE ATT&CK.
- Chốt đề cương đồ án (`docs/DeCuong_DeTai_HoanThien.docx`, `docs/TAI_LIEU_TONG_HOP_DACN_CTI.docx`) và tạo kho mã nguồn `ai-devsecops-agent` trên GitHub.
- Chia ranh giới thư mục làm việc cho 3 máy để tránh xung đột khi đẩy code (`sync.py`, `.agents/rules/territory-guard.md`):
  - **Nguyễn Phi Phúc (`src/core/`):** Khởi tạo khung xử lý AI Agent (`langgraph_graph.py`, `llm_client.py` ở mức khung ban đầu chờ gắn model thật) và định nghĩa giao ước dữ liệu trong `shared/schemas.py`.
  - **Trần Minh Khang (`src/security/`):** Nghiên cứu API kiểm tra danh tiếng IOC (VirusTotal API v3, AbuseIPDB v2, Shodan InternetDB, OpenPhish, MalwareBazaar) và bộ đệm SQLite để đỡ tốn quota API miễn phí.
  - **Nguyễn Nhật Lâm (`src/automation/`):** Thiết kế cấu trúc thu thập tin tức OSINT (RSS, CISA KEV), bảng SQLite lưu bài viết và chuẩn bị khung FastAPI.

## 2. Kết quả & Tồn đọng cuối tuần
- Đã có đề cương, `shared/schemas.py` (`RawThreatData`, `ExtractedIOC`, `EnrichedIOC`, `MitreTechnique`, `ThreatIntelReport`) và môi trường Python chạy được test cơ bản.
- Tồn đọng: Phần gọi LLM trong `feat/phuc-dev` mới là hàm khung (`NotImplementedError`), chưa nối được với mô hình thật; dữ liệu bài báo vẫn đang ở bước thử nghiệm rời rạc từng máy.
