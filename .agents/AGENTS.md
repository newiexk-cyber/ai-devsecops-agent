# ANTIGRAVITY WORKSPACE RULES - AUTONOMOUS CTI AI AGENT

Hệ thống Multi-Agent AI tự chủ thu thập, trích xuất IOCs, làm giàu dữ liệu và sinh báo cáo Tình báo An ninh mạng (Cyber Threat Intelligence - CTI).

## 1. CƠ CHẾ NHẬN DIỆN DANH TÍNH TỰ ĐỘNG (IDENTITY RECOGNITION):
- Khi bắt đầu một phiên làm việc, Agent hãy TỰ ĐỘNG ĐỌC file `.agents/identity.txt` để biết người đang thao tác là ai:
  * Nếu file ghi `phuc`: Người dùng là **👑 PHÚC (Trưởng nhóm - AI Core & CTI Reasoning)**.
  * Nếu file ghi `khang`: Người dùng là **🛡️ KHANG (Threat Intel & Enrichment Lead)**.
  * Nếu file ghi `lam`: Người dùng là **⚙️ LÂM (Data Pipeline, DevOps & Dashboard Lead)**.
- Tuyệt đối không yêu cầu người dùng phải tự giới thiệu lại nếu đã có file `identity.txt`.

## 2. PHÂN QUYỀN LÃNH THỔ BẤT KHẢ XÂM PHẠM (TERRITORY GUARD):
- **PHÚC** sở hữu độc quyền: `src/core/` (Multi-Agent LangGraph, Prompt IOC Extractor, MITRE ATT&CK Mapper, Rule Generator sinh YARA/Sigma).
- **KHANG** sở hữu độc quyền: `src/security/` (Tích hợp API VirusTotal, AbuseIPDB, Shodan, chuẩn hóa STIX 2.1/MISP, bộ Dataset báo cáo APT để Benchmark).
- **LÂM** sở hữu độc quyền: `src/automation/` (Engine tự động cào dữ liệu đa nguồn RSS/GitHub/NVD, FastAPI Backend, Threat Intel Dashboard, Docker).
- **Quy tắc chặn tự động:** Khi nhận lệnh sửa file, Agent PHẢI kiểm tra file đó có nằm trong thư mục của người dùng hiện tại không. NẾU KHÔNG: Lập tức từ chối và cảnh báo người dùng.

## 3. QUY TRÌNH TỰ ĐỘNG ĐỒNG BỘ GIT (AUTO-SYNC AGENT):
1. **Tự động Kéo (Auto-Pull):** Trước khi bắt đầu viết tính năng mới, Agent hãy tự động chạy lệnh `git pull origin main --rebase` ngầm để đảm bảo mã nguồn luôn mới nhất.
2. **Tự động Đẩy (Auto-Push):** Sau khi hoàn thành code và kiểm tra chạy tốt, Agent hãy chủ động thông báo: *"Tôi đã hoàn thành mã nguồn trong thư mục của bạn. Bạn có muốn tôi tự động commit và đẩy lên nhánh `feat/[tên]-dev` trên GitHub ngay không?"*

## 4. GIAO ƯỚC DỮ LIỆU CHUNG (SHARED INTERFACE):
- Mọi dữ liệu trao đổi giữa các thành viên BẮT BUỘC tuân thủ theo các Model định nghĩa trong `shared/schemas.py`.
- Khi cần dùng kết quả của bạn mình, chỉ được ĐỌC (Read-only) và `import` hàm, TUYỆT ĐỐI không sửa logic bên trong file của bạn.
