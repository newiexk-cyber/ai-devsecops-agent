# ANTIGRAVITY WORKSPACE RULES - AI DEVSECOPS MULTI-AGENT

Hệ thống AI Agent hỗ trợ rà soát lỗ hổng mã nguồn (SAST), lọc cảnh báo ảo và tự động tạo Pull Request vá lỗi (DevSecOps).

## 1. CƠ CHẾ NHẬN DIỆN DANH TÍNH TỰ ĐỘNG (IDENTITY RECOGNITION):
- Khi bắt đầu một phiên làm việc, Agent hãy TỰ ĐỘNG ĐỌC file `.agents/identity.txt` để biết người đang thao tác là ai:
  * Nếu file ghi `phuc`: Người dùng là **👑 PHÚC (Trưởng nhóm - AI Core)**.
  * Nếu file ghi `khang`: Người dùng là **🛡️ KHANG (Security & Benchmark)**.
  * Nếu file ghi `lam`: Người dùng là **⚙️ LÂM (DevOps & Git Bot)**.
- Tuyệt đối không yêu cầu người dùng phải tự giới thiệu lại nếu đã có file `identity.txt`.

## 2. PHÂN QUYỀN LÃNH THỔ BẤT KHẢ XÂM PHẠM (TERRITORY GUARD):
- **PHÚC** sở hữu độc quyền: `src/core/`
- **KHANG** sở hữu độc quyền: `src/security/`
- **LÂM** sở hữu độc quyền: `src/automation/`
- **Quy tắc chặn tự động:** Khi nhận lệnh sửa file, Agent PHẢI kiểm tra file đó có nằm trong thư mục của người dùng hiện tại không. NẾU KHÔNG: Lập tức từ chối và cảnh báo người dùng: *"File này thuộc quyền sở hữu của [Tên bạn]. Tôi không được phép chỉnh sửa trực tiếp. Hãy liên hệ với [Tên bạn] hoặc gọi qua hàm Interface trong shared/schemas.py!"*

## 3. QUY TRÌNH TỰ ĐỘNG ĐỒNG BỘ GIT (AUTO-SYNC AGENT):
1. **Tự động Kéo (Auto-Pull):** Trước khi bắt đầu viết tính năng mới, Agent hãy tự động chạy lệnh `git pull origin main --rebase` ngầm để đảm bảo mã nguồn luôn mới nhất.
2. **Tự động Đẩy (Auto-Push):** Sau khi hoàn thành code và kiểm tra chạy tốt, Agent hãy chủ động thông báo: *"Tôi đã hoàn thành mã nguồn trong thư mục của bạn. Bạn có muốn tôi tự động commit và đẩy lên nhánh `feat/[tên]-dev` trên GitHub ngay không?"*

## 4. GIAO ƯỚC DỮ LIỆU CHUNG (SHARED INTERFACE):
- Mọi dữ liệu trao đổi giữa các thành viên BẮT BUỘC tuân thủ theo các Model định nghĩa trong `shared/schemas.py`.
- Khi cần dùng kết quả của bạn mình, chỉ được ĐỌC (Read-only) và `import` hàm, TUYỆT ĐỐI không sửa logic bên trong file của bạn.
