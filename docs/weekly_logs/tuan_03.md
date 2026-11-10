# Nhật ký Tuần 03 — Rà soát bảo mật mã nguồn, vá lỗi trùng bài & tối ưu Crawler

- **Thời gian:** 20/10/2026 – 28/10/2026
- **Nhánh Git liên quan:** `fix/security-audit-remediation` (`14ea026` -> `aa63062`)

## 1. Các lỗi nghiêm trọng phát hiện khi kiểm tra kỹ repo
Khi rà soát toàn bộ codebase tại `9f83981`, nhóm phát hiện các điểm không đạt an toàn để demo hay đưa vào dùng thực tế:
1. **Dữ liệu tình báo giả khi thiếu API Key:** `enrichment_service.py` từng tự gán điểm `85–98` và `is_malicious=True` khi chưa có key VirusTotal/AbuseIPDB.
2. **Xác thực CVE lỏng lẻo:** Chuỗi không phải CVE (vd `CVE-HELLO`) vẫn có thể tạo advisory fallback.
3. **Nguy cơ Code Injection & trạng thái giả trong Skill:** Chuỗi threat chưa escape được ghép thẳng f-string vào Python code sinh ra, đồng thời code chỉ in log mô phỏng nhưng lại gán nhãn `ENFORCED`.
4. **Trùng lặp bài & nghẽn mạng:** Mỗi lần bấm cào lại trên web thì catalog bị chèn trùng lên 60+ thẻ giống nhau; hàm `fetch_cve_by_id` tải lại file JSON CISA KEV ~2MB lặp đi lặp lại 35 lần gây `ReadTimeout`.

## 2. Kết quả đã xử lý (`aa63062`)
- **Enrichment:** Khi thiếu API key hoặc provider không có dữ liệu, bắt buộc trả `verdict="unknown"`, `is_verified=False`, `confidence=0` (chỉ mô phỏng nếu tự bật `DEMO_MODE=true`).
- **Validation & Security:** Kiểm tra chặt CVE theo regex `^CVE-\d{4}-\d{4,}$`, kiểm tra `compile()` trước khi trả code Skill, gắn trạng thái `DRY_RUN`, sửa `sync.py` bỏ `shell=True`, thêm SQLite PRAGMA `WAL` / `foreign_keys=ON` / `busy_timeout=5000`, thêm `escapeHtml` trên frontend.
- **Crawler Cache & Deduplication:** Thêm `get_cached_cisa_kev_data()` TTL 15 phút (giảm thời gian cào từ >40s xuống ~1s) và lọc trùng 3 lớp từ catalog tới giao diện.
- **Kiểm thử:** Toàn bộ 26 ca test trong `tests/` chạy pass.
