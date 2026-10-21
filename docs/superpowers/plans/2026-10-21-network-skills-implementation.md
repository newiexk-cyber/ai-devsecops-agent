# KẾ HOẠCH TRIỂN KHAI: NETWORK SENTINEL (CHUYÊN SÂU MẠNG & AGENT SKILLS)

- **Mục tiêu:** Chuyển đổi toàn diện hệ thống từ Rules tĩnh chung chung sang Tình báo An toàn Mạng & Kho Kỹ năng Tác tử (Agent Skills) có giải trình Explainable AI (XAI).
- **Phân công:**
  - Nguyễn Nhật Lâm: Network Ingestion, Smart Trigger, Database & FastApi REST Endpoints
  - Nguyễn Phi Phúc: Explainable AI Engine & Dynamic Agent Skills Generator
  - Trần Minh Khang: Timeline Aging (24h/30d/1y/3y), Multi-Tagging & ThreatFox C2 verification

---

## Các bước triển khai (TDD Workflow):

### Bước 1: Viết Unit Tests (`tests/test_network_skills.py`)
- Test 1: Lọc dữ liệu thuần mạng (Network CVEs, C2 IPs, Firmware Hashes)
- Test 2: Đánh giá bộ kích hoạt thông minh (Smart Crawl Trigger)
- Test 3: Phân loại Timeline Date (24h, 30d, 1y, 3y) & Gán thẻ (Tags)
- Test 4: Khởi tạo cấu trúc Explainable AI (XAI) và tính Trust Score
- Test 5: Sinh Dynamic Agent Skills chuẩn JSON-Schema (Tool Calling)

### Bước 2: Tạo Core Engine
- `src/core/network_cve_catalog.py`: Kho dữ liệu và logic phân loại Network CVEs, Active C2 IPs và Smart Triggers.
- `src/core/network_skill_generator.py`: Bộ máy Explainable AI (XAI) và Kỹ năng Agent (Virtual Patching, Containment, Active Exposure Probe, Traffic Triage).

### Bước 3: Cập nhật REST API (`src/automation/server.py`)
- `GET /api/network-intel/feeds`: Lọc theo timeline, tag và mức độ nghiêm trọng.
- `POST /api/network-intel/trigger-evaluation`: Trả về kết quả đánh giá "Khi nào nên cào".
- `POST /api/network-intel/generate-skill`: Sinh XAI Trust Card + Executable Agent Skill.
- `GET /api/network-intel/skills-library`: Danh mục các Kỹ năng sẵn sàng xuất cho Agent khác.

### Bước 4: Nâng cấp Giao diện Web Dashboard (`index.html`, `styles.css`, `app.js`)
- Thêm Tab ưu tiên: **🌐 Tình Báo Mạng & Kỹ Năng Tác Tử (Network Agent Hub)**.
- Thanh chọn Timeline Date trực quan (24h Đỏ rực, 30 ngày Cam, 1 năm Vàng, 3 năm Xanh).
- Trạng thái Smart Trigger: "Khi nào nên cào?" kèm đồng hồ đo độ khẩn cấp.
- Hiển thị Thẻ Tags phân màu rõ rệt (`#Cisco`, `#Fortinet`, `#VPN_Exploit`, `#AuthBypass`).
- Hộp XAI Trust Card (Chuỗi lập luận + Bằng chứng + Điểm tin cậy).
- Trình xem Agent Skill Schema (JSON Tool Definition + Python Action Code) kèm nút Copy & Export.

### Bước 5: Kiểm thử toàn diện & Bảng So sánh
- Chạy toàn bộ pytest suite đảm bảo pass 100%.
- Kiểm tra trực tiếp trên trình duyệt `http://127.0.0.1:8080`.
- Lập bảng so sánh chi tiết giữa Mô hình Cũ vs Mô hình Mới gửi cho người dùng.
