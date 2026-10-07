# ⚙️ LÃNH THỔ CỦA LÂM (Data Pipeline, DevOps & Dashboard Lead)

Thư mục này dành riêng cho LÂM phát triển hạ tầng thu thập tự động và giao diện CTI Dashboard:
- `collectors/`: Bộ thu thập đa nguồn (Multi-Source Threat Collectors):
  * `rss_collector.py`: Tự động cào tin mới từ TheHackerNews, BleepingComputer, DarkReading.
  * `cisa_nvd_collector.py`: Tự động kéo cảnh báo khẩn cấp từ CISA KEV (Known Exploited Vulnerabilities) và NVD CVE.
  * `github_poc_collector.py`: Theo dõi các kho mã nguồn exploit mới đẩy lên GitHub.
- `server.py`: FastAPI server xử lý hàng đợi phân tích (Queue) và cung cấp REST API cho hệ thống.
- `dashboard/`: Giao diện Web Threat Intelligence Dashboard trực quan:
  * Bản đồ tương quan IOC (Graph Visualization).
  * Ma trận MITRE ATT&CK với các kỹ thuật được đánh dấu đỏ.
  * Nút xuất và tải về file Sigma Rules, YARA Rules và STIX 2.1 Bundle.
- `docker-compose.yml`: Đóng gói toàn bộ hệ thống chạy 1 lệnh là lên.

👉 **Quy ước:** 
- Thu thập dữ liệu thô $\rightarrow$ Đóng gói thành `RawThreatData` trong `shared.schemas` để kích hoạt Agent của Phúc.
- Nhận `ThreatIntelReport` từ Phúc & Khang để hiển thị lên Dashboard.
- Các thành viên khác chỉ gọi hàm trong thư mục này, không sửa file bên trong.
