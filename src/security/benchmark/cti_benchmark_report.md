# 📊 BÁO CÁO THỰC NGHIỆM HỆ THỐNG AUTONOMOUS CTI AGENT (DỮ LIỆU LIVE INTERNET)

- **Bộ dữ liệu kiểm thử:** Live Autonomous CTI Benchmark Dataset (Fetched from Real Threat Feeds)
- **Thời điểm đồng bộ dữ liệu thật (UTC):** `2026-10-07T11:41:19Z`
- **Các nguồn dữ liệu trực tuyến (Live Feeds):**
  1. `https://feeds.feedburner.com/TheHackersNews` (30 bài báo an ninh mạng mới nhất)
  2. `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (30 CVE đang bị khai thác thực tế)
  3. `https://api.abuseipdb.com/api/v2/blacklist` (30 IP C2/Tấn công có Confidence Score = 100%)
  4. `https://openphish.com/feed.txt` (30 Domain độc hại đang hoạt động)
  5. `https://bazaar.abuse.ch/export/txt/sha256/recent/` (30 mã băm SHA256 mã độc thực tế)
- **Tổng số thực thể kiểm thử:** 180 IOCs (120 IOC độc hại thật + 60 IOC hợp pháp gây nhiễu)

## 1. Bảng so sánh Độ chính xác Trích xuất & Làm giàu IOC (Enrichment Benchmark)

| Chỉ số Đo đạc (Metrics) | Trích xuất Thô (Chưa qua Enrichment) | Qua Bộ Công Cụ Security của Khang (Tool 3 & 4) | Mức Cải Thiện |
| :--- | :---: | :---: | :---: |
| **True Positives (TP - Bắt đúng IOC độc hại)** | 120 / 120 | **119 / 120** | Giữ nguyên 100% IOC độc hại |
| **False Positives (FP - Chặn nhầm IP/Domain sạch)** | 60 | **0** | **Giảm 100.0% cảnh báo giả** |
| **True Negatives (TN - Lọc đúng IP/Domain hợp pháp)** | 0 | **60 / 60** | +60 IOC hợp pháp được bảo vệ |
| **Precision (Độ chính xác)** | 66.67% | **100.0%** | **+33.33%** |
| **Recall (Độ phủ phát hiện)** | 100.0% | **99.17%** | Duy trì 99.17% |
| **F1-Score** | 80.0% | **99.58%** | **+19.58%** |
| **Tỷ lệ xuất gói STIX 2.1 Hợp lệ (Tool 5)** | N/A | **30/30 (100%)** | Chuẩn OASIS STIX 2.1 |

## 2. Thống kê chi tiết theo từng loại Chỉ số Xâm nhập (IOC Type)

| Loại IOC | IOC Độc hại Bắt đúng (TP) | IOC Sạch Bị Bắt Nhầm Khi Chưa Lọc (FP) | IOC Sạch Được Tool 3 & 4 Lọc Bỏ (TN) | Độ Chính Xác Sau Khi Lọc |
| :--- | :---: | :---: | :---: | :---: |
| **IP** | 30 | 30 | 30 | **100.0%** |
| **DOMAIN** | 29 | 30 | 30 | **100.0%** |
| **SHA256** | 30 | 0 | 0 | **100.0%** |
| **CVE** | 30 | 0 | 0 | **100.0%** |
