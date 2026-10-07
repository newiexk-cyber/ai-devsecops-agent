# 📊 BÁO CÁO THỰC NGHIỆM HỆ THỐNG AUTONOMOUS CTI AGENT (30 BÁO CÁO APT)

- **Bộ dữ liệu kiểm thử:** Autonomous CTI APT Benchmark Dataset (30 Real-World APT Scenarios)
- **Quy mô đánh giá:** 30 bài báo chiến dịch APT thực tế
- **Tổng số thực thể kiểm thử:** 180 IOCs (120 IOC độc hại thật + 60 IOC hợp pháp gây nhiễu)

## 1. Bảng so sánh Độ chính xác Trích xuất & Làm giàu IOC (Enrichment Benchmark)

| Chỉ số Đo đạc (Metrics) | Trích xuất Thô (Chưa qua VirusTotal/AbuseIPDB) | Qua Bộ Công Cụ Security của Khang (Tool 3 & 4) | Mức Cải Thiện |
| :--- | :---: | :---: | :---: |
| **True Positives (TP - Bắt đúng IOC độc hại)** | 120 / 120 | **120 / 120** | Giữ nguyên 100% IOC độc hại |
| **False Positives (FP - Chặn nhầm IP/Domain sạch)** | 60 | **0** | **Giảm 100.0% cảnh báo giả** |
| **True Negatives (TN - Lọc đúng IP/Domain hợp pháp)** | 0 | **60 / 60** | +60 IOC hợp pháp được bảo vệ |
| **Precision (Độ chính xác)** | 66.67% | **100.0%** | **+33.33%** |
| **Recall (Độ phủ phát hiện)** | 100.0% | **100.0%** | Duy trì 100.0% |
| **F1-Score** | 80.0% | **100.0%** | **+20.0%** |
| **Tỷ lệ xuất gói STIX 2.1 Hợp lệ (Tool 5)** | N/A | **30/30 (100%)** | Chuẩn OASIS STIX 2.1 |

## 2. Thống kê chi tiết theo từng loại Chỉ số Xâm nhập (IOC Type)

| Loại IOC | IOC Độc hại Bắt đúng (TP) | IOC Sạch Bị Bắt Nhầm Khi Chưa Lọc (FP) | IOC Sạch Được Tool 3 & 4 Lọc Bỏ (TN) | Độ Chính Xác Sau Khi Lọc |
| :--- | :---: | :---: | :---: | :---: |
| **IP** | 30 | 30 | 30 | **100.0%** |
| **DOMAIN** | 30 | 30 | 30 | **100.0%** |
| **SHA256** | 30 | 0 | 0 | **100.0%** |
| **CVE** | 30 | 0 | 0 | **100.0%** |
