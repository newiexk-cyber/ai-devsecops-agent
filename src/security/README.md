# 🛡️ LÃNH THỔ CỦA KHANG (Threat Intel & Enrichment Lead)

Thư mục này dành riêng cho KHANG phát triển các Module làm giàu dữ liệu (Enrichment) và chuẩn hóa CTI:
- `enrichment_service.py`: Tích hợp các API Threat Intelligence bên thứ 3:
  * **VirusTotal API:** Kiểm tra danh tiếng mã hash, domain, IP.
  * **AbuseIPDB API:** Kiểm tra mức độ độc hại và điểm tự tin của IP.
  * **Shodan / AlienVault OTX API:** Tra cứu thông tin mở cổng và hạ tầng C2 của hacker.
- `stix_converter.py`: Chuẩn hóa dữ liệu IOC và kỹ thuật MITRE ATT&CK thành định dạng quốc tế **STIX 2.1 JSON** và MISP.
- `benchmark/`: Bộ dữ liệu 50 - 100 báo cáo APT thực tế (từ Mandiant, CISA, Kaspersky) có nhãn chuẩn để đo đạc độ chính xác bóc tách IOC (Precision, Recall, F1-Score).

👉 **Quy ước:** 
- Nhận `ExtractedIOC` từ Phúc $\rightarrow$ Gọi API làm giàu $\rightarrow$ Xuất ra `EnrichedIOC` trong `shared.schemas`.
- Các thành viên khác chỉ gọi hàm trong thư mục này, không sửa file bên trong.
