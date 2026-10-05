# 🛡️ LÃNH THỔ CỦA KHANG (Security & Benchmark Lead)

Thư mục này dành riêng cho KHANG phát triển Engine rà soát và Benchmark:
- `semgrep_runner.py`: Script gọi Semgrep CLI quét thư mục
- `rules/`: Bộ rule Semgrep bắt 4 nhóm lỗi cốt lõi (SQLi, XSS, Path Traversal, Secrets)
- `datasets/`: 50-100 mẫu code lỗi thực tế (lấy từ Vulncode-DB)
- `benchmark.py`: Script đo đạc Precision, Recall, Tỷ lệ giảm báo ảo (FPRR)

👉 **Quy ước:** 
- Quét xong bóc tách ra chuẩn `ScannerOutput` trong `shared.schemas` để gửi cho Phúc.
- Các thành viên khác chỉ gọi hàm trong thư mục này, không sửa file bên trong.
