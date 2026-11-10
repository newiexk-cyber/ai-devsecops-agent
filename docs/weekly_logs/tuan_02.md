# Nhật ký Tuần 02 — Thu thập dữ liệu sống (RSS / CISA KEV), Enrichment & Dashboard bản đầu

- **Thời gian:** 13/10/2026 – 19/10/2026
- **Nhánh Git liên quan:** `main` (`48defcc` -> `9f83981`), `feat/khang-dev` (`524e61c`)

## 1. Nội dung thực hiện theo từng thành viên
- **Nguyễn Nhật Lâm (`src/automation/`):**
  - Viết `rss_collector.py` và `cisa_collector.py` kéo tin từ The Hacker News, BleepingComputer và CISA KEV Catalog vào SQLite (`database.py`, khử trùng URL bằng MD5 `url_hash`).
  - Dựng REST API bằng FastAPI (`server.py` chạy cổng `8080` để tránh đụng socket trên Windows) và giao diện Web Dashboard (`dashboard/index.html`, `app.js`, `styles.css`).
  - Trong tuần có thử nghiệm thêm phần quét code `sast_analyzer.py` và định hướng `network_cve_catalog.py`, nhưng nhận ra bị lan man sang thiết bị mạng cứng và quét mã nguồn, làm loãng đề tài CTI ban đầu.
- **Trần Minh Khang (`src/security/`):**
  - Đẩy nhánh `feat/khang-dev` với `enrichment_service.py`, `stix_converter.py` và thử nghiệm script đo 30 mẫu (`apt_dataset_builder.py`, `cti_benchmark.py`).
  - Tự nhận thấy hạn chế lớn: script `apt_dataset_builder.py` lúc đó ghép đoạn văn bản C2/hash từ feed khác vào tóm tắt RSS nên bộ 30 mẫu ra kết quả 100% giả tạo, không phản ánh đúng độ khó của bài báo thật.
- **Nguyễn Phi Phúc (`src/core/`):**
  - Viết bộ trích xuất IOC bằng Regex (`ioc_extractor.py`) kèm khử defang (`hxxp`, `[.]`), ánh xạ MITRE ATT&CK (`mitre_mapper.py`) và bản thử sinh Skill (`network_skill_generator.py`).

## 2. Vấn đề phát sinh
- Web còn hay báo timeout khi bấm cào nhiều lần vì chưa có cache CISA KEV, các bài cào về bị lặp nhiều bản ghi trong RAM.
- Chưa có mô hình ngôn ngữ chạy thật để đọc ngữ cảnh bài báo; Regex gặp chuỗi version hoặc domain tham chiếu vẫn bắt nhầm khá nhiều.
