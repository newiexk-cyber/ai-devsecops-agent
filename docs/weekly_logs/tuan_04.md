# Nhật ký Tuần 04 — Chốt đúng đề tài CTI + Sinh Skill, chạy Local LLM & dựng tập 50 bài gán nhãn tay

- **Thời gian:** 02/11/2026 – 10/11/2026
- **Nhánh Git liên quan:** `feat/cti-local-agent-skills`
- **GVHD góp ý & định hướng nhóm chốt:**
  - Bỏ hoàn toàn phần SAST (`sast_analyzer.py`) và khung Network Sentinel bó hẹp vào 8 CVE cứng (`network_cve_catalog.py`), đưa hệ thống về đúng bài toán **CTI đọc bản tin thực tế -> trích IOC -> giải trình XAI -> sinh Agent Skill**.
  - Không dùng bộ dataset ghép câu tự động ở nhánh `feat/khang-dev`; nhóm phải thu thập khoảng **50 bài báo CTI thật**, tự đọc và gán nhãn tay (`IP`, `Domain`, `MD5`, `SHA256`, `CVE`...) làm đáp án chuẩn rồi cho Agent (dùng mô hình cục bộ) đọc lại để đo độ chính xác thực tế.
  - Phần kỹ năng phòng thủ sinh ra phải đo được tỷ lệ hợp lệ cú pháp và khả năng bắt mẫu thử thật trong sandbox.

## 1. Công việc từng thành viên trong tuần
- **Nguyễn Nhật Lâm (`src/automation/`, hạ tầng máy & Dashboard):**
  - Cài **Ollama 0.40.16** trên Windows với `OLLAMA_MODELS=D:\ollama_models` (do ổ `C:` chỉ còn ~13GB trống), kéo model `qwen2.5:3b` (~1.9GB) phù hợp CPU `Intel i5-1135G7 / 16GB RAM`.
  - Xử lý lỗi mạng IPv6 làm `ollama pull` treo khi tải blob từ Cloudflare R2 bằng cách dựng local IPv4 CONNECT proxy tạm thời trong lúc tải model.
  - Cập nhật `rss_collector.py` (lấy thêm Cisco Talos, Palo Alto Unit 42, Kaspersky Securelist, Malwarebytes Labs), dọn route SAST khỏi `server.py`, và thiết kế lại 4 tab Dashboard kèm giao diện **Đọc & Gán Nhãn 50 Bài + Bảng Benchmark Agent**.
- **Nguyễn Phi Phúc (`src/core/`):**
  - Viết `local_llm_client.py` kết nối `127.0.0.1:11434/api/chat` và bóc JSON an toàn; nếu Ollama tắt sẽ tự rơi về `regex_fallback` minh bạch.
  - Xây dựng Hybrid Agent (`cti_agent.py`): `ioc_extractor.py` quét ứng viên kèm câu ngữ cảnh (lọc sơ chuỗi version như `11.2.3.4`), sau đó `qwen2.5:3b` đọc đoạn văn bản rút gọn để loại các domain báo chí/nạn nhân gây nhiễu (`dropped_iocs`), giữ kiểm tra Grounding chống AI bịa IOC.
  - Viết `skill_synthesizer.py` & `skill_verifier.py`: sinh hàm Python `execute_cti_defense_skill(telemetry)` + schema OpenAI/Claude/Gemini/LangChain từ chính IOC trích ra, kiểm tra `ast.parse()` chặn `eval`/`exec`/`subprocess`, chạy thử mẫu dương tính & mẫu sạch trong sandbox cô lập để đo `SANDBOX_VERIFIED`.
- **Trần Minh Khang (`src/security/`):**
  - Hợp nhất phần enrichment thật không cần key (Shodan InternetDB, Abuse.ch MalwareBazaar, OpenPhish) vào `enrichment_service.py` mà vẫn giữ nguyên tắc không tự bịa điểm giả khi thiếu dữ liệu.
  - Viết `corpus_manager.py` thu thập đủ **50 bài báo CTI thật** đầy đủ nội dung (trung bình >10.000 ký tự/bài, lưu tại `data/benchmark/cti_50_corpus.json`) và `evaluator.py` tính `TP/FP/FN/Precision/Recall/F1` so sánh giữa `regex_only` và `hybrid` kèm phân tích lỗi từng bài.

## 2. Khó khăn thực tế gặp phải & Cách giải quyết
- **Chạy model 3B trên CPU khá chậm (~60s/bài nếu prompt dài):** Khi để LLM in lại toàn bộ danh sách IOC (nhất là chuỗi SHA256 64 ký tự), output bị vượt giới hạn `num_predict` và lỗi parse JSON. Nhóm đổi sang schema gọn nhẹ **chỉ yêu cầu LLM liệt kê những ứng viên bị loại (`dropped_iocs`)**, rút gọn đoạn trích còn 1.800 ký tự ưu tiên đoạn chứa IOC và giữ prompt cache trên Ollama; kết quả thời gian xử lý 1 bài giảm xuống ngưỡng chạy được ổn định trên CPU laptop.
- **LLM trả trường `type` dạng chuỗi mẫu ghép (`"IP|DOMAIN|..."`):** Đã thêm bước chuẩn hóa ánh xạ ngược lại đúng loại IOC từ `regex_map` trước khi lọc.
- **Một số trang tin (BleepingComputer, SecurityWeek) chặn 403 khi cào HTML:** Chuyển nguồn chính sang các feed cho phép đọc đầy đủ nội dung như Cisco Talos, Palo Alto Unit 42, Securelist và Malwarebytes Labs để nhóm có bài viết hoàn chỉnh phục vụ gán nhãn tay.

## 3. Kế hoạch tuần tiếp theo
- Cả 3 thành viên chia nhau đọc kỹ toàn bộ 50 bài trong `cti_50_corpus.json` (mỗi người ~17 bài) qua tab Dashboard hoặc CSV, tự kiểm tra xóa nhiễu và chốt nhãn `human_verified`.
- Chạy Benchmark chính thức trên đủ 50 bài đã gán tay (`regex_only` vs `hybrid` với `qwen2.5:3b`), phân tích những ca Agent còn bắt nhầm/bỏ sót để tinh chỉnh prompt và bộ quy tắc lọc ngữ cảnh.
