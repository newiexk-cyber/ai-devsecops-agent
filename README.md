# 🛡️ CTI-SENTINEL: Hệ Thống AI Agent Phân Tích Tình Báo CTI & Sinh Kỹ Năng Phòng Thủ

> Đồ án Chuyên ngành (HUTECH — 23DATA1) | GVHD: ThS. Đinh Phương Nam
> Nhóm thực hiện: **Nguyễn Phi Phúc** (AI Core & Skill Synthesizer) • **Trần Minh Khang** (Enrichment & Benchmark) • **Nguyễn Nhật Lâm** (Collectors, API & Dashboard)

## 1. Luồng xử lý chính của hệ thống
1. **Thu thập bản tin CTI thật (`src/automation/collectors/`):** Kéo bài viết từ Cisco Talos, Palo Alto Unit 42, Securelist, Malwarebytes Labs, The Hacker News và CISA KEV / NIST NVD (có cache & khử trùng lặp URL).
2. **Hybrid Local Agent (`src/core/ioc_extractor.py`, `local_llm_client.py`, `cti_agent.py`):**
   - Regex trích xuất ứng viên IOC (`IP`, `DOMAIN`, `URL`, `MD5`, `SHA256`, `CVE`) kèm câu ngữ cảnh gốc.
   - Mô hình cục bộ **Ollama (`qwen2.5:3b`)** đọc đoạn trích bài báo để lọc nhiễu theo ngữ cảnh (domain báo chí/nạn nhân, version phần mềm, câu phủ định), xuất chuỗi giải trình XAI bám trích dẫn văn bản. Nếu Ollama offline sẽ tự động chuyển về `regex_fallback` minh bạch.
3. **Threat Enrichment (`src/security/enrichment_service.py`):** Đối chiếu VirusTotal v3, AbuseIPDB v2 (nếu cấu hình key) và nguồn mở Shodan InternetDB, MalwareBazaar, OpenPhish kèm bộ đệm SQLite. Không tự tạo điểm độc hại giả.
4. **Sinh Agent Skill & Kiểm chứng Sandbox (`src/core/skill_synthesizer.py`, `skill_verifier.py`):** Sinh hàm Python `execute_cti_defense_skill(telemetry)` + JSON Tool Schema (OpenAI, Claude, Gemini, LangChain), kiểm tra AST chặn hàm nguy hiểm, chạy `compile()` và kiểm thử mẫu dương tính / mẫu sạch trong sandbox (`SANDBOX_VERIFIED` / `DRY_RUN`).
5. **Bộ 50 bài CTI thật gán nhãn tay & Benchmark (`src/security/benchmark/`):** Tập 50 bài báo đầy đủ nội dung (`data/benchmark/cti_50_corpus.json`) cùng giao diện Web để nhóm tự đọc, xác nhận đáp án tay (`human_verified`) và đo Precision/Recall/F1 thực tế.

## 2. Cài đặt & Chạy trên máy Windows
1. Cài thư viện Python:
   ```bash
   pip install -r requirements.txt
   ```
2. Cài Ollama và lưu model sang ổ `D:` (nếu ổ `C:` ít dung lượng):
   ```powershell
   setx OLLAMA_MODELS "D:\ollama_models"
   ollama pull qwen2.5:3b
   ```
3. Khởi động Web Dashboard:
   ```bash
   python app.py
   ```
   Truy cập `http://127.0.0.1:8080`.
4. Chạy bộ kiểm thử đơn vị:
   ```bash
   python -m pytest tests/ -v
   ```

## 3. Tài liệu & Nhật ký tuần
- Đặc tả thiết kế kiến trúc mới: [`docs/superpowers/specs/2026-11-10-cti-local-agent-skills-design.md`](docs/superpowers/specs/2026-11-10-cti-local-agent-skills-design.md)
- Kế hoạch triển khai: [`docs/superpowers/plans/2026-11-10-cti-local-agent-skills-plan.md`](docs/superpowers/plans/2026-11-10-cti-local-agent-skills-plan.md)
- Nhật ký Tuần 1–4: xem thư mục [`docs/weekly_logs/`](docs/weekly_logs/)
