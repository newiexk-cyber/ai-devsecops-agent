# Kế Hoạch Triển Khai: Hệ Thống CTI Local Agent Trích Xuất IOC, Sinh Skill & Benchmark 50 Bài Gán Nhãn Tay

> **Mục tiêu:** Chuyển đổi nhánh `feat/cti-local-agent-skills` thành hệ thống CTI thuần (bỏ SAST và khung Network Sentinel hardcoded), kết hợp mô hình cục bộ Ollama (`qwen2.5:3b` lưu trên `D:\ollama_models`) để đọc bản tin, lọc nhiễu IOC, giải trình XAI bám dẫn chứng, sinh Agent Skill kiểm chứng AST + Sandbox, kèm bộ 50 bài CTI thật để nhóm tự gán nhãn tay và đo Precision/Recall/F1 thực tế.

---

## Bước 1: Hạ tầng Mô hình Cục bộ (Ollama trên ổ `D:\`) & Dọn dẹp Git
1.1. Cài đặt Ollama (`Ollama.Ollama`), đặt `OLLAMA_MODELS=D:\ollama_models` (cấp User + process), kiểm tra `ollama --version` và kéo model `qwen2.5:3b`.
1.2. Cập nhật `.gitignore` bỏ qua các file dữ liệu runtime, `.docx` rác ngoài lề (`Bao_Cao_Do_An_SFSA_RS_HUTECH.docx`), và file backup tạm.
1.3. Xóa bỏ hoàn toàn SAST (`src/core/sast_analyzer.py`, `tests/test_sast_analyzer.py`) và khung Network Sentinel hardcoded (`src/core/network_cve_catalog.py`, `src/core/network_skill_generator.py`, `tests/test_network_skills.py` sẽ được thay thế bằng bộ test CTI Agent & Skill Synthesizer).
1.4. Cập nhật `.agents/rules/territory-guard.md` cho phép đồng bộ trên nhánh tích hợp `feat/cti-local-agent-skills`.

## Bước 2 (TDD): `src/core/local_llm_client.py` — Kết nối Ollama Cục bộ & Parse JSON An toàn
- **Test trước (`tests/test_local_llm_client.py`):**
  - Test `check_ollama_health()` khi Ollama khả dụng và khi mất kết nối -> trả về dict chuẩn (`online: bool`, `model`, `error`).
  - Test `extract_json_payload()` xử lý output có markdown fence ```` ```json ... ``` ```` hoặc text bao quanh.
  - Test `OllamaClient.chat_json()` khi API timeout / HTTP lỗi -> raise/trả fallback có cấu trúc, không crash.
- **Implement:** Viết `src/core/local_llm_client.py` dùng `httpx`, đọc `OLLAMA_BASE_URL` (mặc định `http://127.0.0.1:11434`), `OLLAMA_MODEL` (mặc định `qwen2.5:3b`).
- **Verify:** Chạy `python -m pytest tests/test_local_llm_client.py -v`.

## Bước 3 (TDD): `src/core/ioc_extractor.py` + `src/core/cti_agent.py` — Trích xuất Regex Kèm Ngữ cảnh & Agent Lọc Nhiễu
- **Test trước (`tests/test_cti_agent.py`):**
  - Test `ioc_extractor.extract_iocs_with_context()`: trích xuất đầy đủ `IP`, `DOMAIN`, `URL`, `MD5`, `SHA256`, `CVE`, khử defang (`hxxp`, `[.]`, `(.)`, `[dot]`), giữ nguyên câu gốc `context_sentence` quanh mỗi IOC và lọc cơ bản version string (`v1.2.3.4`).
  - Test `cti_agent.analyze_cti_article(..., mode="hybrid")` với mocked Local LLM trả JSON lọc bỏ domain tham chiếu/báo chí và giữ lại IOC độc hại thật + chuỗi XAI trích dẫn câu trong bài.
  - Test `cti_agent.analyze_cti_article()` khi Ollama offline -> tự động rơi về `analysis_mode="regex_fallback"` một cách minh bạch (không giả vờ LLM đã phân tích).
- **Implement:**
  - Bổ sung URL extractor + `context_sentence` extraction vào `src/core/ioc_extractor.py`.
  - Tạo `src/core/cti_agent.py` tích hợp `ioc_extractor`, `local_llm_client`, `mitre_mapper` để đọc hiểu bài báo và xuất báo cáo có trường `analysis_mode`, `agent_decisions` (giữ/loại IOC + lý do), `xai_report` (reasoning chain bám dẫn chứng + citations).
- **Verify:** Chạy `python -m pytest tests/test_cti_agent.py -v`.

## Bước 4 (TDD): `src/security/enrichment_service.py` — Hợp nhất Nguồn Mở Thật & Không Dữ Liệu Giả
- **Test trước (`tests/test_enrichment_real_sources.py`):**
  - Giữ toàn bộ test P0 (`test_enrichment_does_not_fabricate_fake_scores`): khi thiếu key & nguồn mở không có -> trả `unknown`, `is_verified=False`.
  - Test enrichment với Shodan InternetDB / MalwareBazaar / OpenPhish cache lookup (không đọc ground truth, không trả điểm giả).
- **Implement:** Giữ chuẩn `enrich_ioc(ioc_type, ioc_value)` + SQLite cache ở `database.py`, bổ sung kiểm tra đối chiếu nguồn mở không cần key (Shodan InternetDB IP ports/vulns, OpenPhish domain list, MalwareBazaar recent SHA256 list) khi có mạng và bỏ qua an toàn khi offline.
- **Verify:** Chạy `python -m pytest tests/test_enrichment_real_sources.py tests/test_security_audit_fixes.py -v`.

## Bước 5 (TDD): `src/core/skill_synthesizer.py` & `src/core/skill_verifier.py` — Sinh Agent Skill Động & Kiểm chứng AST + Sandbox
- **Test trước (`tests/test_skill_synthesizer.py`):**
  - Test sinh Skill từ báo cáo CTI có cả `SHA256`, `IP`, `DOMAIN`, `CVE` -> chứa đủ OpenAI, Anthropic Claude, Google Gemini, LangChain schemas + code Python `execute_cti_defense_skill(telemetry: dict)`.
  - Test trường hợp không có IOC thực thi -> thông báo rõ thay vì chèn IP giả (`127.0.0.1` / `malicious.example`).
  - Test `verify_skill_code()` từ chối code chứa `os.system`, `subprocess`, `eval`, `exec`, `open(..., 'w')` (AST Security Guard).
  - Test `run_skill_sandbox_verification()`:
    - Cho mẫu thử dương tính (event giả lập chứa IP/Domain/Hash của bài báo) -> trả `positive_probe_matched=True`.
    - Cho mẫu thử âm tính (event sạch `8.8.8.8`, `google.com`, hash vô hại) -> trả `negative_probe_clean=True` (`matched=False`).
    - Trạng thái luôn là `SANDBOX_VERIFIED` hoặc `DRY_RUN`, không bao giờ `ENFORCED`.
- **Implement:** Tạo `src/core/skill_synthesizer.py` và `src/core/skill_verifier.py`.
- **Verify:** Chạy `python -m pytest tests/test_skill_synthesizer.py -v`.

## Bước 6 (TDD): Bộ 50 Bài CTI Thật, Giao Diện/API Gán Nhãn Tay & Bộ Chấm Điểm Agent (`src/security/benchmark/`)
- **Test trước (`tests/test_benchmark_evaluator.py`):**
  - Test `evaluate_dataset()` tính chính xác `TP`, `FP`, `FN`, `Precision`, `Recall`, `F1-Score` theo từng loại IOC (`IP`, `DOMAIN`, `MD5`, `SHA256`, `CVE`) và tổng thể.
  - Test evaluator **chỉ chấm trên các bài có `annotation_meta.status == "human_verified"`** (bỏ qua bài `pending_human_review`) và thống kê lỗi cụ thể (`false_positives`, `false_negatives`).
  - Test đánh giá Skill trên các bài đó: `syntax_valid_rate` và `sandbox_match_rate`.
- **Implement:**
  - `src/security/benchmark/corpus_manager.py`: Quản lý đọc/ghi `data/benchmark/cti_50_corpus.json`, cập nhật nhãn gán tay (`update_human_annotation`), thu thập full-text 50 bài CTI thật (`collect_real_cti_corpus`), xuất CSV cho nhóm đối chiếu.
  - `src/security/benchmark/evaluator.py`: Chạy so sánh song song `regex_only` vs `hybrid_local_llm` trên tập đã duyệt tay, kiểm chứng Skill AST + Sandbox trên từng bài, xuất báo cáo JSON + Markdown (`data/benchmark/latest_benchmark_report.md`).
- **Chạy thực tế thu thập 50 bài:** Chạy script kéo đủ **50 bài CTI thật** lưu vào `data/benchmark/cti_50_corpus.json` (tình trạng ban đầu: `pending_human_review`, kèm 1 lô mẫu đầu tiên nhóm có thể rà soát ngay trong buổi kiểm thử).

## Bước 7: FastAPI Backend & Unified Dashboard (`src/automation/server.py`, `src/automation/dashboard/`)
- Cập nhật `src/automation/server.py`:
  - Gỡ bỏ hoàn toàn `/api/sast/*` và `/api/network-intel/*` hardcoded.
  - Cập nhật `/api/analyze` dùng `cti_agent` (Local LLM + Regex) + `enrichment_service` + `skill_synthesizer` + `skill_verifier`.
  - Thêm các API mới:
    - `GET /api/llm/status` (kiểm tra Ollama đang chạy & model sẵn sàng).
    - `POST /api/skills/verify` (kiểm tra AST + chạy thử mẫu Positive/Negative trong sandbox).
    - `GET /api/corpus` & `POST /api/corpus/{article_id}/annotate` (đọc & lưu đáp án gán nhãn tay từ thành viên).
    - `POST /api/benchmark/run` & `GET /api/benchmark/latest` (chạy đối chiếu Regex Baseline vs Local LLM Agent + thống kê Skill Syntax/Match).
- Thiết kế lại Web Dashboard (`index.html`, `app.js`, `styles.css`) sạch sẽ, tiếng Việt chuẩn:
  - **Tab 1 — Tin Tình Báo & Phân Tích Agent (XAI):** Cào RSS/CISA KEV, dán bài tự chọn hoặc chọn bài đã cào -> bấm **"Phân Tích Bằng Local Agent"** -> xem IOC đã lọc, trạng thái Enrichment thật, XAI Reasoning Chain kèm dẫn chứng.
  - **Tab 2 — Studio Sinh Kỹ Năng Agent (Skills):** Xem mã Python thực thi + Schema (OpenAI, Claude, Gemini, LangChain) + bấm **"Chạy Sandbox Kiểm Chứng (AST + Mẫu Thử)"** xem kết quả bắt mẫu dương tính / né mẫu sạch.
  - **Tab 3 — Gán Nhãn 50 Bài & Đo Độ Chính Xác Agent:** Đọc nguyên văn từng bài trong 50 bài -> gán/sửa đáp án tay (`IP`, `Domain`, `MD5`, `SHA256`, `CVE`, `Actor/Malware`) -> bấm **"Lưu Đáp Án Tay"** -> chạy Benchmark so sánh kết quả Agent vs Đáp án Tay & xem bảng sai số.
  - **Tab 4 — Kiến Trúc & Nhật Ký Tuần:** Lịch sử công việc nhóm và kiến trúc 4 tầng.

## Bước 8: Nhật ký Tuần 1–4 & Kiểm thử Cuối cùng
- Tạo `docs/weekly_logs/tuan_01.md`, `tuan_02.md`, `tuan_03.md`, `tuan_04.md` và `README.md` cập nhật ngắn gọn luồng chạy mới (cài Ollama, chạy web, gán nhãn 50 bài, chạy benchmark).
- Chạy toàn bộ `python -m pytest tests/ -v`, test khởi động Web Server thực tế, test Ollama `qwen2.5:3b` phân tích trực tiếp, kiểm tra corpus 50 bài thật.
- Commit theo từng phần rõ ràng (không `git add .`) và push lên `origin feat/cti-local-agent-skills`.
