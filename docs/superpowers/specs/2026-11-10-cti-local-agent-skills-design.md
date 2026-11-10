# Đặc Tả Thiết Kế: Hệ Thống CTI Local Agent Trích Xuất IOC & Sinh Kỹ Năng Phòng Thủ (Kèm Benchmark 50 Bài Gán Nhãn Tay)

- **Mã tài liệu:** `SPEC-2026-11-10-CTI-LOCAL-AGENT-SKILLS`
- **Dự án:** `ai-devsecops-agent` (CTI-Sentinel)
- **Nhóm thực hiện (HUTECH 23DATA1):** Nguyễn Phi Phúc (2387701131), Trần Minh Khang (2387700027), Nguyễn Nhật Lâm (2387700036)
- **GVHD:** ThS. Đinh Phương Nam
- **Trạng thái:** Draft — Chờ duyệt để lập kế hoạch triển khai

---

## 1. Bối cảnh & Yêu cầu Thực tế Cần Giải quyết

Sau các buổi góp ý của Giảng viên hướng dẫn và rà soát hiện trạng mã nguồn trên Git (`main`, `fix/security-audit-remediation`, `origin/feat/khang-dev`, `origin/feat/phuc-dev`), dự án cần điều chỉnh dứt khoát theo các quyết định sau:

1. **Định hướng cốt lõi — CTI thuần & Sinh Agent Skill (Bỏ SAST, bỏ khung Network Sentinel bó hẹp):**
   - Loại bỏ toàn bộ phần quét mã nguồn tĩnh (`SAST Studio`) và phần danh mục thiết bị mạng hardcoded của `Network Sentinel`.
   - Tập trung 100% vào bài toán Tình báo Mối đe dọa Mạng (CTI): đọc mọi bản tin an ninh mạng thật (Malware, APT, Ransomware, Phishing, C2, CVE/0-day), bóc tách **IOCs (`IP`, `DOMAIN`, `URL`, `MD5`, `SHA256`, `CVE`) + Thực thể (`Threat Actor`, `Malware Family`)**, giải trình XAI bám sát câu dẫn chứng trong bài, và **sinh Kỹ năng Tác tử (`Dynamic Agent Skill`)** thực thi được thay cho rule tĩnh.
2. **Dùng Mô hình Ngôn ngữ Cục bộ (Local LLM) phù hợp phần cứng hiện có:**
   - Máy phát triển dùng CPU `Intel Core i5-1135G7`, `16 GB RAM`, không GPU rời; ổ `C:` còn `~13 GB`, ổ `D:` còn `~104 GB`.
   - Cài đặt **Ollama** trên Windows và cấu hình biến môi trường `OLLAMA_MODELS=D:\ollama_models` để không làm đầy ổ `C:`, sử dụng model nhẹ hợp CPU như `qwen2.5:3b` (~1.9 GB).
   - Phải kết hợp **Regex + Local LLM Agent**: Regex lấy ứng viên đầy đủ, Local LLM đọc ngữ cảnh bài báo để **lọc nhiễu** (tránh bắt nhầm số phiên bản phần mềm, domain nguồn tin như `thehackernews.com`, hoặc câu phủ định) và tổng hợp XAI / Skill.
3. **Đo độ chính xác thực tế bằng 50 Bài báo Gán nhãn Tay (Ground Truth thật):**
   - Bộ dataset trước đó trên `feat/khang-dev` (30 mẫu) dùng script ghép câu tự động nên cho Precision/Recall = 100% thiếu thực tế.
   - Yêu cầu mới: Kéo đủ **50 bản tin CTI thật** (đầy đủ nội dung bài viết) kèm **giao diện/file Gán nhãn Tay** để 3 thành viên (Lâm, Phúc, Khang) tự đọc và xác nhận đáp án chuẩn (`IP`, `DOMAIN`, `MD5`, `SHA256`, `CVE`, tác nhân...).
   - Cho Agent chạy lại trên đúng 50 bài đó và so sánh đối chiếu hai kết quả: đo **Precision, Recall, F1-Score** cho từng loại IOC (so sánh *Regex Baseline* vs *Local LLM Agent*), kèm **tỷ lệ Skill hợp lệ cú pháp (AST + compile)** và **tỷ lệ Skill bắt đúng mẫu thử trong sandbox**.
4. **Cập nhật Git sạch sẽ & Nhật ký Tuần 1–4 chân thực:**
   - Tạo nhánh thống nhất `feat/cti-local-agent-skills` từ nền tảng `fix/security-audit-remediation` (`aa63062`) nhằm giữ trọn các bản vá bảo mật (không bịa điểm fallback, validate CVE chặt, chống XSS/Injection, cache CISA KEV, khử trùng lặp).
   - Gộp phần làm giàu thật từ `origin/feat/khang-dev` (Shodan InternetDB, OpenPhish, MalwareBazaar, STIX 2.1) nhưng **giữ nguyên ràng buộc không tạo điểm giả**.
   - Viết đầy đủ **Nhật ký Tuần 1–4** và sửa lại `BAO_CAO_TIEN_DO_TUAN_04.docx` bám sát công việc, file code và lịch sử Git thật, bỏ hoàn toàn văn phong rập khuôn kiểu "AI công nghiệp".

---

## 2. Kiến trúc Hệ thống Mục tiêu (4 Tầng Module)

```text
+-------------------------------------------------------------------+
| 1. OSINT INGESTION & CORPUS COLLECTOR (src/automation/collectors) |
| - RSS Feeds (TheHackerNews, BleepingComputer, SecurityWeek...)    |
| - CISA KEV JSON (15m TTL Cache) + Full-article text extractor     |
| - SQLite persistence (url_hash deduplication)                     |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
| 2. HYBRID LOCAL AGENT ENGINE (src/core/)                          |
| - ioc_extractor.py : Regex scan + Defang cleaning + Context line  |
| - local_llm_client.py : Ollama client (qwen2.5:3b on D:\)         |
| - cti_agent.py : Context filter (loại FP), XAI citations, Actors  |
| - Fallback minh bạch: báo rõ trạng thái nếu Ollama offline        |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
| 3. THREAT ENRICHMENT (src/security/enrichment_service.py)         |
| - VirusTotal v3, AbuseIPDB v2 (nếu có API key)                    |
| - Nguồn mở không key: Shodan InternetDB, MalwareBazaar, OpenPhish |
| - SQLite Cache + Strict Zero-Fabrication (thiếu nguồn -> unknown) |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
| 4. DYNAMIC SKILL SYNTHESIZER & SANDBOX BENCHMARK                  |
| - skill_synthesizer.py : Sinh Python Defense Skill + JSON Schema  |
|   (OpenAI / Claude / Gemini / LangChain) theo đúng IOC bài báo    |
| - skill_verifier.py : Kiểm tra AST whitelist + compile() + chạy   |
|   thử mẫu Positive (IOC từ bài) & Negative (mẫu sạch) trong sandbox|
| - benchmark/ : Bộ 50 bài + Annotation UI + Evaluator (P/R/F1)     |
+-------------------------------------------------------------------+
```

---

## 3. Thiết kế Chi tiết Từng Thành phần

### 3.1. Dọn dẹp & Phạm vi Git (`feat/cti-local-agent-skills`)
- **Xuất phát điểm nhánh:** Tạo nhánh `feat/cti-local-agent-skills` từ `fix/security-audit-remediation` (`aa63062`) để kế thừa toàn bộ 11 bản vá bảo mật và cache crawler đã kiểm thử.
- **Loại bỏ khỏi nhánh mới:**
  - `src/core/sast_analyzer.py`, `tests/test_sast_analyzer.py`, các model/route `/api/sast/*` trong `src/automation/server.py`.
  - Xóa/loại bỏ phần `Network Sentinel` cứng (danh mục 8 CVE cố định trong `src/core/network_cve_catalog.py` và các endpoint `/api/network-intel/*` chỉ xoay quanh router CVE), thay bằng hệ thống **CTI Feed + Agent Skill Studio** dùng chung cho mọi bài báo CTI.
  - Cập nhật `.agents/rules/territory-guard.md` bổ sung điều khoản cho phép đồng bộ trên nhánh tích hợp `feat/cti-local-agent-skills` khi cả nhóm tái cấu trúc pipeline chung, vẫn giữ docstring phân rõ trách nhiệm module.
  - Không commit file untracked `Bao_Cao_Do_An_SFSA_RS_HUTECH.docx` (file đồ án khác nằm nhầm thư mục) vào Git.

### 3.2. Local LLM Agent & Cơ chế Đọc hiểu Bài báo (`src/core/local_llm_client.py`, `src/core/cti_agent.py`)
- **Kết nối Ollama cục bộ:**
  - Cấu hình mặc định qua biến môi trường: `OLLAMA_BASE_URL=http://127.0.0.1:11434`, `OLLAMA_MODEL=qwen2.5:3b`, timeout hợp lý cho CPU (`45s`–`90s` tùy độ dài bài, có giới hạn input context `<= 6000` ký tự sạch ưu tiên đoạn chứa IOC).
  - Hàm `check_ollama_health()` trả về trạng thái thực (`online`, danh sách model đã kéo, hay `offline` kèm lỗi).
- **Quy trình Agent phân tích 1 bài báo (`analyze_cti_article(title, raw_content, mode="hybrid")`):**
  1. `extract_iocs_from_text(raw_content)` trích xuất toàn bộ ứng viên (`ips`, `domains`, `urls`, `md5`, `sha256`, `cves`) kèm câu ngữ cảnh chứa chúng (`context_sentence`).
  2. Nếu `mode == "hybrid"` và Ollama sẵn sàng, Agent gọi LLM với prompt JSON nghiêm ngặt:
     - Đưa tóm tắt bài báo + danh sách ứng viên IOC kèm câu chứa IOC.
     - Yêu cầu LLM đánh giá từng ứng viên: giữ hay loại kèm **lý do ngắn** (ví dụ: loại `10.0.0.1` vì là IP minh họa mạng nội bộ; loại `thehackernews.com` vì là tên báo; loại `1.2.3.4` nếu thực chất là version `v1.2.3.4` hoặc CVE giả).
     - Yêu cầu LLM trích xuất thêm nếu regex bỏ sót (vd: tên nhóm APT, họ mã độc, kỹ thuật chính) và tạo chuỗi lập luận XAI **chỉ được trích dẫn sự kiện có trong bài**.
  3. **Chế độ kiểm chứng minh bạch:** Nếu LLM trả về JSON sai định dạng hoặc timeout, parser dùng cơ chế sửa JSON an toàn rồi mới rơi về `regex_only` và **bắt buộc ghi `analysis_mode: "regex_fallback"`** (không bao giờ đánh lừa người dùng rằng LLM đã chạy).

### 3.3. Sinh Kỹ năng Phòng thủ (`Dynamic Agent Skill`) & Kiểm chứng Sandbox (`src/core/skill_synthesizer.py`, `src/core/skill_verifier.py`)
Khác với bản cũ (`network_skill_generator.py`) chỉ rẽ nhánh `if vendor == "ivanti"`, bản mới sinh Skill **trực tiếp từ tập IOC thật vừa trích xuất được từ bài báo**:
1. **Phân loại Skill động theo IOC thực tế của bài:**
   - Nếu bài có `MD5` / `SHA256` -> Sinh hàm kiểm tra Hash tệp/tiến trình (`detect_malware_hashes`).
   - Nếu bài có `IP` / `DOMAIN` / `URL` -> Sinh hàm kiểm tra nhật ký mạng/kết nối/DNS & sinh kế hoạch chặn an toàn (`contain_malicious_network_iocs`).
   - Nếu bài có `CVE` -> Sinh hàm đối chiếu dấu hiệu khai thác/phiên bản bị ảnh hưởng (`triage_cve_exposure`).
   - Một bài có cả Hash + IP/Domain + CVE sẽ đóng gói thành bộ **Composite CTI Defense Skill** (`execute_cti_defense_skill(telemetry: dict) -> dict`) thực thi thống nhất.
2. **Đa chuẩn giao tiếp Agent + Prompt:**
   - Vẫn xuất đủ 4 schema gọi hàm cho các hệ sinh thái phổ biến (**OpenAI Function Calling**, **Anthropic Tool Use**, **Google Gemini**, **LangChain `@tool`**) và **Python Executable Skill**.
   - Local LLM (nếu online) sinh mô tả ngữ cảnh chiến dịch & khuyến nghị kiểm tra cho Skill; phần khung hàm Python truyền IOC bằng `json.dumps()` chuẩn hóa (tuyệt đối chống Code Injection như P0 đã vá).
3. **Kiểm tra an toàn & Kiểm thử mẫu thử (`skill_verifier.py`):**
   - **Bước 1 (AST Safety Guard + Syntax Check):** Duyệt cây cú pháp `ast.parse(code)`: từ chối mọi `Import` ngoài whitelist (`json`, `re`, `hashlib`, `ipaddress`, `datetime`, `typing`), từ chối gọi `eval`, `exec`, `compile`, `open`, `subprocess`, `os.system`, `__import__`; sau đó chạy `compile()` để xác nhận `syntax_valid: True`.
   - **Bước 2 (Sandbox Match Test):** Chạy thử hàm `execute_cti_defense_skill` trong namespace cô lập trên:
     - *Mẫu thử dương tính (Positive Probe)*: event mạng / metadata file giả lập chứa chính IOC rút ra từ bài báo -> phải trả về `matched: True` và đúng danh sách IOC khớp.
     - *Mẫu thử âm tính (Negative Probe)*: event sạch (`8.8.8.8`, `google.com`, hash vô hại) -> phải trả về `matched: False` (không false-positive).
   - **Trạng thái thực thi:** Luôn gắn `"execution_status": "SANDBOX_VERIFIED"` hoặc `"DRY_RUN"` — không tự nhận `"ENFORCED"`.

### 3.4. Tập 50 Bài báo Thật, Gán nhãn Tay & Bộ Đo Độ chính xác (`src/security/benchmark/`, `data/benchmark/`)
1. **Thu thập 50 bài báo CTI thật (`scripts/collect_50_articles.py` / service):**
   - Lấy từ các bài báo công khai gần đây trên TheHackerNews, BleepingComputer, CISA Advisories, Unit42/DFIR/SecurityWeek (ưu tiên các bài thực sự có nhắc tới IOC như CVE, IP, Domain, Hash để bộ test có giá trị đo thật).
   - Cố gắng fetch nội dung HTML đầy đủ của bài báo (dùng `BeautifulSoup` lọc thẻ bài viết) để không bị cụt như RSS summary 2 câu; lưu vào `data/benchmark/cti_50_corpus.json`.
2. **Cấu trúc gán nhãn tay (`ground_truth` + `annotation_meta`):**
   ```json
   {
     "article_id": "CTI-01",
     "title": "...",
     "source": "TheHackerNews",
     "url": "https://...",
     "published_date": "2026-...",
     "raw_content": "...",
     "ground_truth": {
       "ips": [],
       "domains": [],
       "urls": [],
       "md5": [],
       "sha256": [],
       "cves": [],
       "threat_actors": [],
       "malware_families": []
     },
     "annotation_meta": {
       "status": "pending_human_review",
       "annotated_by": "",
       "reviewed_at": "",
       "notes": ""
     }
   }
   ```
   - **Nguyên tắc trung thực:** Không tự ý đánh dấu `human_verified` trước khi thành viên nhóm đọc và bấm xác nhận. Pipeline đánh giá chỉ tính điểm chuẩn trên các bài `human_verified` (và hiển thị rõ tiến độ `X/50 bài đã gán tay`).
3. **Giao diện Gán nhãn Tay & Chạy Benchmark trên Web Dashboard:**
   - Tab **"Gán Nhãn & Benchmark (50 Bài)"**:
     - Danh sách 50 bài bên trái (hiện trạng thái `Chưa duyệt` / `Đã gán tay - Lâm/Phúc/Khang`).
     - Khung giữa hiển thị toàn văn bài báo + khung bên phải là ô nhập/tích chọn đáp án IOC (`IP`, `DOMAIN`, `MD5`, `SHA256`, `CVE`, `Actor/Malware`) + nút gợi ý regex hỗ trợ đọc nhanh (nhưng bắt buộc người đọc kiểm, thêm cái sót, xóa cái sai rồi mới bấm **"Lưu Đáp Án Gán Tay"**).
     - Bảng **Benchmark & So sánh Độ chính xác Agent**: chạy so sánh song song *Regex Baseline* vs *Local LLM Agent (`qwen2.5:3b`)* trên toàn bộ các bài đã gán tay, xuất bảng:
       - `TP / FP / FN`, `Precision (%)`, `Recall (%)`, `F1-Score (%)` cho tổng IOC và từng loại (`IP`, `DOMAIN`, `HASH`, `CVE`).
       - `Skill Syntax Valid Rate (%)` và `Skill Sandbox Match Rate (%)`.
       - Bảng soi lỗi từng bài (Agent bắt thừa gì, sót gì so với đáp án người đọc).

### 3.5. Nhật ký Tiến độ Tuần 1–4 & Tài liệu Word
- Lưu trữ đầy đủ nhật ký Markdown trong `docs/weekly_logs/tuan_01.md` .. `tuan_04.md` để theo dõi trên Git.
- Cập nhật/xuất lại [`BAO_CAO_TIEN_DO_TUAN_04.docx`](file:///C:/Users/NhatLam/Downloads/d%C3%A1c/BAO_CAO_TIEN_DO_TUAN_04.docx) (và bản Tuần 1–3 nếu cần nộp kèm) đúng tên đề tài, đúng form bảng của HUTECH/GVHD, nội dung thực chất theo những gì từng thành viên làm được ở mỗi tuần và nêu rõ kế hoạch gán nhãn 50 bài + benchmark với Local LLM.

---

## 4. Kế hoạch Kiểm thử & Tiêu chí Nghiệm thu
1. **Unit & Integration Tests (`pytest tests/ -v`):**
   - Test `local_llm_client.py` (cả mock response lẫn live check nếu Ollama đang bật).
   - Test `cti_agent.py` (khử defang, lọc nhiễu version/whitelist domain, giữ nguyên tính xác định khi Ollama offline).
   - Test `skill_synthesizer.py` & `skill_verifier.py` (AST cấm hàm nguy hiểm, `compile()` đạt 100%, mẫu thử dương tính match `True`, mẫu âm tính `False`, không có trạng thái `ENFORCED`).
   - Test `evaluator.py` (tính chính xác TP/FP/FN/Precision/Recall/F1 trên dữ liệu mẫu đối chiếu đáp án).
   - Test API FastAPI (`/api/analyze`, `/api/corpus/*`, `/api/benchmark/run`, `/api/skills/*`) và xác nhận không còn route SAST.
2. **Kiểm tra thực tế trên máy:**
   - Ollama cài đặt xong, model `qwen2.5:3b` nằm tại `D:\ollama_models`, phản hồi OK qua `http://127.0.0.1:11434`.
   - Corpus 50 bài CTI thật nạp sạch, UI Dashboard mở bình thường không lỗi console/CSP, nút gán nhãn và chạy benchmark hoạt động trọn vẹn.

