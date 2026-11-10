# LUẬT BẢO VỆ RANH GIỚI VÀ PHÂN QUYỀN MÃ NGUỒN (TERRITORY GUARD)

## 1. Bản đồ quyền sở hữu module:
- PHÚC phụ trách: `src/core/` (Local LLM Agent, IOC Extractor, MITRE Mapper, Dynamic Agent Skill Synthesizer & Sandbox Verifier)
- KHANG phụ trách: `src/security/` (Enrichment API VirusTotal/AbuseIPDB/Shodan/OpenPhish/MalwareBazaar, STIX 2.1, Dataset 50 bài & Evaluator Benchmark)
- LÂM phụ trách: `src/automation/` (OSINT Collectors RSS/CISA KEV, SQLite Cache, FastAPI Backend & Web Dashboard)

## 2. Quy tắc làm việc trên nhánh tích hợp chung (`feat/cti-local-agent-skills`):
- Mặc định trên nhánh cá nhân (`feat/[tên]-dev`), mỗi thành viên chỉ sửa module thuộc quyền sở hữu của mình.
- Riêng trên nhánh tích hợp tái cấu trúc theo góp ý GVHD (`feat/cti-local-agent-skills`), nhóm thống nhất cho phép cập nhật đồng bộ giữa `src/core/`, `src/security/` và `src/automation/` nhưng phải giữ rõ tên người phụ trách trong docstring đầu file và giao ước schema tại `shared/schemas.py`.
- Không được đẩy thẳng lên `main`; mọi thay đổi phải chạy `python -m pytest tests/ -v` đạt trước khi push lên nhánh tính năng.
