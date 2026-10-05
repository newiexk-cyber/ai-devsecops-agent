# 🛡️ AI DEVSECOPS MULTI-AGENT SYSTEM

> Hệ thống Multi-Agent AI tự động rà soát lỗ hổng mã nguồn (SAST), lọc cảnh báo ảo và tự sinh Pull Request vá lỗi tích hợp CI/CD.

## 👥 Nhóm phát triển (3 thành viên):
- 👑 **PHÚC (Trưởng nhóm):** AI Core & LangGraph Lead (`src/core/`)
- 🛡️ **KHANG:** Security Engine & Benchmark Lead (`src/security/`)
- ⚙️ **LÂM:** DevOps, CI/CD & Git Bot Lead (`src/automation/`)

## 🔗 Repository GitHub:
```bash
git clone https://github.com/newiexk-cyber/ai-devsecops-agent.git
```

## 🚀 Hướng dẫn bắt đầu nhanh (Quick Start):

1. **Cài đặt thư viện:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Tạo Thẻ Căn Cước định danh (làm 1 lần duy nhất trên máy):**
   Tạo file `.agents/identity.txt`:
   - Trên máy Phúc ghi: `phuc`
   - Trên máy Khang ghi: `khang`
   - Trên máy Lâm ghi: `lam`

3. **Đồng bộ mã nguồn hàng ngày:**
   ```bash
   python sync.py
   ```

4. **Tài liệu chi tiết:**
   - Kế hoạch 12 tuần & đề cương: xem tại `docs/DACN.docx`
   - Hướng dẫn điều khiển & phối hợp: xem tại `docs/HUONG_DAN_DIEU_KHIEN_AGENT_DONG_BO.docx`
