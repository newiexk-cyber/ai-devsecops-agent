# ĐẶC TẢ THIẾT KẾ: NETWORK SENTINEL - CHUYÊN SÂU MẠNG & KHO KỸ NĂNG TÁC TỬ (AGENT SKILLS)

- **Mã thiết kế:** `SPEC-2026-10-21-NETWORK-SKILLS`
- **Tác giả:** Nguyễn Nhật Lâm (Data & DevOps Lead) & Team CTI-Sentinel
- **GVHD:** ThS. Đinh Phương Nam (HUTECH 23DATA1)
- **Trạng thái:** Approved / Implementation Phase

---

## 1. Bối cảnh & Lý do Chuyển đổi (Strategic Pivot)
Mô hình cũ đang gặp 3 hạn chế thực tế:
1. **Quá rộng và không rõ trọng tâm:** Cào chung chung mọi loại tin an ninh mạng khiến dữ liệu bị loãng, không làm nổi bật nghiệp vụ hạ tầng mạng.
2. **Quy tắc phòng thủ tĩnh (Sigma / YARA / IP blocklist) quá cứng nhắc:** Mỗi hãng thiết bị mạng (Cisco, Fortinet, Palo Alto) dùng một cú pháp cấu hình riêng. Một đoạn text tĩnh không thể tương thích linh hoạt với nhiều hệ thống.
3. **Thiếu tính giải trình (Explainable AI - XAI):** Người quản trị mạng không tin tưởng các quyết định của AI nếu AI không chứng minh được tại sao nguy hiểm, căn cứ từ đâu.

### Mục tiêu của Mô hình Mới:
- **Phạm vi đầu vào:** Tập trung 100% vào **An toàn Mạng (Network Security)**: Thiết bị biên (Firewall, Router, VPN), Giao thức mạng (BGP, DNS, SSH, SSL), dải IP C2 Botnet và mã Hash của malware nhắm vào hạ tầng mạng.
- **Khi nào nên cào (Smart Trigger):** Cơ chế kích hoạt dựa trên sự kiện và độ khẩn cấp mạng (CISA KEV Network CVE mới, dải IP Botnet bùng nổ, EPSS spike) thay vì cào định kỳ mù quáng.
- **Phân loại Date & Tags:** Phân chia mốc thời gian (24h Nóng, 30 ngày, 1 năm, 3 năm) và gắn Tags phân màu rõ rệt.
- **Explainable AI (XAI & Trust):** Xuất chuỗi lập luận (Reasoning Chain), bằng chứng đối chiếu và điểm tin cậy (Trust Score 0-100%).
- **Đầu ra cốt lõi: Dynamic Agent Skills:** Thay thế các file rule tĩnh bằng **Kỹ năng Tác tử (Tool Definition & Playbook Actions)** chuẩn JSON-Schema để các AI Agent khác (như Blue Team Defense Agent, Incident Response Agent) có thể tự động gọi và thực thi.

---

## 2. Kiến trúc Hệ thống

```
+---------------------------------------------------------------------------------+
|                         ADAPTIVE NETWORK INGESTION ENGINE                       |
|   - Network CVE Filter (Cisco, Fortinet, Palo Alto, Ivanti, CheckPoint, ...)    |
|   - Active Network C2 Botnet IPs (ThreatFox / Feodo Tracker with timestamps)    |
|   - Smart Trigger: Evaluates Urgency Score to decide "When to Crawl"            |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                        TIMELINE & NETWORK TAGGING TAXONOMY                      |
|   - Date Aging: 24h Emergency | Active 30 Days | Trending 1 Year | 1-3 Years     |
|   - Multi-Tags: #Cisco #FortiOS #VPN_Exploit #AuthBypass #PreAuth_RCE #C2_Botnet|
|   - Color Coding: 🔴 Critical | 🟠 High | 🟡 Medium | 🔵 Informational          |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                         EXPLAINABLE AI (XAI) & TRUST ENGINE                     |
|   - Multi-source Evidence Verification (CISA KEV, NVD, Vendor Bulletins)        |
|   - Step-by-Step Reasoning Chain (Why is this critical for the network?)       |
|   - Trust Confidence Score (%) & Network Blast Radius Analysis                  |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                       DYNAMIC NETWORK AGENT SKILLS LIBRARY                      |
|   - Skill 1: network_virtual_patching (Adaptive Fortigate/Cisco/pfSense policy) |
|   - Skill 2: network_containment_and_isolation (BGP null-route, DNS sinkhole)   |
|   - Skill 3: active_network_exposure_probe (Validate internal exposure)         |
|   - Skill 4: network_traffic_triage (Dynamic packet filter & Suricata actions)  |
|   ==> Exportable as OpenAI Tool Call Schema / LangChain Tool / Antigravity Skill|
+---------------------------------------------------------------------------------+
```

---

## 3. Cấu trúc Dữ liệu Chi tiết

### 3.1. Network Threat Entity
```json
{
  "id": "NET-2024-001",
  "threat_type": "CVE | C2_IP | FIRMWARE_HASH",
  "identifier": "CVE-2024-21887",
  "target_asset": "Ivanti Connect Secure / Policy Secure Gateway",
  "vendor": "Ivanti",
  "cvss_score": 9.1,
  "severity": "CRITICAL",
  "severity_color": "crimson",
  "date_category": "24h_emergency | active_30d | trending_1y | historical_3y",
  "published_date": "2024-01-11",
  "last_seen": "2026-10-15",
  "tags": ["#Ivanti", "#VPN_Gateway", "#PreAuth_RCE", "#Command_Injection"],
  "smart_trigger_reason": "CISA KEV emergency directive + Active exploitation reported"
}
```

### 3.2. Explainable AI (XAI) Trust Structure
```json
{
  "trust_score": 96,
  "reasoning_chain": [
    "1. Phát hiện thiết bị VPN Gateway bị lộ giao diện Web quản trị trên cổng 443.",
    "2. Lỗ hổng cho phép bypass xác thực và chèn lệnh hệ điều hành trực tiếp qua tham số URI.",
    "3. Kẻ tấn công có thể xâm nhập sâu vào mạng nội bộ công ty mà không cần thông tin đăng nhập.",
    "4. Đề xuất: Khóa đường dẫn URI nghi vấn và cách ly tài khoản dịch vụ liên quan."
  ],
  "evidence_sources": [
    "CISA Known Exploited Vulnerabilities Catalog (KEV)",
    "Ivanti Security Advisory 2024-01",
    "Mandiant Threat Intelligence Report"
  ],
  "network_blast_radius": "Toàn bộ mạng nội bộ kết nối qua cổng SSL-VPN (VLAN 10, VLAN 20)."
}
```

### 3.3. Dynamic Agent Skill Schema
```json
{
  "skill_id": "skill_network_virtual_patch",
  "skill_name": "network_virtual_patching",
  "description": "Áp dụng chính sách phòng thủ ảo tức thì cho Firewall/WAF để chặn khai thác lỗ hổng mạng",
  "parameters": {
    "type": "object",
    "properties": {
      "target_device": { "type": "string", "enum": ["fortigate", "cisco_asa", "pfsense", "nginx_waf"] },
      "action": { "type": "string", "enum": ["block_uri", "drop_ip", "rate_limit", "isolate_interface"] },
      "pattern": { "type": "string" },
      "rollback_enabled": { "type": "boolean", "default": true }
    },
    "required": ["target_device", "action", "pattern"]
  },
  "execution_code": "def execute(params): ...",
  "verification_step": "Gửi request kiểm tra tính sẵn sàng mà không gián đoạn người dùng thật",
  "rollback_skill": "network_virtual_patch_rollback"
}
```
