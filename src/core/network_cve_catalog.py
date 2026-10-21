# -*- coding: utf-8 -*-
"""
==============================================================================
NETWORK THREAT INTELLIGENCE CATALOG & SMART TRIGGER ENGINE (LÂM / DATA & DEVOPS)
Chuyên sâu An toàn Mạng (Firewall, Router, VPN, Gateway, C2 Botnet traffic).
Hỗ trợ phân loại Timeline Date (24h/30d/1y/3y), Multi-Tagging và Smart Trigger.
==============================================================================
"""
from typing import Dict, Any, List, Optional
from datetime import datetime

# Danh mục các mối đe dọa mạng được xác thực chuẩn quốc tế (CISA KEV / ThreatFox / Vendor)
NETWORK_CATALOG: List[Dict[str, Any]] = [
    {
        "id": "NET-2024-001",
        "threat_domain": "network",
        "threat_type": "CVE",
        "identifier": "CVE-2024-21887",
        "title": "Ivanti Connect Secure / Policy Secure Gateway Pre-Auth RCE",
        "target_asset": "Ivanti Connect Secure SSL-VPN Gateway",
        "vendor": "Ivanti",
        "protocol": "HTTPS (Port 443)",
        "cvss_score": 9.1,
        "severity": "CRITICAL",
        "severity_color": "crimson",
        "date_category": "24h_emergency",
        "published_date": "2024-01-11",
        "last_seen": "2026-10-21",
        "tags": ["#Ivanti", "#VPN_Gateway", "#PreAuth_RCE", "#Command_Injection", "#CISA_KEV"],
        "description": "Lỗ hổng chèn lệnh hệ điều hành (Command Injection) trong thành phần web quản trị của Ivanti VPN, cho phép kẻ tấn công chưa xác thực từ Internet gửi payload độc hại để thực thi lệnh tùy ý với quyền root.",
        "smart_trigger_reason": "CISA ban hành Chỉ thị Khẩn cấp ED 24-01 + Đang bị khai thác diện rộng trên Internet.",
        "evidence_sources": [
            "CISA Known Exploited Vulnerabilities (KEV) Catalog",
            "Ivanti Security Advisory KB44123",
            "Mandiant Zero-Day Exploitation Analysis"
        ],
        "blast_radius": "Toàn bộ mạng nội bộ kết nối qua cổng SSL-VPN (VLAN 10, VLAN 20, Active Directory)."
    },
    {
        "id": "NET-2024-002",
        "threat_domain": "network",
        "threat_type": "CVE",
        "identifier": "CVE-2024-3400",
        "title": "Palo Alto Networks PAN-OS GlobalProtect Command Injection",
        "target_asset": "Palo Alto Next-Gen Firewall (GlobalProtect Gateway)",
        "vendor": "Palo Alto Networks",
        "protocol": "GlobalProtect VPN (Port 443)",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "severity_color": "crimson",
        "date_category": "active_30d",
        "published_date": "2024-04-12",
        "last_seen": "2026-10-18",
        "tags": ["#PaloAlto", "#PAN_OS", "#GlobalProtect", "#RCE_ZeroDay", "#Firewall"],
        "description": "Lỗ hổng thực thi mã từ xa cực kỳ nghiêm trọng trên tính năng GlobalProtect của tường lửa Palo Alto PAN-OS, cho phép kẻ tấn công chưa xác thực chiếm quyền root trên thiết bị tường lửa biên.",
        "smart_trigger_reason": "Điểm CVSS tuyệt đối 10.0 + Phát hiện nhóm gián điệp mạng UTA0218 khai thác cài cắm backdoor.",
        "evidence_sources": [
            "Palo Alto Unit 42 Threat Advisory",
            "Volexity Incident Response Report",
            "CISA KEV Catalog"
        ],
        "blast_radius": "Tường lửa biên công ty, cho phép vượt qua toàn bộ chính sách lọc gói mạng."
    },
    {
        "id": "NET-2024-003",
        "threat_domain": "network",
        "threat_type": "CVE",
        "identifier": "CVE-2024-21762",
        "title": "Fortinet FortiOS SSL-VPN Out-of-bounds Write RCE",
        "target_asset": "FortiGate Next-Generation Firewall",
        "vendor": "Fortinet",
        "protocol": "SSL-VPN (Port 443/10443)",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "severity_color": "crimson",
        "date_category": "active_30d",
        "published_date": "2024-02-09",
        "last_seen": "2026-10-12",
        "tags": ["#Fortinet", "#FortiOS", "#SSL_VPN", "#Out_of_Bounds_RCE", "#Firewall"],
        "description": "Lỗ hổng ghi ngoài vùng nhớ trong web service của FortiOS SSL-VPN, cho phép thực thi mã lệnh hoặc kiểm soát thiết bị từ xa qua các HTTP request được chế tạo đặc biệt.",
        "smart_trigger_reason": "Fortinet xác nhận lỗ hổng có khả năng đang bị khai thác trong môi trường thực tế.",
        "evidence_sources": [
            "Fortinet PSIRT Advisory FG-IR-24-015",
            "CISA KEV Alert",
            "NCSC-UK Security Guidance"
        ],
        "blast_radius": "Cổng kết nối VPN từ xa của toàn bộ cán bộ nhân viên và đối tác."
    },
    {
        "id": "NET-2023-001",
        "threat_domain": "network",
        "threat_type": "CVE",
        "identifier": "CVE-2023-20198",
        "title": "Cisco IOS XE Web UI Privilege Escalation & Implant",
        "target_asset": "Cisco Enterprise Routers & Catalyst Switches",
        "vendor": "Cisco",
        "protocol": "HTTP/HTTPS Web UI (Port 80/443)",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "severity_color": "crimson",
        "date_category": "trending_1y",
        "published_date": "2023-10-16",
        "last_seen": "2026-09-28",
        "tags": ["#Cisco", "#IOS_XE", "#Privilege_Escalation", "#Router", "#Switch"],
        "description": "Kẻ tấn công từ xa tạo tài khoản đặc quyền cấp cao (Level 15) trên thiết bị định tuyến Cisco IOS XE thông qua giao diện Web UI, sau đó cài cắm backdoor điều khiển lưu lượng mạng.",
        "smart_trigger_reason": "Hơn 40.000 thiết bị Cisco trên Internet bị cài cắm mã độc điều khiển ngầm.",
        "evidence_sources": [
            "Cisco Talos Intelligence Incident Advisory",
            "CISA Emergency Directive 24-01"
        ],
        "blast_radius": "Bộ định tuyến trục chính (Core Router), kẻ xấu có thể sniff toàn bộ luồng dữ liệu truyền qua."
    },
    {
        "id": "NET-2024-004",
        "threat_domain": "network",
        "threat_type": "CVE",
        "identifier": "CVE-2024-40766",
        "title": "SonicWall SonicOS Management Access Control Vulnerability",
        "target_asset": "SonicWall Gen 5, Gen 6, Gen 7 Firewalls",
        "vendor": "SonicWall",
        "protocol": "SonicOS Management SSL-VPN",
        "cvss_score": 9.3,
        "severity": "CRITICAL",
        "severity_color": "crimson",
        "date_category": "active_30d",
        "published_date": "2024-08-22",
        "last_seen": "2026-10-19",
        "tags": ["#SonicWall", "#SonicOS", "#AuthBypass", "#Ransomware_Target"],
        "description": "Lỗ hổng kiểm soát truy cập không đúng đắn trong giao diện quản trị SonicOS, dẫn đến việc thiết bị bị treo hoặc kẻ tấn công chiếm quyền truy cập trái phép.",
        "smart_trigger_reason": "SonicWall và CISA cảnh báo nhóm Akira Ransomware đang tích cực khai thác vào mạng doanh nghiệp.",
        "evidence_sources": [
            "SonicWall PSIRT Advisory SNWLID-2024-0015",
            "Arctic Wolf Labs Ransomware Bulletin"
        ],
        "blast_radius": "Tường lửa chi nhánh và kết nối mạng riêng ảo VPN Site-to-Site."
    },
    {
        "id": "NET-C2-001",
        "threat_domain": "network",
        "threat_type": "C2_IP",
        "identifier": "194.26.29.112:8443",
        "title": "Active Cobalt Strike C2 Server (Mirai / AsyncRAT Reflector)",
        "target_asset": "Network Perimeter / DNS Outbound",
        "vendor": "Abuse.ch Feodo/ThreatFox",
        "protocol": "TCP / HTTPS (Port 8443)",
        "cvss_score": 8.8,
        "severity": "HIGH",
        "severity_color": "amber",
        "date_category": "24h_emergency",
        "published_date": "2026-10-20",
        "last_seen": "2026-10-21",
        "tags": ["#C2_Botnet", "#CobaltStrike", "#Active_C2", "#Port8443", "#ThreatFox"],
        "description": "Địa chỉ IP máy chủ điều khiển C2 của mã độc Cobalt Strike đang hoạt động tích cực, chuyên gửi tín hiệu beaconing và tải payload đánh cắp dữ liệu mạng nội bộ.",
        "smart_trigger_reason": "ThreatFox ghi nhận tín hiệu C2 kết nối trong 24 giờ qua với mức tin cậy 100%.",
        "evidence_sources": [
            "Abuse.ch ThreatFox API (IOC ID: 1198234)",
            "Shodan Host Exposure: Open JARM SSL Fingerprint"
        ],
        "blast_radius": "Các máy trạm bị nhiễm gửi kết nối ngầm ra ngoài qua cổng HTTPS không chuẩn."
    },
    {
        "id": "NET-C2-002",
        "threat_domain": "network",
        "threat_type": "C2_IP",
        "identifier": "45.142.214.238:443",
        "title": "Qakbot / Black Basta Ransomware Network Proxy",
        "target_asset": "Edge Gateway / Proxy",
        "vendor": "Abuse.ch Feodo Tracker",
        "protocol": "TCP / TLS (Port 443)",
        "cvss_score": 8.5,
        "severity": "HIGH",
        "severity_color": "amber",
        "date_category": "active_30d",
        "published_date": "2026-09-30",
        "last_seen": "2026-10-17",
        "tags": ["#Qakbot", "#Botnet_Proxy", "#Ransomware_Prep", "#FeodoTracker"],
        "description": "Node trung gian botnet dùng để chuyển tiếp lưu lượng điều khiển và quét mạng tìm kiếm dịch vụ SMB/RDP mở.",
        "smart_trigger_reason": "Feodo Tracker xác nhận trạng thái 'online' với hơn 40 lượt ping từ honeypot.",
        "evidence_sources": [
            "Abuse.ch Feodo Tracker Verified List",
            "AbuseIPDB Score: 100% Malicious"
        ],
        "blast_radius": "Lưu lượng quét tự động nhắm vào cổng dịch vụ VPN/Remote Desktop của công ty."
    },
    {
        "id": "NET-HIST-001",
        "threat_domain": "network",
        "threat_type": "CVE",
        "identifier": "CVE-2023-32154",
        "title": "MikroTik RouterOS IPv6 Route Advertisement Buffer Overflow",
        "target_asset": "MikroTik RouterOS v7 Core Routers",
        "vendor": "MikroTik",
        "protocol": "IPv6 Router Advertisement (ICMPv6)",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "severity_color": "crimson",
        "date_category": "historical_3y",
        "published_date": "2023-05-18",
        "last_seen": "2026-08-15",
        "tags": ["#MikroTik", "#RouterOS", "#IPv6_Exploit", "#Buffer_Overflow"],
        "description": "Lỗ hổng tràn bộ đệm khi xử lý gói tin định tuyến IPv6, cho phép kẻ tấn công cùng lớp mạng hoặc từ xa gửi gói tin ICMPv6 để chiếm quyền điều khiển router.",
        "smart_trigger_reason": "Lỗ hổng mạng lịch sử vẫn được các botnet quét tự động nhằm vào các router doanh nghiệp chưa nâng cấp.",
        "evidence_sources": [
            "MikroTik Security Changelog v7.9.1",
            "GitHub PoC Exploit Repository"
        ],
        "blast_radius": "Bộ định tuyến biên ISP / Doanh nghiệp vừa và nhỏ."
    }
]

def get_network_threat_catalog() -> List[Dict[str, Any]]:
    """Trả về toàn bộ danh mục mối đe dọa mạng."""
    return NETWORK_CATALOG

def filter_network_threats(
    time_window: Optional[str] = None,
    tag: Optional[str] = None,
    severity: Optional[str] = None,
    threat_type: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Lọc các mối đe dọa mạng theo:
    - time_window: '24h_emergency', 'active_30d', 'trending_1y', 'historical_3y'
    - tag: '#Cisco', '#Fortinet', '#VPN', '#C2_Botnet', v.v.
    - severity: 'CRITICAL', 'HIGH', 'MEDIUM'
    - threat_type: 'CVE', 'C2_IP', 'FIRMWARE_HASH'
    """
    results = []
    
    # Định nghĩa quan hệ tích lũy thời gian
    timeline_hierarchy = {
        "24h_emergency": ["24h_emergency"],
        "active_30d": ["24h_emergency", "active_30d"],
        "trending_1y": ["24h_emergency", "active_30d", "trending_1y"],
        "historical_3y": ["24h_emergency", "active_30d", "trending_1y", "historical_3y"]
    }
    
    allowed_categories = timeline_hierarchy.get(time_window, None) if time_window else None

    for item in NETWORK_CATALOG:
        # Lọc time window
        if allowed_categories and item["date_category"] not in allowed_categories:
            continue
            
        # Lọc tag
        if tag and tag.lower() not in [t.lower() for t in item.get("tags", [])]:
            continue
            
        # Lọc severity
        if severity and item.get("severity", "").upper() != severity.upper():
            continue
            
        # Lọc threat type
        if threat_type and item.get("threat_type", "").upper() != threat_type.upper():
            continue
            
        results.append(item)
        
    return results

def evaluate_smart_crawl_trigger(
    high_severity_events: int = 0,
    cisa_network_update: bool = False,
    hours_since_last_crawl: float = 1.0,
    surge_detected: bool = False
) -> Dict[str, Any]:
    """
    Bộ kích hoạt thông minh (Smart Trigger Engine):
    Đánh giá xem hệ thống có nên tiến hành quét/cào dữ liệu hay không thay vì cào vô tội vạ.
    """
    urgency_score = 0
    reasons = []

    if cisa_network_update:
        urgency_score += 50
        reasons.append("Phát hiện Chỉ thị Khẩn cấp / Cập nhật CVE Mạng mới từ CISA KEV.")

    if surge_detected or high_severity_events >= 2:
        urgency_score += 40
        reasons.append(f"Ghi nhận {high_severity_events} mối đe dọa mạng nghiêm trọng (CVSS >= 9.0) bùng phát.")

    if hours_since_last_crawl >= 6.0:
        urgency_score += 25
        reasons.append(f"Đã {hours_since_last_crawl:.1f} giờ kể từ lần làm sạch dữ liệu gần nhất (Định kỳ kiểm tra liveness IP).")

    # Xác định mức độ khẩn
    if urgency_score >= 50:
        urgency_level = "CRITICAL"
        should_crawl = True
    elif urgency_score >= 35:
        urgency_level = "HIGH"
        should_crawl = True
    elif urgency_score >= 20:
        urgency_level = "MEDIUM"
        should_crawl = (hours_since_last_crawl >= 4.0)
    else:
        urgency_level = "LOW"
        should_crawl = False
        reasons.append("Hạ tầng an ninh mạng ổn định, chưa có tín hiệu đe dọa đột biến.")

    return {
        "should_crawl": should_crawl,
        "urgency_score": urgency_score,
        "urgency_level": urgency_level,
        "reason": " | ".join(reasons) if reasons else "Hệ thống đang ở trạng thái giám sát tiêu chuẩn.",
        "evaluated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
