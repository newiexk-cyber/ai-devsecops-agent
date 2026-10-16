# -*- coding: utf-8 -*-
"""
MITRE ATT&CK ENTERPRISE MAPPER (PHÚC)
Ánh xạ tự động các mô tả hành vi tấn công trong văn bản báo cáo sang mã kỹ thuật và chiến thuật MITRE ATT&CK.
"""
from typing import List, Dict, Any

MITRE_RULES = [
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "keywords": ["cve-", "zero-day", "vulnerability", "command injection", "remote code execution", "rce", "unauthenticated"]
    },
    {
        "id": "T1566.001",
        "name": "Spearphishing Attachment / Link",
        "tactic": "Initial Access",
        "keywords": ["phishing", "fake captcha", "attachment", "fraudulent", "lure", "email"]
    },
    {
        "id": "T1059.001",
        "name": "PowerShell Script Execution",
        "tactic": "Execution",
        "keywords": ["powershell", "powershell.exe", "win + r", "script block", "base64", "run dialog"]
    },
    {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "keywords": ["download", "dropper", "reverse shell", "payload.bin", "staged loader", "beacon"]
    },
    {
        "id": "T1071.001",
        "name": "Web Protocols C2",
        "tactic": "Command and Control",
        "keywords": ["command and control", "c2", "port 443", "https", "telemetry", "exfiltration"]
    },
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "keywords": ["ransomware", "encrypt", "chacha20", "aes", "ransom note", "bitcoin", "payment"]
    },
    {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "keywords": ["mimikatz", "lsass", "credential", "stealer", "passwords", "tokens", "wallet"]
    },
    {
        "id": "T1021.001",
        "name": "Remote Desktop Protocol (RDP)",
        "tactic": "Lateral Movement",
        "keywords": ["rdp", "remote desktop", "lateral movement", "internal subnet"]
    }
]

def map_mitre_techniques(text: str) -> List[Dict[str, Any]]:
    lower_text = text.lower()
    matched_techniques = []
    
    for rule in MITRE_RULES:
        matched_words = [kw for kw in rule["keywords"] if kw in lower_text]
        if matched_words:
            matched_techniques.append({
                "technique_id": rule["id"],
                "technique_name": rule["name"],
                "tactic": rule["tactic"],
                "evidence": f"Phát hiện các từ khóa liên quan: {', '.join(matched_words[:3])}",
                "confidence": min(0.65 + (len(matched_words) * 0.1), 0.98)
            })
            
    # Sắp xếp theo độ tin cậy giảm dần
    matched_techniques.sort(key=lambda x: x["confidence"], reverse=True)
    return matched_techniques
