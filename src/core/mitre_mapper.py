# -*- coding: utf-8 -*-
"""
MITRE ATT&CK ENTERPRISE MAPPER (PHÚC & LÂM)
Ánh xạ kỹ thuật và chiến thuật MITRE ATT&CK dựa trên phân tích ranh giới từ (word boundary),
lọc câu phủ định (negation filter), trích xuất câu bằng chứng thực tế và chấm điểm heuristic.
"""
import re
from typing import List, Dict, Any

MITRE_RULES = [
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "keywords": ["cve-", "zero-day", "command injection", "remote code execution", "rce", "unauthenticated access"]
    },
    {
        "id": "T1566.001",
        "name": "Spearphishing Attachment / Link",
        "tactic": "Initial Access",
        "keywords": ["phishing", "fake captcha", "malicious attachment", "phishing lure", "fraudulent email"]
    },
    {
        "id": "T1059.001",
        "name": "PowerShell Script Execution",
        "tactic": "Execution",
        "keywords": ["powershell", "powershell.exe", "script block", "encodedcommand"]
    },
    {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "keywords": ["dropper", "reverse shell", "staged loader", "c2 beacon", "payload download"]
    },
    {
        "id": "T1071.001",
        "name": "Web Protocols C2",
        "tactic": "Command and Control",
        "keywords": ["command and control", "c2 server", "c2 traffic", "exfiltration over https"]
    },
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "keywords": ["ransomware", "ransom note", "encrypted files", "chacha20 encryption", "aes encryption"]
    },
    {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "keywords": ["mimikatz", "lsass dump", "credential dumping", "password stealer", "token theft"]
    },
    {
        "id": "T1021.001",
        "name": "Remote Desktop Protocol (RDP)",
        "tactic": "Lateral Movement",
        "keywords": ["rdp lateral", "remote desktop protocol", "rdp connection", "internal lateral movement"]
    }
]

NEGATION_PATTERNS = [
    r"\bnot\s+vulnerable\b",
    r"\bno\s+evidence\b",
    r"\bnot\s+affected\b",
    r"\bhas\s+been\s+patched\b",
    r"\bmitigated\b",
    r"\bdoes\s+not\s+(?:use|contain|execute|encrypt)\b",
    r"\bno\s+signs\s+of\b",
    r"\bwithout\s+(?:any)?\s+evidence\b"
]


def map_mitre_techniques(text: str) -> List[Dict[str, Any]]:
    """
    Ánh xạ văn bản với cơ sở tri thức MITRE ATT&CK.
    - So khớp theo word boundary (\b).
    - Lọc bỏ các câu có ngữ cảnh phủ định (ví dụ: 'not vulnerable', 'no evidence').
    - Trích xuất câu bằng chứng (evidence sentence) trực tiếp từ văn bản.
    - Cung cấp heuristic_score được chuẩn hóa.
    """
    if not text or not text.strip():
        return []

    # Loại bỏ phần reference boilerplate nếu có
    clean_lines = []
    in_references = False
    for line in text.split("\n"):
        line_strip = line.strip().lower()
        if line_strip.startswith("references:") or line_strip.startswith("sources:"):
            in_references = True
            continue
        if not in_references:
            clean_lines.append(line)
    
    body_text = "\n".join(clean_lines)

    # Chia nhỏ văn bản thành các câu độc lập
    sentences = re.split(r'(?<=[.!?\n])\s+', body_text)
    matched_techniques: List[Dict[str, Any]] = []

    for rule in MITRE_RULES:
        rule_matched_words = set()
        evidence_sentences = []

        for kw in rule["keywords"]:
            # Word boundary regex matching
            kw_pattern = re.compile(r'(?i)\b' + re.escape(kw) + r'\b')

            for s in sentences:
                s_clean = s.strip()
                if not s_clean:
                    continue

                if kw_pattern.search(s_clean):
                    # Kiểm tra xem câu này có chứa câu phủ định không
                    is_negated = any(re.search(neg, s_clean, re.IGNORECASE) for neg in NEGATION_PATTERNS)
                    if not is_negated:
                        rule_matched_words.add(kw)
                        if len(evidence_sentences) < 2 and s_clean not in evidence_sentences:
                            evidence_sentences.append(s_clean)

        if rule_matched_words:
            matched_list = sorted(list(rule_matched_words))
            heuristic_score = round(min(0.60 + (len(matched_list) * 0.10), 0.95), 2)
            evidence_sample = evidence_sentences[0] if evidence_sentences else f"Phát hiện các từ khóa: {', '.join(matched_list)}"
            
            matched_techniques.append({
                "technique_id": rule["id"],
                "technique_name": rule["name"],
                "tactic": rule["tactic"],
                "matched_keywords": matched_list,
                "evidence_sentence": evidence_sample,
                "evidence": f"Từ khóa xác thực ({', '.join(matched_list)}): \"{evidence_sample[:120]}...\"",
                "heuristic_score": heuristic_score,
                "confidence": heuristic_score  # Alias giữ tính tương thích API
            })

    # Sắp xếp theo điểm heuristic giảm dần
    matched_techniques.sort(key=lambda x: x["heuristic_score"], reverse=True)
    return matched_techniques
