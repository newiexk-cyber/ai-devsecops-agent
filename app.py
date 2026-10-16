# -*- coding: utf-8 -*-
"""
==============================================================================
CTI-SENTINEL // AUTONOMOUS THREAT INTELLIGENCE AI AGENT SYSTEM
Đồ án chuyên ngành - Khoa Công nghệ thông tin - Đại học HUTECH
GVHD: ThS. Đinh Phương Nam
Nhóm sinh viên thực hiện (23DATA1):
- Nguyễn Nhật Lâm (2387700036) - Nhóm trưởng / Data & DevOps Lead
- Nguyễn Phi Phúc (2387701131) - AI Core & Reasoning Lead
- Trần Minh Khang (2387700027) - Threat Intel & Security Lead
==============================================================================
"""
import sys
import uvicorn
import webbrowser

def print_banner():
    banner = r"""
  ____ _____ ___     ____  _____ _   _ _____ ___ _   _ _____ _     
 / ___|_   _|_ _|   / ___|| ____| \ | |_   _|_ _| \ | | ____| |    
| |     | |  | |____\___ \|  _| |  \| | | |  | ||  \| |  _| | |    
| |___  | |  | |_____|__) | |___| |\  | | |  | || |\  | |___| |___ 
 \____| |_| |___|   |____/|_____|_| \_| |_| |___|_| \_|_____|_____|

    🛡️ HỆ THỐNG TÌNH BÁO MẠNG VÀ TỰ ĐỘNG SINH LUẬT PHÒNG THỦ AI AGENT
    🏛️ ĐẠI HỌC CÔNG NGHỆ TP.HCM (HUTECH) - KHOA CÔNG NGHỆ THÔNG TIN
    👨‍🏫 GVHD: ThS. Đinh Phương Nam
    👥 Nhóm: Nguyễn Nhật Lâm - Trần Minh Khang - Nguyễn Phi Phúc (23DATA1)
    =================================================================
    🌐 GIAO DIỆN WEB DEMO ĐANG CHẠY TẠI: http://127.0.0.1:8000
    📑 API SWAGGER DOCS TẠI: http://127.0.0.1:8000/docs
    =================================================================
"""
    print(banner)

if __name__ == "__main__":
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    print_banner()
    uvicorn.run("src.automation.server:app", host="127.0.0.1", port=8000, reload=False, log_level="info")
