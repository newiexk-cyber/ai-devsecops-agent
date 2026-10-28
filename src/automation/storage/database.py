# -*- coding: utf-8 -*-
"""
DATABASE PERSISTENCE & CACHING LAYER
Quản lý cơ sở dữ liệu SQLite: Lưu trữ bài viết thô, bộ đệm danh tiếng IOC và báo cáo tình báo đã phân tích.
"""
import sqlite3
import json
import hashlib
import os
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "data")
DB_PATH = os.path.join(DB_DIR, "cti_sentinel.db")

def get_db_connection() -> sqlite3.Connection:
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn

def init_database():
    """Khởi tạo các bảng cơ sở dữ liệu nếu chưa tồn tại kèm migration an toàn"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Bảng lưu trữ bài viết thô (Lâm)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS raw_threat_articles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_id TEXT UNIQUE,
        source_name TEXT NOT NULL,
        source_url TEXT NOT NULL,
        url_hash TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        raw_content TEXT NOT NULL,
        published_date TEXT,
        is_analyzed INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    # 2. Bảng bộ đệm danh tiếng IOC (Khang - Caching VirusTotal / AbuseIPDB)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ioc_reputation_cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ioc_type TEXT NOT NULL,
        ioc_value TEXT NOT NULL,
        is_malicious INTEGER NOT NULL,
        reputation_score INTEGER NOT NULL,
        enrichment_source TEXT NOT NULL,
        is_verified INTEGER DEFAULT 0,
        is_demo INTEGER DEFAULT 0,
        details_json TEXT,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(ioc_type, ioc_value)
    );
    """)

    # Migration kiểm tra các cột mới nếu đã tạo bảng trước đó
    try:
        cursor.execute("ALTER TABLE ioc_reputation_cache ADD COLUMN is_verified INTEGER DEFAULT 0")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE ioc_reputation_cache ADD COLUMN is_demo INTEGER DEFAULT 0")
    except Exception:
        pass
    
    # 3. Bảng lưu báo cáo tình báo và quy tắc phòng thủ đã sinh (Phúc)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id TEXT UNIQUE NOT NULL,
        article_id INTEGER,
        title TEXT NOT NULL,
        executive_summary TEXT,
        threat_actors TEXT,
        targeted_sectors TEXT,
        extracted_iocs_json TEXT,
        mitre_matrix_json TEXT,
        sigma_rule TEXT,
        yara_rule TEXT,
        firewall_blocklist TEXT,
        stix_bundle_json TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (article_id) REFERENCES raw_threat_articles(id)
    );
    """)
    
    conn.commit()
    conn.close()

def save_raw_article(source_name: str, source_url: str, title: str, raw_content: str, published_date: Optional[str] = None) -> Optional[int]:
    """Lưu bài viết thô với cơ chế khử trùng lặp qua MD5 của URL"""
    url_hash = hashlib.md5(source_url.strip().encode("utf-8")).hexdigest()
    source_id = f"{source_name.lower()}-{url_hash[:8]}"
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
        INSERT INTO raw_threat_articles (source_id, source_name, source_url, url_hash, title, raw_content, published_date)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (source_id, source_name, source_url, url_hash, title, raw_content, published_date or datetime.utcnow().isoformat()))
        conn.commit()
        article_id = cursor.lastrowid
        return article_id
    except sqlite3.IntegrityError:
        # Bài viết đã tồn tại (khử trùng lặp thành công)
        cursor.execute("SELECT id FROM raw_threat_articles WHERE url_hash = ?", (url_hash,))
        row = cursor.fetchone()
        return row["id"] if row else None
    finally:
        conn.close()

def get_all_articles(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, source_id, source_name, source_url, title, raw_content, published_date, is_analyzed, created_at
    FROM raw_threat_articles
    ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    articles = [dict(row) for row in rows]
    conn.close()
    return articles

def get_article_by_id(article_id: int) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM raw_threat_articles WHERE id = ?", (article_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def mark_article_analyzed(article_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE raw_threat_articles SET is_analyzed = 1 WHERE id = ?", (article_id,))
    conn.commit()
    conn.close()

def save_threat_report(report_data: Dict[str, Any]) -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO threat_reports (
        report_id, article_id, title, executive_summary, threat_actors, targeted_sectors,
        extracted_iocs_json, mitre_matrix_json, sigma_rule, yara_rule, firewall_blocklist, stix_bundle_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        report_data.get("report_id"),
        report_data.get("article_id"),
        report_data.get("title"),
        report_data.get("executive_summary"),
        json.dumps(report_data.get("threat_actors", []), ensure_ascii=False),
        json.dumps(report_data.get("targeted_sectors", []), ensure_ascii=False),
        json.dumps(report_data.get("enriched_iocs", []), ensure_ascii=False),
        json.dumps(report_data.get("mitre_attack_matrix", []), ensure_ascii=False),
        report_data.get("defensive_rules", {}).get("sigma_rule", ""),
        report_data.get("defensive_rules", {}).get("yara_rule", ""),
        json.dumps(report_data.get("defensive_rules", {}).get("firewall_blocklist", []), ensure_ascii=False),
        json.dumps(report_data.get("stix_json", {}), ensure_ascii=False)
    ))
    conn.commit()
    report_pk = cursor.lastrowid
    conn.close()
    return report_pk

def get_all_reports(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threat_reports ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    reports = [dict(row) for row in rows]
    conn.close()
    return reports

def get_report_by_id(report_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threat_reports WHERE report_id = ?", (report_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_system_stats() -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as count FROM raw_threat_articles")
    total_articles = cursor.fetchone()["count"]
    
    cursor.execute("SELECT COUNT(*) as count FROM raw_threat_articles WHERE is_analyzed = 1")
    analyzed_articles = cursor.fetchone()["count"]
    
    cursor.execute("SELECT COUNT(*) as count FROM threat_reports")
    total_reports = cursor.fetchone()["count"]
    
    cursor.execute("SELECT COUNT(*) as count FROM ioc_reputation_cache")
    cached_iocs = cursor.fetchone()["count"]
    conn.close()
    
    return {
        "total_articles": total_articles,
        "analyzed_articles": analyzed_articles,
        "total_reports": total_reports,
        "cached_iocs": cached_iocs,
        "active_sources": ["CISA KEV", "The Hacker News", "BleepingComputer", "NVD"]
    }
