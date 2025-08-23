"""
Database module for Telegram Security Bot
Handles SQLite database operations for scan results, settings, and admin data
"""

import sqlite3
import json
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from contextlib import contextmanager

from utils.logger import setup_logger

class Database:
    """Database manager for bot data persistence"""
    
    def __init__(self, db_path: str = "security_bot.db"):
        self.db_path = db_path
        self.logger = setup_logger(__name__)
        self._lock = threading.Lock()
        
        # Initialize database
        self._init_database()
        
        self.logger.info(f"📁 Database initialized: {db_path}")
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            self.logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def _init_database(self):
        """Initialize database tables"""
        with self.get_connection() as conn:
            # URL scan results table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS url_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    message_id INTEGER,
                    url TEXT NOT NULL,
                    scan_uuid TEXT,
                    urlscan_verdict INTEGER,
                    cloudflare_verdict TEXT,
                    threat_score INTEGER,
                    is_malicious BOOLEAN DEFAULT FALSE,
                    scan_result TEXT,  -- JSON data
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Chat settings table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chat_settings (
                    chat_id INTEGER PRIMARY KEY,
                    auto_scan_enabled BOOLEAN DEFAULT TRUE,
                    threat_threshold INTEGER DEFAULT 50,
                    alert_admins BOOLEAN DEFAULT TRUE,
                    delete_malicious BOOLEAN DEFAULT FALSE,
                    whitelist TEXT DEFAULT '[]',  -- JSON array of domains
                    blacklist TEXT DEFAULT '[]',  -- JSON array of domains
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Admin management table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chat_admins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    username TEXT,
                    permissions TEXT DEFAULT '[]',  -- JSON array of permissions
                    added_by INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(chat_id, user_id)
                )
            """)
            
            # Banned users table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS banned_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    username TEXT,
                    reason TEXT,
                    banned_by INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(chat_id, user_id)
                )
            """)
            
            # Bot statistics table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS bot_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date DATE NOT NULL,
                    urls_scanned INTEGER DEFAULT 0,
                    threats_detected INTEGER DEFAULT 0,
                    chats_active INTEGER DEFAULT 0,
                    UNIQUE(date)
                )
            """)
            
            # Create indexes for better performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_url_scans_chat_id ON url_scans(chat_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_url_scans_created_at ON url_scans(created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_chat_settings_chat_id ON chat_settings(chat_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_chat_admins_chat_user ON chat_admins(chat_id, user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_banned_users_chat_user ON banned_users(chat_id, user_id)")
            
            conn.commit()
    
    # URL Scan Methods
    def save_url_scan(self, chat_id: int, user_id: int, message_id: int, url: str,
                     scan_uuid: Optional[str] = None, urlscan_verdict: Optional[int] = None,
                     cloudflare_verdict: Optional[str] = None, threat_score: Optional[int] = None,
                     is_malicious: bool = False, scan_result: Optional[Dict] = None) -> int:
        """Save URL scan result to database"""
        with self._lock, self.get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO url_scans 
                (chat_id, user_id, message_id, url, scan_uuid, urlscan_verdict, 
                 cloudflare_verdict, threat_score, is_malicious, scan_result)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                chat_id, user_id, message_id, url, scan_uuid, urlscan_verdict,
                cloudflare_verdict, threat_score, is_malicious,
                json.dumps(scan_result) if scan_result else None
            ))
            conn.commit()
            return cursor.lastrowid or 0
    
    def update_url_scan(self, scan_id: int, **kwargs):
        """Update existing URL scan record"""
        if not kwargs:
            return
        
        # Convert scan_result to JSON if present
        if 'scan_result' in kwargs and kwargs['scan_result'] is not None:
            kwargs['scan_result'] = json.dumps(kwargs['scan_result'])
        
        # Build dynamic update query
        set_clause = ", ".join([f"{key} = ?" for key in kwargs.keys()])
        values = list(kwargs.values()) + [scan_id]
        
        with self._lock, self.get_connection() as conn:
            conn.execute(f"""
                UPDATE url_scans 
                SET {set_clause}, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, values)
            conn.commit()
    
    def get_url_scan(self, scan_id: int) -> Optional[Dict]:
        """Get URL scan by ID"""
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM url_scans WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            
            if row:
                result = dict(row)
                if result['scan_result']:
                    result['scan_result'] = json.loads(result['scan_result'])
                return result
            return None
    
    def get_recent_scans(self, chat_id: int, hours: int = 24, limit: int = 50) -> List[Dict]:
        """Get recent URL scans for a chat"""
        since = datetime.now() - timedelta(hours=hours)
        
        with self.get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM url_scans 
                WHERE chat_id = ? AND created_at > ?
                ORDER BY created_at DESC 
                LIMIT ?
            """, (chat_id, since, limit))
            
            results = []
            for row in cursor.fetchall():
                result = dict(row)
                if result['scan_result']:
                    result['scan_result'] = json.loads(result['scan_result'])
                results.append(result)
            return results
    
    # Chat Settings Methods
    def get_chat_settings(self, chat_id: int) -> Dict:
        """Get chat settings, create defaults if not exist"""
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM chat_settings WHERE chat_id = ?", (chat_id,))
            row = cursor.fetchone()
            
            if row:
                result = dict(row)
                result['whitelist'] = json.loads(result['whitelist'])
                result['blacklist'] = json.loads(result['blacklist'])
                return result
            else:
                # Create default settings
                self.update_chat_settings(chat_id)
                return self.get_chat_settings(chat_id)
    
    def update_chat_settings(self, chat_id: int, **kwargs):
        """Update chat settings"""
        # Convert lists to JSON if present
        if 'whitelist' in kwargs:
            kwargs['whitelist'] = json.dumps(kwargs['whitelist'])
        if 'blacklist' in kwargs:
            kwargs['blacklist'] = json.dumps(kwargs['blacklist'])
        
        with self._lock, self.get_connection() as conn:
            # Use INSERT OR REPLACE to handle both insert and update
            conn.execute("""
                INSERT OR REPLACE INTO chat_settings 
                (chat_id, auto_scan_enabled, threat_threshold, alert_admins, 
                 delete_malicious, whitelist, blacklist, updated_at)
                VALUES (
                    ?, 
                    COALESCE(?, (SELECT auto_scan_enabled FROM chat_settings WHERE chat_id = ?), TRUE),
                    COALESCE(?, (SELECT threat_threshold FROM chat_settings WHERE chat_id = ?), 50),
                    COALESCE(?, (SELECT alert_admins FROM chat_settings WHERE chat_id = ?), TRUE),
                    COALESCE(?, (SELECT delete_malicious FROM chat_settings WHERE chat_id = ?), FALSE),
                    COALESCE(?, (SELECT whitelist FROM chat_settings WHERE chat_id = ?), '[]'),
                    COALESCE(?, (SELECT blacklist FROM chat_settings WHERE chat_id = ?), '[]'),
                    CURRENT_TIMESTAMP
                )
            """, (
                chat_id,
                kwargs.get('auto_scan_enabled'), chat_id,
                kwargs.get('threat_threshold'), chat_id,
                kwargs.get('alert_admins'), chat_id,
                kwargs.get('delete_malicious'), chat_id,
                kwargs.get('whitelist'), chat_id,
                kwargs.get('blacklist'), chat_id
            ))
            conn.commit()
    
    # Admin Management Methods
    def add_chat_admin(self, chat_id: int, user_id: int, username: Optional[str] = None,
                      permissions: Optional[List[str]] = None, added_by: Optional[int] = None) -> bool:
        """Add chat admin"""
        permissions = permissions or []
        
        with self._lock, self.get_connection() as conn:
            try:
                conn.execute("""
                    INSERT INTO chat_admins (chat_id, user_id, username, permissions, added_by)
                    VALUES (?, ?, ?, ?, ?)
                """, (chat_id, user_id, username, json.dumps(permissions), added_by))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                # Admin already exists, update instead
                conn.execute("""
                    UPDATE chat_admins 
                    SET username = ?, permissions = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE chat_id = ? AND user_id = ?
                """, (username, json.dumps(permissions), chat_id, user_id))
                conn.commit()
                return True
    
    def remove_chat_admin(self, chat_id: int, user_id: int) -> bool:
        """Remove chat admin"""
        with self._lock, self.get_connection() as conn:
            cursor = conn.execute("""
                DELETE FROM chat_admins 
                WHERE chat_id = ? AND user_id = ?
            """, (chat_id, user_id))
            conn.commit()
            return cursor.rowcount > 0
    
    def is_chat_admin(self, chat_id: int, user_id: int) -> bool:
        """Check if user is admin in chat"""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                SELECT 1 FROM chat_admins 
                WHERE chat_id = ? AND user_id = ?
            """, (chat_id, user_id))
            return cursor.fetchone() is not None
    
    def get_chat_admins(self, chat_id: int) -> List[Dict]:
        """Get all admins for a chat"""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM chat_admins WHERE chat_id = ?
                ORDER BY created_at ASC
            """, (chat_id,))
            
            results = []
            for row in cursor.fetchall():
                result = dict(row)
                result['permissions'] = json.loads(result['permissions'])
                results.append(result)
            return results
    
    # Ban Management Methods
    def ban_user(self, chat_id: int, user_id: int, username: Optional[str] = None,
                reason: Optional[str] = None, banned_by: Optional[int] = None) -> bool:
        """Ban user from chat"""
        with self._lock, self.get_connection() as conn:
            try:
                conn.execute("""
                    INSERT INTO banned_users (chat_id, user_id, username, reason, banned_by)
                    VALUES (?, ?, ?, ?, ?)
                """, (chat_id, user_id, username, reason, banned_by))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False  # Already banned
    
    def unban_user(self, chat_id: int, user_id: int) -> bool:
        """Unban user from chat"""
        with self._lock, self.get_connection() as conn:
            cursor = conn.execute("""
                DELETE FROM banned_users 
                WHERE chat_id = ? AND user_id = ?
            """, (chat_id, user_id))
            conn.commit()
            return cursor.rowcount > 0
    
    def is_user_banned(self, chat_id: int, user_id: int) -> bool:
        """Check if user is banned in chat"""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                SELECT 1 FROM banned_users 
                WHERE chat_id = ? AND user_id = ?
            """, (chat_id, user_id))
            return cursor.fetchone() is not None
    
    # Statistics Methods
    def update_daily_stats(self, urls_scanned: int = 0, threats_detected: int = 0, chats_active: int = 0):
        """Update daily statistics"""
        today = datetime.now().date()
        
        with self._lock, self.get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO bot_stats (date, urls_scanned, threats_detected, chats_active)
                VALUES (
                    ?,
                    COALESCE((SELECT urls_scanned FROM bot_stats WHERE date = ?), 0) + ?,
                    COALESCE((SELECT threats_detected FROM bot_stats WHERE date = ?), 0) + ?,
                    COALESCE(?, (SELECT chats_active FROM bot_stats WHERE date = ?), 0)
                )
            """, (today, today, urls_scanned, today, threats_detected, chats_active, today))
            conn.commit()
    
    def get_stats(self, days: int = 7) -> Dict:
        """Get bot statistics for specified days"""
        since = datetime.now().date() - timedelta(days=days)
        
        with self.get_connection() as conn:
            # Get aggregated stats
            cursor = conn.execute("""
                SELECT 
                    SUM(urls_scanned) as total_urls_scanned,
                    SUM(threats_detected) as total_threats_detected,
                    MAX(chats_active) as max_chats_active,
                    COUNT(*) as days_with_data
                FROM bot_stats 
                WHERE date >= ?
            """, (since,))
            row = cursor.fetchone()
            
            # Get daily breakdown
            cursor = conn.execute("""
                SELECT * FROM bot_stats 
                WHERE date >= ?
                ORDER BY date ASC
            """, (since,))
            daily_stats = [dict(row) for row in cursor.fetchall()]
            
            return {
                'total_urls_scanned': row['total_urls_scanned'] or 0,
                'total_threats_detected': row['total_threats_detected'] or 0,
                'max_chats_active': row['max_chats_active'] or 0,
                'days_with_data': row['days_with_data'] or 0,
                'daily_breakdown': daily_stats
            }
    
    def cleanup_old_data(self, days: int = 30):
        """Clean up old scan results and stats"""
        cutoff = datetime.now() - timedelta(days=days)
        
        with self._lock, self.get_connection() as conn:
            # Clean old URL scans
            cursor = conn.execute("DELETE FROM url_scans WHERE created_at < ?", (cutoff,))
            scans_deleted = cursor.rowcount
            
            # Clean old stats (keep more stats data, clean after 90 days)
            stats_cutoff = datetime.now().date() - timedelta(days=90)
            cursor = conn.execute("DELETE FROM bot_stats WHERE date < ?", (stats_cutoff,))
            stats_deleted = cursor.rowcount
            
            conn.commit()
            
            if scans_deleted > 0 or stats_deleted > 0:
                self.logger.info(f"🧹 Cleaned up {scans_deleted} old scans and {stats_deleted} old stats")
