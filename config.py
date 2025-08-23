"""
Configuration module for Telegram Security Bot
Handles environment variables and bot settings
"""

import os
from typing import List, Dict, Any

class Config:
    """Configuration class with environment variable handling"""
    
    def __init__(self):
        # API Keys from environment variables
        self.TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
        self.CLOUDFLARE_API_KEY = os.getenv("CLOUDFLARE_API_KEY", "")
        self.CLOUDFLARE_ACCOUNT_ID = os.getenv("CLOUDFLARE_ACCOUNT_ID", "")
        
        # Database configuration
        self.DATABASE_PATH = os.getenv("DATABASE_PATH", "security_bot.db")
        
        # Bot settings
        self.DEFAULT_THREAT_THRESHOLD = int(os.getenv("THREAT_THRESHOLD", "50"))  # 0-100 scale
        self.AUTO_SCAN_ENABLED = os.getenv("AUTO_SCAN_ENABLED", "true").lower() == "true"
        self.SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "60"))  # seconds
        self.MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "5"))
        
        # Rate limiting settings
        self.URLSCAN_RATE_LIMIT = int(os.getenv("URLSCAN_RATE_LIMIT", "10"))  # requests per minute
        self.CLOUDFLARE_RATE_LIMIT = int(os.getenv("CLOUDFLARE_RATE_LIMIT", "100"))  # requests per minute
        
        # Admin settings
        self.SUPER_ADMIN_ID = os.getenv("SUPER_ADMIN_ID")  # Optional super admin user ID
        
        # Logging configuration
        self.LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
        self.LOG_FILE = os.getenv("LOG_FILE", "security_bot.log")
        self.LOG_MAX_SIZE = int(os.getenv("LOG_MAX_SIZE", "10485760"))  # 10MB
        self.LOG_BACKUP_COUNT = int(os.getenv("LOG_BACKUP_COUNT", "5"))
        
        # Server settings
        self.HOST = os.getenv("HOST", "0.0.0.0")
        self.PORT = int(os.getenv("PORT", "8000"))
        
        # Validation
        self._validate_config()
    
    def _validate_config(self):
        """Validate required configuration parameters"""
        required_vars = [
            ("TELEGRAM_BOT_TOKEN", self.TELEGRAM_BOT_TOKEN),
        ]
        
        missing_vars = [var_name for var_name, var_value in required_vars if not var_value]
        
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
        
        # Warn about missing optional API keys
        optional_vars = [
            ("URLSCAN_API_KEY", self.URLSCAN_API_KEY),
            ("CLOUDFLARE_API_KEY", self.CLOUDFLARE_API_KEY),
        ]
        
        for var_name, var_value in optional_vars:
            if not var_value:
                print(f"⚠️ Warning: {var_name} not set - some features will be limited")
    
    @property
    def has_urlscan_api(self) -> bool:
        """Check if URLScan API key is available"""
        return bool(self.URLSCAN_API_KEY)
    
    @property
    def has_cloudflare_api(self) -> bool:
        """Check if Cloudflare API key is available"""
        return bool(self.CLOUDFLARE_API_KEY)
    
    def get_bot_info(self) -> Dict[str, Any]:
        """Get bot configuration summary"""
        return {
            "auto_scan_enabled": self.AUTO_SCAN_ENABLED,
            "threat_threshold": self.DEFAULT_THREAT_THRESHOLD,
            "urlscan_available": self.has_urlscan_api,
            "cloudflare_available": self.has_cloudflare_api,
            "scan_timeout": self.SCAN_TIMEOUT,
            "max_concurrent_scans": self.MAX_CONCURRENT_SCANS
        }
