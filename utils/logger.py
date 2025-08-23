"""
Logging utility for Telegram Security Bot
Provides centralized logging configuration
"""

import logging
import logging.handlers
import os
from datetime import datetime
from typing import Optional

def setup_logger(name: str, level: Optional[str] = None, 
                log_file: Optional[str] = None) -> logging.Logger:
    """
    Setup logger with file and console handlers
    
    Args:
        name: Logger name
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Log file path
    
    Returns:
        Configured logger instance
    """
    # Get configuration from environment or defaults
    log_level = level or os.getenv('LOG_LEVEL', 'INFO').upper()
    log_file = log_file or os.getenv('LOG_FILE', 'security_bot.log')
    max_size = int(os.getenv('LOG_MAX_SIZE', '10485760'))  # 10MB
    backup_count = int(os.getenv('LOG_BACKUP_COUNT', '5'))
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level))
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        fmt='%(asctime)s | %(name)s | %(levelname)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    simple_formatter = logging.Formatter(
        fmt='%(levelname)s | %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(simple_formatter)
    logger.addHandler(console_handler)
    
    # File handler with rotation
    if log_file:
        try:
            # Create log directory if it doesn't exist
            log_dir = os.path.dirname(log_file) if os.path.dirname(log_file) else '.'
            os.makedirs(log_dir, exist_ok=True)
            
            file_handler = logging.handlers.RotatingFileHandler(
                filename=log_file,
                maxBytes=max_size,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setLevel(getattr(logging, log_level))
            file_handler.setFormatter(detailed_formatter)
            logger.addHandler(file_handler)
            
        except Exception as e:
            logger.warning(f"Could not setup file logging: {e}")
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger

def log_bot_startup():
    """Log bot startup information"""
    logger = setup_logger('startup')
    
    logger.info("=" * 60)
    logger.info("🤖 TELEGRAM SECURITY BOT STARTING UP")
    logger.info("=" * 60)
    logger.info(f"⏰ Startup time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    import sys
    logger.info(f"🐍 Python version: {sys.version}")
    logger.info(f"📁 Working directory: {os.getcwd()}")
    logger.info(f"🔑 Environment variables loaded:")
    
    # Log (sanitized) environment variables
    env_vars = [
        'TELEGRAM_BOT_TOKEN',
        'URLSCAN_API_KEY', 
        'CLOUDFLARE_API_KEY',
        'CLOUDFLARE_ACCOUNT_ID',
        'DATABASE_PATH',
        'LOG_LEVEL',
        'HOST',
        'PORT'
    ]
    
    for var in env_vars:
        value = os.getenv(var)
        if value:
            if 'TOKEN' in var or 'KEY' in var:
                # Sanitize sensitive values
                sanitized = f"{value[:8]}...{value[-4:]}" if len(value) > 12 else "***"
                logger.info(f"   {var}: {sanitized}")
            else:
                logger.info(f"   {var}: {value}")
        else:
            logger.warning(f"   {var}: NOT SET")
    
    logger.info("=" * 60)

def log_bot_shutdown():
    """Log bot shutdown information"""
    logger = setup_logger('shutdown')
    
    logger.info("=" * 60)
    logger.info("🛑 TELEGRAM SECURITY BOT SHUTTING DOWN")
    logger.info("=" * 60)
    logger.info(f"⏰ Shutdown time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("👋 Goodbye!")
    logger.info("=" * 60)

class BotLogger:
    """Enhanced logger class with bot-specific methods"""
    
    def __init__(self, name: str):
        self.logger = setup_logger(name)
        self.name = name
    
    def log_user_action(self, user_id: int, username: str, chat_id: int, 
                       action: str, details: str = ""):
        """Log user actions with context"""
        context = f"User {user_id} (@{username}) in chat {chat_id}"
        message = f"{action}"
        if details:
            message += f" | {details}"
        
        self.logger.info(f"👤 {context} | {message}")
    
    def log_admin_action(self, admin_id: int, admin_username: str, chat_id: int,
                        action: str, target_user: Optional[int] = None, details: str = ""):
        """Log admin actions"""
        context = f"Admin {admin_id} (@{admin_username}) in chat {chat_id}"
        message = f"{action}"
        
        if target_user:
            message += f" | Target: {target_user}"
        if details:
            message += f" | {details}"
        
        self.logger.warning(f"👨‍💼 {context} | {message}")
    
    def log_url_scan(self, url: str, chat_id: int, user_id: int, 
                    threat_score: int, is_malicious: bool):
        """Log URL scan results"""
        status = "🔴 MALICIOUS" if is_malicious else "🟢 SAFE"
        self.logger.info(
            f"🔍 URL Scan | {status} | Score: {threat_score}/100 | "
            f"URL: {url} | User: {user_id} | Chat: {chat_id}"
        )
    
    def log_api_call(self, service: str, endpoint: str, status_code: int, 
                    response_time: float = 0):
        """Log API calls"""
        status = "✅" if 200 <= status_code < 300 else "❌"
        self.logger.debug(
            f"🌐 API Call | {status} {service} | {endpoint} | "
            f"Status: {status_code} | Time: {response_time:.2f}s"
        )
    
    def log_error(self, error: Exception, context: str = ""):
        """Log errors with context"""
        error_msg = f"💥 ERROR | {type(error).__name__}: {str(error)}"
        if context:
            error_msg += f" | Context: {context}"
        
        self.logger.error(error_msg)
    
    def log_rate_limit(self, service: str, limit_type: str = ""):
        """Log rate limiting events"""
        message = f"⏱️ RATE LIMITED | Service: {service}"
        if limit_type:
            message += f" | Type: {limit_type}"
        
        self.logger.warning(message)
    
    def log_security_event(self, event_type: str, user_id: int, chat_id: int, 
                          details: str):
        """Log security-related events"""
        self.logger.warning(
            f"🛡️ SECURITY EVENT | {event_type} | "
            f"User: {user_id} | Chat: {chat_id} | {details}"
        )
    
    def debug(self, message: str):
        """Debug logging"""
        self.logger.debug(message)
    
    def info(self, message: str):
        """Info logging"""
        self.logger.info(message)
    
    def warning(self, message: str):
        """Warning logging"""
        self.logger.warning(message)
    
    def error(self, message: str):
        """Error logging"""
        self.logger.error(message)
    
    def critical(self, message: str):
        """Critical logging"""
        self.logger.critical(message)
