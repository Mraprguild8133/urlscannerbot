#!/usr/bin/env python3
"""
Telegram Security Bot - Main Entry Point
Real-time URL threat analysis using URLScan.io and Cloudflare Radar APIs
"""

import os
import sys
import time
import signal
import threading
from typing import Optional

import telebot
from telebot import apihelper
from telebot.types import Message, CallbackQuery

# Enable middleware for the bot
apihelper.ENABLE_MIDDLEWARE = True

from config import Config
from database import Database
from utils.logger import setup_logger
from handlers.message_handler import MessageHandler
from handlers.admin_handler import AdminHandler
from services.url_scanner import URLScanner
from services.cloudflare_radar import CloudflareRadar
from services.admin_manager import AdminManager
from services.threat_analyzer import ThreatAnalyzer


class TelegramSecurityBot:
    """Main bot class that orchestrates all components"""
    
    def __init__(self):
        self.logger = setup_logger(__name__)
        self.config = Config()
        self.running = True
        
        # Validate critical configuration
        self._validate_config()
        
        # Initialize bot
        self.bot = telebot.TeleBot(
            self.config.TELEGRAM_BOT_TOKEN,
            parse_mode='HTML',
            threaded=True
        )
        
        # Initialize database
        self.db = Database()
        
        # Initialize services
        self.url_scanner = URLScanner(self.config.URLSCAN_API_KEY)
        self.cloudflare_radar = CloudflareRadar(self.config.CLOUDFLARE_API_KEY)
        self.admin_manager = AdminManager(self.db)
        self.threat_analyzer = ThreatAnalyzer(self.url_scanner, self.cloudflare_radar, self.db)
        
        # Initialize handlers
        self.message_handler = MessageHandler(self.bot, self.threat_analyzer, self.admin_manager, self.db)
        self.admin_handler = AdminHandler(self.bot, self.admin_manager, self.db)
        
        # Setup bot handlers
        self._setup_handlers()
        
        # Setup signal handlers for graceful shutdown
        self._setup_signal_handlers()
        
        self.logger.info("🤖 Telegram Security Bot initialized successfully")

    def _validate_config(self):
        """Validate critical configuration values"""
        if not self.config.TELEGRAM_BOT_TOKEN or self.config.TELEGRAM_BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
            self.logger.error("❌ Telegram bot token not configured")
            sys.exit(1)
            
        if not self.config.URLSCAN_API_KEY or self.config.URLSCAN_API_KEY == "YOUR_URLSCAN_API_KEY_HERE":
            self.logger.warning("⚠️ URLScan API key not configured - URL scanning will be limited")
            
        if not self.config.CLOUDFLARE_API_KEY or self.config.CLOUDFLARE_API_KEY == "YOUR_CLOUDFLARE_API_KEY_HERE":
            self.logger.warning("⚠️ Cloudflare API key not configured - Some features will be limited")

    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        if sys.platform != "win32":
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        else:
            # Windows compatibility
            try:
                import win32api
                win32api.SetConsoleCtrlHandler(self._windows_signal_handler, True)
            except ImportError:
                self.logger.warning("Windows signal handling not available - install pywin32 for proper shutdown handling")

    def _windows_signal_handler(self, sig):
        """Signal handler for Windows"""
        if sig in (0, 2):  # CTRL_C_EVENT, CTRL_BREAK_EVENT
            self._signal_handler(sig, None)
            return True
        return False

    # ---------------- BOT HANDLERS ----------------
    def _setup_handlers(self):
        """Setup all bot message and callback handlers"""
        
        # Command handlers
        @self.bot.message_handler(commands=['start', 'help'])
        def handle_start_help(message: Message):
            if message.text.startswith('/start'):
                self.message_handler.handle_start(message)
            else:
                self.message_handler.handle_help(message)

        @self.bot.message_handler(commands=['scan'])
        def handle_manual_scan(message: Message):
            self.message_handler.handle_manual_scan(message)

        @self.bot.message_handler(commands=['stats'])
        def handle_stats(message: Message):
            self.message_handler.handle_stats(message)

        @self.bot.message_handler(commands=['settings'])
        def handle_settings(message: Message):
            self.message_handler.handle_settings(message)

        # Admin commands
        @self.bot.message_handler(commands=['admin'])
        def handle_admin(message: Message):
            self.admin_handler.handle_admin(message)

        @self.bot.message_handler(commands=['addadmin'])
        def handle_add_admin(message: Message):
            self.admin_handler.handle_add_admin(message)

        @self.bot.message_handler(commands=['removeadmin'])
        def handle_remove_admin(message: Message):
            self.admin_handler.handle_remove_admin(message)

        @self.bot.message_handler(commands=['ban'])
        def handle_ban(message: Message):
            self.admin_handler.handle_ban(message)

        @self.bot.message_handler(commands=['unban'])
        def handle_unban(message: Message):
            self.admin_handler.handle_unban(message)

        @self.bot.message_handler(commands=['whitelist'])
        def handle_whitelist(message: Message):
            self.admin_handler.handle_whitelist(message)

        @self.bot.message_handler(commands=['blacklist'])
        def handle_blacklist(message: Message):
            self.admin_handler.handle_blacklist(message)

        @self.bot.message_handler(commands=['threshold'])
        def handle_threshold(message: Message):
            self.admin_handler.handle_threshold(message)

        # Auto URL scanning for all text messages
        @self.bot.message_handler(func=lambda message: True, content_types=['text'])
        def handle_text(message: Message):
            self.message_handler.handle_text_message(message)

        # Callback query handlers
        @self.bot.callback_query_handler(func=lambda call: True)
        def handle_callback(call: CallbackQuery):
            self.message_handler.handle_callback(call)

    # ---------------- SIGNALS ----------------
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        self.logger.info(f"Received signal {signum}. Shutting down gracefully...")
        self.running = False
        self.bot.stop_polling()

    # ---------------- HEALTH CHECK ----------------
    def _health_check(self):
        """Periodic health check and restart if needed"""
        check_interval = 300  # 5 minutes
        
        while self.running:
            try:
                time.sleep(check_interval)
                
                # Check bot API connectivity
                self.bot.get_me()
                
                # Check database connectivity if available
                if hasattr(self.db, 'health_check'):
                    self.db.health_check()
                
                self.logger.info("🟢 Bot health check passed")
                
            except Exception as e:
                self.logger.error(f"🔴 Bot health check failed: {e}")
                if self.running:
                    self.logger.info("Attempting to restart bot polling...")
                    try:
                        self.start_polling()
                    except Exception as restart_error:
                        self.logger.error(f"Failed to restart bot: {restart_error}")

    # ---------------- POLLING ----------------
    def start_polling(self):
        """Start bot polling with error recovery"""
        max_retries = 5
        retry_delay = 10
        
        for attempt in range(max_retries):
            try:
                self.logger.info(f"🚀 Starting bot polling (attempt {attempt+1}/{max_retries})")
                
                # Start health check thread
                health_thread = threading.Thread(target=self._health_check, daemon=True)
                health_thread.start()
                
                # Start polling
                self.bot.infinity_polling(
                    timeout=30,
                    long_polling_timeout=30,
                    skip_pending=True,
                    none_stop=True,
                    restart_on_change=True
                )
                break
            except Exception as e:
                self.logger.error(f"Polling attempt {attempt+1} failed: {e}")
                if attempt < max_retries - 1:
                    self.logger.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2
                else:
                    self.logger.error("Max retries reached. Bot failed to start.")
                    raise

    def run(self):
        """Main run method"""
        try:
            self.logger.info("🔐 Telegram Security Bot starting up...")
            
            # Start bot polling
            self.start_polling()

        except KeyboardInterrupt:
            self.logger.info("Bot stopped by user")
        except Exception as e:
            self.logger.error(f"Fatal error: {e}")
            raise
        finally:
            self.running = False
            if hasattr(self, 'db'):
                self.db.close()
            self.logger.info("🛑 Bot shutdown complete")


def main():
    """Main entry point"""
    try:
        bot = TelegramSecurityBot()
        bot.run()
    except Exception as e:
        logger = setup_logger(__name__)
        logger.error(f"Failed to start bot: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
