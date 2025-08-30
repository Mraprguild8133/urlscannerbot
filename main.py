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
import atexit
from typing import Optional

import telebot
from telebot import apihelper
from telebot.types import Message, CallbackQuery

from flask import Flask, render_template

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
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(TelegramSecurityBot, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self.logger = setup_logger(__name__)
        self.config = Config()
        self.running = False
        self.polling_thread = None
        self.health_thread = None
        
        # Initialize bot
        self.bot = telebot.TeleBot(
            self.config.TELEGRAM_BOT_TOKEN,
            parse_mode='HTML',
            threaded=True,
            num_threads=4
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
        
        # Register cleanup
        atexit.register(self.cleanup)
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        self._initialized = True
        self.logger.info("🤖 Telegram Security Bot initialized successfully")

    # ---------------- BOT HANDLERS ----------------
    def _setup_handlers(self):
        """Setup all bot message and callback handlers"""
        
        # Command handlers
        @self.bot.message_handler(commands=['start'])
        def handle_start(message: Message):
            self.message_handler.handle_start(message)

        @self.bot.message_handler(commands=['help'])
        def handle_help(message: Message):
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
        self.cleanup()

    # ---------------- HEALTH CHECK ----------------
    def _health_check(self):
        """Periodic health check"""
        while self.running:
            try:
                time.sleep(300)  # Check every 5 minutes
                self.bot.get_me()
                self.logger.debug("🟢 Bot health check passed")
            except Exception as e:
                self.logger.error(f"🔴 Bot health check failed: {e}")
                # Don't try to restart automatically to avoid conflicts
                # Just log the error and continue

    # ---------------- POLLING ----------------
    def _polling_worker(self):
        """Worker thread for bot polling"""
        max_retries = 5
        retry_delay = 10
        
        for attempt in range(max_retries):
            try:
                if not self.running:
                    break
                    
                self.logger.info(f"🚀 Starting bot polling (attempt {attempt+1}/{max_retries})")
                
                # Start polling with a specific allowed_update
                self.bot.infinity_polling(
                    timeout=30,
                    long_polling_timeout=30,
                    skip_pending=True,
                    none_stop=True,
                    allowed_updates=["message", "callback_query"]
                )
                break
            except Exception as e:
                self.logger.error(f"Polling attempt {attempt+1} failed: {e}")
                if attempt < max_retries - 1 and self.running:
                    self.logger.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2
                else:
                    self.logger.error("Max retries reached. Bot failed to start.")
                    self.running = False
                    break

    def start(self):
        """Start the bot"""
        if self.running:
            self.logger.warning("Bot is already running")
            return False
            
        try:
            self.running = True
            
            # Start health check thread
            self.health_thread = threading.Thread(target=self._health_check, daemon=True)
            self.health_thread.start()
            
            # Start polling in a separate thread
            self.polling_thread = threading.Thread(target=self._polling_worker, daemon=True)
            self.polling_thread.start()
            
            self.logger.info("🔐 Telegram Security Bot started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start bot: {e}")
            self.running = False
            return False

    def stop(self):
        """Stop the bot"""
        self.logger.info("Stopping bot...")
        self.running = False
        try:
            self.bot.stop_polling()
        except:
            pass  # Ignore errors when stopping

    def cleanup(self):
        """Cleanup resources"""
        self.stop()
        if hasattr(self, 'db'):
            self.db.close()
        self.logger.info("🛑 Bot cleanup complete")

    def is_running(self):
        """Check if bot is running"""
        return self.running and self.polling_thread and self.polling_thread.is_alive()


def create_flask_app():
    """Create and configure Flask application"""
    app = Flask(__name__, template_folder="templates")
    
    # Try to get bot instance
    bot_instance = None
    try:
        bot_instance = TelegramSecurityBot()
    except Exception as e:
        print(f"Could not initialize bot: {e}")
    
    @app.route("/")
    def index():
        return render_template("base.html")
    
    @app.route("/health")
def health_check():
    try:
        if bot_instance and bot_instance.is_running():
            return {
                "status": "healthy",
                "bot": "running",
                "last_check": time.strftime("%Y-%m-%d %H:%M:%S"),
                "threads": threading.active_count(),
                "database": "connected" if bot_instance.db.is_connected() else "error",
                "api_keys": "✅ Loaded" if bot_instance.config.URLSCAN_API_KEY and bot_instance.config.CLOUDFLARE_API_KEY else "⚠️ Missing"
            }, 200
        return {
            "status": "unhealthy",
            "bot": "stopped",
            "last_check": time.strftime("%Y-%m-%d %H:%M:%S"),
            "threads": threading.active_count(),
            "database": "error",
            "api_keys": "⚠️ Missing"
        }, 503
    except Exception as e:
        return {"status": "error", "message": str(e)}, 500
    
    @app.route("/start_bot")
    def start_bot():
        if not bot_instance:
            return {"status": "error", "message": "Bot not initialized"}, 500
            
        if bot_instance.is_running():
            return {"status": "already_running", "message": "Bot is already running"}, 200
            
        if bot_instance.start():
            return {"status": "started", "message": "Bot started successfully"}, 200
        else:
            return {"status": "error", "message": "Failed to start bot"}, 500
    
    @app.route("/stop_bot")
    def stop_bot():
        if not bot_instance:
            return {"status": "error", "message": "Bot not initialized"}, 500
            
        bot_instance.stop()
        return {"status": "stopped", "message": "Bot stopped successfully"}, 200
    
    return app


def main():
    """Main entry point"""
    logger = setup_logger(__name__)
    
    try:
        # Initialize the bot (but don't start it yet)
        bot = TelegramSecurityBot()
        
        # Start the bot
        if not bot.start():
            logger.error("Failed to start bot. Exiting.")
            return 1
        
        # Create and run Flask app
        app = create_flask_app()
        port = int(os.getenv("PORT", 5000))
        
        logger.info(f"🌐 Web server starting on port {port}")
        app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
