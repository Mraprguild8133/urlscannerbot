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
        if sys.platform != "win32":
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        
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
        self.bot.stop_polling()

    # ---------------- HEALTH CHECK ----------------
    def _health_check(self):
        """Periodic health check and restart if needed"""
        while self.running:
            try:
                time.sleep(300)  # Check every 5 minutes
                self.bot.get_me()
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
            
            # Start health check thread
            health_thread = threading.Thread(target=self._health_check, daemon=True)
            health_thread.start()
            
            # Start bot polling
            self.start_polling()
            
        except KeyboardInterrupt:
            self.logger.info("Bot stopped by user")
        except Exception as e:
            self.logger.error(f"Fatal error: {e}")
            raise
        finally:
            self.running = False
            self.db.close()
            self.logger.info("🛑 Bot shutdown complete")


def create_flask_app():
    """Create and configure Flask application"""
    from flask import Flask, render_template
    
    app = Flask(__name__, template_folder="templates")
    
    @app.route("/")
    def index():
        return render_template("base.html")
    
    return app


def main():
    """Main entry point"""
    try:
        # Check if we should run the Flask web server
        if os.environ.get('RUN_FLASK', 'false').lower() == 'true':
            from waitress import serve
            
            # Create Flask app
            app = create_flask_app()
            
            # Start Flask server in a separate thread
            port = int(os.getenv("PORT", 5000))
            flask_thread = threading.Thread(
                target=lambda: serve(app, host="0.0.0.0", port=port),
                daemon=True
            )
            flask_thread.start()
            print(f"🌐 Flask server running on port {port}")
        
        # Start the bot
        bot = TelegramSecurityBot()
        bot.run()
        
    except Exception as e:
        logger = setup_logger(__name__)
        logger.error(f"Failed to start bot: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
