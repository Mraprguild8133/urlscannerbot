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
from telebot.types import Message, CallbackQuery
from flask import Flask, render_template

# ======================
# Bot Configuration
# ======================

class Config:
    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")
    BOT_NAME = "Telegram Security Bot"
    PORT = int(os.getenv("PORT", 5000))
    PID_FILE = "bot.pid"

# ======================
# Telegram Security Bot
# ======================

class TelegramSecurityBot:
    def __init__(self, config: Config):
        self.config = config
        self.logger = self._setup_logger()
        self.bot = telebot.TeleBot(config.TELEGRAM_BOT_TOKEN, parse_mode="HTML")
        self.running = True

        # Register bot commands/handlers
        self._register_handlers()

    def _setup_logger(self):
        import logging
        logger = logging.getLogger(self.config.BOT_NAME)
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s | %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger

    # ======================
    # Bot Handlers
    # ======================
    def _register_handlers(self):
        @self.bot.message_handler(commands=["start"])
        def start_handler(message: Message):
            self.bot.reply_to(message, "👋 Hello! I am your Security Bot.\nSend me a URL and I'll check it.")

        @self.bot.message_handler(func=lambda msg: True)
        def echo_handler(message: Message):
            self.bot.reply_to(message, f"🔍 Received: {message.text}")

    # ======================
    # Health Check
    # ======================
    def _health_check(self):
        """Periodic health check and restart if needed"""
        while self.running:
            try:
                time.sleep(300)  # check every 5 minutes
                self.bot.get_me()
                self.logger.info("🟢 Bot health check passed")
            except Exception as e:
                self.logger.error(f"🔴 Health check failed: {e}")

    # ======================
    # Start Polling
    # ======================
    def start_polling(self):
        max_retries = 5
        retry_delay = 10

        for attempt in range(max_retries):
            try:
                self.logger.info(f"🚀 Starting bot polling (attempt {attempt+1}/{max_retries})")

                # ✅ Always remove webhook before polling
                self.bot.remove_webhook()

                # Start health check thread (only once)
                if attempt == 0:
                    health_thread = threading.Thread(target=self._health_check, daemon=True)
                    health_thread.start()

                # Start polling
                self.bot.infinity_polling(
                    timeout=30,
                    long_polling_timeout=30,
                    skip_pending=True
                )
                break

            except Exception as e:
                err_msg = str(e)
                self.logger.error(f"Polling attempt {attempt+1} failed: {err_msg}")

                # ✅ Specific fix for 409 conflict
                if "Conflict: terminated by other getUpdates request" in err_msg:
                    self.logger.error("❌ Another instance of this bot is already running.")
                    self._cleanup_pid()
                    sys.exit(1)

                if attempt < max_retries - 1:
                    self.logger.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2
                else:
                    self.logger.error("Max retries reached. Bot failed to start.")
                    self._cleanup_pid()
                    raise

    # ======================
    # PID Lock System
    # ======================
    def _check_pid(self):
        """Ensure only one instance is running"""
        if os.path.exists(self.config.PID_FILE):
            with open(self.config.PID_FILE, "r") as f:
                old_pid = f.read().strip()
            if old_pid and os.path.exists(f"/proc/{old_pid}"):
                self.logger.error("❌ Another bot process is already running. Exiting.")
                sys.exit(1)

        # Write current PID
        with open(self.config.PID_FILE, "w") as f:
            f.write(str(os.getpid()))
        atexit.register(self._cleanup_pid)

    def _cleanup_pid(self):
        """Remove PID file on exit"""
        try:
            if os.path.exists(self.config.PID_FILE):
                os.remove(self.config.PID_FILE)
        except Exception:
            pass

    # ======================
    # Run Bot + Flask
    # ======================
    def run(self):
        """Run bot with Flask healthcheck server"""
        self._check_pid()  # ensure single instance

        # Handle SIGTERM/SIGINT
        signal.signal(signal.SIGTERM, lambda s, f: self.stop())
        signal.signal(signal.SIGINT, lambda s, f: self.stop())

        # Start bot polling in a thread
        bot_thread = threading.Thread(target=self.start_polling, daemon=True)
        bot_thread.start()

        # Start Flask server
        app = Flask(__name__)

        @app.route("/", methods=["GET", "HEAD"])
        def index():
            return render_template("base.html", status="🟢 Running")

        self.logger.info(f"🌐 Starting Flask server on port {self.config.PORT}")
        app.run(host="0.0.0.0", port=self.config.PORT, debug=False, use_reloader=False)

    def stop(self):
        self.logger.info("🛑 Stopping bot...")
        self.running = False
        self._cleanup_pid()
        sys.exit(0)


# ======================
# Main Entry
# ======================

if __name__ == "__main__":
    config = Config()
    bot = TelegramSecurityBot(config)
    bot.run()
                    
