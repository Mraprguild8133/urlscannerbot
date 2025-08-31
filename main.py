#!/usr/bin/env python3
"""
Telegram Security Bot - Fixed Main Entry Point
Simplified version to ensure it runs properly
"""

import os
import sys
import time
import signal
import logging
import threading
from typing import Optional

import telebot
from telebot.types import Message, CallbackQuery

# Set up basic logging first
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('bot.log')
    ]
)
logger = logging.getLogger(__name__)

# Try to import other modules with error handling
try:
    from config import Config
    from database import Database
    from handlers.message_handler import MessageHandler
    from handlers.admin_handler import AdminHandler
    from services.url_scanner import URLScanner
    from services.cloudflare_radar import CloudflareRadar
    from services.admin_manager import AdminManager
    from services.threat_analyzer import ThreatAnalyzer
except ImportError as e:
    logger.error(f"Import error: {e}")
    logger.error("Please make sure all modules are properly installed and configured")
    sys.exit(1)

class TelegramSecurityBot:
    """Main bot class - simplified and fixed"""
    
    def __init__(self):
        logger.info("🤖 Initializing Telegram Security Bot...")
        
        # Initialize configuration
        try:
            self.config = Config()
            logger.info("✅ Configuration loaded successfully")
        except Exception as e:
            logger.error(f"❌ Failed to load configuration: {e}")
            sys.exit(1)
        
        self.running = True
        self.webhook_mode = os.getenv('WEBHOOK_MODE', 'false').lower() == 'true'
        
        # Get port from environment variable or use default
        self.port = int(os.getenv('PORT', 5000))
        logger.info(f"🌐 Using port: {self.port}")
        
        # Initialize bot
        try:
            self.bot = telebot.TeleBot(
                self.config.TELEGRAM_BOT_TOKEN,
                parse_mode='HTML',
                threaded=True
            )
            logger.info("✅ Bot instance created successfully")
        except Exception as e:
            logger.error(f"❌ Failed to create bot instance: {e}")
            sys.exit(1)
        
        # Initialize database
        try:
            self.db = Database()
            logger.info("✅ Database initialized successfully")
        except Exception as e:
            logger.error(f"❌ Failed to initialize database: {e}")
            # Continue without database if it's not critical
        
        # Initialize services with error handling
        try:
            self.url_scanner = URLScanner(self.config.URLSCAN_API_KEY)
            self.cloudflare_radar = CloudflareRadar(self.config.CLOUDFLARE_API_KEY)
            self.admin_manager = AdminManager(self.db)
            self.threat_analyzer = ThreatAnalyzer(self.url_scanner, self.cloudflare_radar, self.db)
            logger.info("✅ Services initialized successfully")
        except Exception as e:
            logger.error(f"❌ Failed to initialize services: {e}")
            # Continue with limited functionality
        
        # Initialize handlers
        try:
            self.message_handler = MessageHandler(self.bot, self.threat_analyzer, self.admin_manager, self.db)
            self.admin_handler = AdminHandler(self.bot, self.admin_manager, self.db)
            logger.info("✅ Handlers initialized successfully")
        except Exception as e:
            logger.error(f"❌ Failed to initialize handlers: {e}")
            sys.exit(1)
        
        # Setup bot handlers
        self._setup_handlers()
        
        # Setup signal handlers
        self._setup_signal_handlers()
        
        logger.info("✅ Telegram Security Bot initialized successfully")

    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        if hasattr(signal, 'SIGINT'):
            signal.signal(signal.SIGINT, self._signal_handler)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, self._signal_handler)
        logger.info("✅ Signal handlers set up")

    def _setup_handlers(self):
        """Setup all bot message and callback handlers"""
        
        # Basic command handlers
        @self.bot.message_handler(commands=['start', 'help'])
        def handle_start_help(message: Message):
            try:
                if message.text.startswith('/start'):
                    self.message_handler.handle_start(message)
                else:
                    self.message_handler.handle_help(message)
            except Exception as e:
                logger.error(f"Error in start/help handler: {e}")
                self.bot.reply_to(message, "❌ An error occurred. Please try again.")

        @self.bot.message_handler(commands=['scan'])
        def handle_scan(message: Message):
            try:
                self.message_handler.handle_manual_scan(message)
            except Exception as e:
                logger.error(f"Error in scan handler: {e}")
                self.bot.reply_to(message, "❌ Scan failed. Please try again.")

        @self.bot.message_handler(commands=['stats'])
        def handle_stats(message: Message):
            try:
                self.message_handler.handle_stats(message)
            except Exception as e:
                logger.error(f"Error in stats handler: {e}")
                self.bot.reply_to(message, "❌ Could not retrieve statistics.")

        # Auto URL scanning for text messages
        @self.bot.message_handler(func=lambda message: True, content_types=['text'])
        def handle_text(message: Message):
            try:
                self.message_handler.handle_text_message(message)
            except Exception as e:
                logger.error(f"Error in text message handler: {e}")
                # Don't reply to avoid spamming users

        logger.info("✅ Bot handlers set up successfully")

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logger.info(f"🛑 Received shutdown signal. Stopping bot...")
        self.running = False
        try:
            self.bot.stop_polling()
        except:
            pass
        try:
            if hasattr(self, 'db'):
                self.db.close()
        except:
            pass
        logger.info("✅ Bot stopped gracefully")
        sys.exit(0)

    def start_polling_safe(self):
        """Safe polling with error handling"""
        max_retries = 3
        retry_delay = 5
        
        for attempt in range(max_retries):
            try:
                logger.info(f"🔄 Starting polling (attempt {attempt + 1}/{max_retries})")
                
                # Test bot connection first
                bot_info = self.bot.get_me()
                logger.info(f"✅ Connected to bot: @{bot_info.username}")
                
                # Start polling
                self.bot.infinity_polling(
                    timeout=30,
                    long_polling_timeout=30,
                    skip_pending=True,
                    none_stop=True
                )
                break
                
            except Exception as e:
                logger.error(f"❌ Polling attempt {attempt + 1} failed: {e}")
                
                if attempt < max_retries - 1:
                    logger.info(f"⏳ Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2
                else:
                    logger.error("❌ Max retries reached. Polling failed completely.")
                    return False
        
        return True

    def run(self):
        """Main run method"""
        logger.info("🚀 Starting Telegram Security Bot...")
        
        # Validate essential configuration
        if not hasattr(self.config, 'TELEGRAM_BOT_TOKEN') or not self.config.TELEGRAM_BOT_TOKEN:
            logger.error("❌ TELEGRAM_BOT_TOKEN is not set or invalid")
            sys.exit(1)
        
        try:
            if self.webhook_mode:
                logger.info("🌐 Webhook mode selected")
                # For webhook mode, you'd need to set up a web server
                # This is simplified for now - focus on polling first
                logger.warning("⚠️ Webhook mode not fully implemented. Using polling instead.")
            
            # Start polling
            success = self.start_polling_safe()
            
            if not success:
                logger.error("❌ Failed to start polling after multiple attempts")
                sys.exit(1)
                
        except KeyboardInterrupt:
            logger.info("⏹️ Bot stopped by user")
        except Exception as e:
            logger.error(f"💥 Fatal error: {e}", exc_info=True)
        finally:
            self.running = False
            try:
                if hasattr(self, 'db'):
                    self.db.close()
            except:
                pass
            logger.info("🛑 Bot shutdown complete")

def main():
    """Main entry point"""
    try:
        print("=" * 50)
        print("Telegram Security Bot - Starting Up")
        print("=" * 50)
        
        # Display basic info
        port = int(os.getenv('PORT', 5000))
        webhook_mode = os.getenv('WEBHOOK_MODE', 'false').lower() == 'true'
        
        print(f"Port: {port}")
        print(f"Webhook mode: {webhook_mode}")
        print("Check bot.log for detailed logs")
        print("Press Ctrl+C to stop the bot")
        print("=" * 50)
        
        # Create and run bot
        bot = TelegramSecurityBot()
        bot.run()
        
    except Exception as e:
        logger.error(f"💥 Failed to start bot: {e}", exc_info=True)
        print(f"Error: {e}")
        print("Check bot.log for details")
        sys.exit(1)

if __name__ == "__main__":
    main()
