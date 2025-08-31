#!/usr/bin/env python3
"""
cleanup_bot.py - Script to cleanup any existing bot instances
"""

import requests
import sys
import os

# Add the current directory to path to import config
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import Config

def cleanup_bot():
    config = Config()
    
    print("🛠️  Attempting to cleanup existing bot instances...")
    
    # Try to delete webhook
    try:
        response = requests.get(
            f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/deleteWebhook",
            timeout=10
        )
        print(f"Webhook deletion: {response.status_code}")
    except Exception as e:
        print(f"Webhook deletion failed: {e}")
    
    # Try to close connection
    try:
        response = requests.get(
            f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/close",
            timeout=10
        )
        print(f"Connection close: {response.status_code}")
    except Exception as e:
        print(f"Connection close failed: {e}")
    
    print("✅ Cleanup attempted. You can now start the bot.")

if __name__ == "__main__":
    cleanup_bot()
