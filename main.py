import threading
import logging
from app import app
import routes  # noqa: F401
from bot import TelegramBot

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def run_flask():
    """Run Flask web server"""
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)

def run_bot():
    """Run Telegram bot"""
    try:
        bot = TelegramBot()
        bot.start()
    except Exception as e:
        logging.error(f"Bot failed to start: {e}")

if __name__ == "__main__":
    # Start Flask server in a separate thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    
    # Start Telegram bot in main thread
    run_bot()
    
