def run(self):
    """Main run method"""
    try:
        self.logger.info("🔐 Telegram Security Bot starting up...")
        port = int(os.getenv("PORT", 5000))
        self.logger.info(f"🌐 Server binding to port {port}")

        # Start bot thread
        bot_thread = threading.Thread(target=self.start_polling, daemon=True)
        bot_thread.start()

        # Start health check thread once
        health_thread = threading.Thread(target=self._health_check, daemon=True)
        health_thread.start()

        # Flask web server
        app = Flask(__name__, template_folder="templates")

        @app.route("/")
        def index():
            return render_template("base.html")

        app.run(host="0.0.0.0", port=port, debug=False)

    except KeyboardInterrupt:
        self.logger.info("Bot stopped by user")
    except Exception as e:
        self.logger.error(f"Fatal error: {e}")
        raise
    finally:
        self.running = False
        self.db.close()
        self.logger.info("🛑 Bot shutdown complete")
        
