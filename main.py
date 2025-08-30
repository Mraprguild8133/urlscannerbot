#!/usr/bin/env python3
"""
Telegram Security Bot - Web Interface
Provides a web dashboard for monitoring and managing the security bot
"""

from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
import sqlite3
import json
import os
from datetime import datetime, timedelta
from functools import wraps
import threading
import time

# Import your existing modules
try:
    from config import Config
    from database import Database
    from utils.logger import setup_logger
except ImportError:
    # Fallback for standalone operation
    import sys
    sys.path.append('..')
    from config import Config
    from database import Database
    from utils.logger import setup_logger


class WebInterface:
    """Web interface for Telegram Security Bot"""
    
    def __init__(self):
        self.logger = setup_logger(__name__)
        self.config = Config()
        self.db = Database()
        
        # Initialize Flask app
        self.app = Flask(__name__, 
                        template_folder='templates',
                        static_folder='static')
        
        # Configuration
        self.app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
        self.app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
        
        # Initialize login manager
        self.login_manager = LoginManager()
        self.login_manager.init_app(self.app)
        self.login_manager.login_view = 'login'
        
        # User class for authentication
        class User(UserMixin):
            def __init__(self, id, username, is_admin):
                self.id = id
                self.username = username
                self.is_admin = is_admin
        
        self.User = User
        
        # Setup routes
        self._setup_routes()
        
        # Background thread for updating stats
        self._stats_cache = {}
        self._last_update = 0
        self._cache_lock = threading.Lock()
        
        # Start background thread for updating stats
        self._running = True
        self.update_thread = threading.Thread(target=self._update_stats_thread, daemon=True)
        self.update_thread.start()
        
        self.logger.info("🌐 Web Interface initialized successfully")
    
    def _setup_routes(self):
        """Setup all web routes"""
        
        @self.login_manager.user_loader
        def load_user(user_id):
            # In a real application, you would query your database for the user
            # For simplicity, we'll use a hardcoded admin user
            if user_id == 'admin':
                return self.User('admin', 'admin', True)
            return None
        
        @self.app.route('/')
        def index():
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            return render_template('dashboard.html')
        
        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            if request.method == 'POST':
                username = request.form.get('username')
                password = request.form.get('password')
                
                # Simple authentication - in production, use proper password hashing
                if username == 'admin' and password == os.getenv('WEB_ADMIN_PASSWORD', 'admin'):
                    user = self.User('admin', 'admin', True)
                    login_user(user)
                    return redirect(url_for('index'))
                
                return render_template('login.html', error='Invalid credentials')
            
            return render_template('login.html')
        
        @self.app.route('/logout')
        @login_required
        def logout():
            logout_user()
            return redirect(url_for('login'))
        
        @self.app.route('/api/stats')
        @login_required
        def api_stats():
            with self._cache_lock:
                # Return cached stats to avoid database queries on every request
                return jsonify(self._stats_cache)
        
        @self.app.route('/api/recent-scans')
        @login_required
        def api_recent_scans():
            limit = request.args.get('limit', 10, type=int)
            try:
                conn = sqlite3.connect(self.config.DATABASE_PATH)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT url, result, timestamp, user_id, chat_id 
                    FROM scans 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
                
                scans = []
                for row in cursor.fetchall():
                    scans.append({
                        'url': row[0],
                        'result': json.loads(row[1]) if row[1] else {},
                        'timestamp': row[2],
                        'user_id': row[3],
                        'chat_id': row[4]
                    })
                
                conn.close()
                return jsonify({'scans': scans})
            except Exception as e:
                self.logger.error(f"Error fetching recent scans: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/top-threats')
        @login_required
        def api_top_threats():
            limit = request.args.get('limit', 10, type=int)
            try:
                conn = sqlite3.connect(self.config.DATABASE_PATH)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT url, COUNT(*) as count 
                    FROM scans 
                    WHERE result LIKE '%"malicious": true%' 
                    OR result LIKE '%"malicious": True%'
                    OR result LIKE '%"malicious":1%'
                    GROUP BY url 
                    ORDER BY count DESC 
                    LIMIT ?
                ''', (limit,))
                
                threats = []
                for row in cursor.fetchall():
                    threats.append({
                        'url': row[0],
                        'count': row[1]
                    })
                
                conn.close()
                return jsonify({'threats': threats})
            except Exception as e:
                self.logger.error(f"Error fetching top threats: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/user-stats')
        @login_required
        def api_user_stats():
            limit = request.args.get('limit', 10, type=int)
            try:
                conn = sqlite3.connect(self.config.DATABASE_PATH)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT user_id, COUNT(*) as scan_count 
                    FROM scans 
                    GROUP BY user_id 
                    ORDER BY scan_count DESC 
                    LIMIT ?
                ''', (limit,))
                
                users = []
                for row in cursor.fetchall():
                    users.append({
                        'user_id': row[0],
                        'scan_count': row[1]
                    })
                
                conn.close()
                return jsonify({'users': users})
            except Exception as e:
                self.logger.error(f"Error fetching user stats: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/settings')
        @login_required
        def settings():
            return render_template('settings.html')
        
        @self.app.route('/api/settings', methods=['GET', 'PUT'])
        @login_required
        def api_settings():
            if request.method == 'GET':
                try:
                    # Get current settings from database
                    conn = sqlite3.connect(self.config.DATABASE_PATH)
                    cursor = conn.cursor()
                    
                    cursor.execute('SELECT name, value FROM settings')
                    settings = {row[0]: row[1] for row in cursor.fetchall()}
                    
                    conn.close()
                    return jsonify(settings)
                except Exception as e:
                    self.logger.error(f"Error fetching settings: {e}")
                    return jsonify({'error': str(e)}), 500
            
            elif request.method == 'PUT':
                try:
                    data = request.get_json()
                    conn = sqlite3.connect(self.config.DATABASE_PATH)
                    cursor = conn.cursor()
                    
                    for key, value in data.items():
                        cursor.execute('''
                            INSERT OR REPLACE INTO settings (name, value) 
                            VALUES (?, ?)
                        ''', (key, str(value)))
                    
                    conn.commit()
                    conn.close()
                    
                    self.logger.info(f"Settings updated: {data}")
                    return jsonify({'status': 'success'})
                except Exception as e:
                    self.logger.error(f"Error updating settings: {e}")
                    return jsonify({'error': str(e)}), 500
    
    def _update_stats(self):
        """Update statistics cache"""
        try:
            conn = sqlite3.connect(self.config.DATABASE_PATH)
            cursor = conn.cursor()
            
            # Total scans
            cursor.execute('SELECT COUNT(*) FROM scans')
            total_scans = cursor.fetchone()[0]
            
            # Malicious scans
            cursor.execute('''
                SELECT COUNT(*) FROM scans 
                WHERE result LIKE '%"malicious": true%' 
                OR result LIKE '%"malicious": True%'
                OR result LIKE '%"malicious":1%'
            ''')
            malicious_scans = cursor.fetchone()[0]
            
            # Today's scans
            cursor.execute('''
                SELECT COUNT(*) FROM scans 
                WHERE date(timestamp) = date('now')
            ''')
            today_scans = cursor.fetchone()[0]
            
            # Total users
            cursor.execute('SELECT COUNT(DISTINCT user_id) FROM scans')
            total_users = cursor.fetchone()[0]
            
            # Scan results breakdown
            cursor.execute('''
                SELECT 
                    SUM(CASE WHEN result LIKE '%"malicious": true%' OR result LIKE '%"malicious": True%' OR result LIKE '%"malicious":1%' THEN 1 ELSE 0 END) as malicious,
                    SUM(CASE WHEN result LIKE '%"malicious": false%' OR result LIKE '%"malicious": False%' OR result LIKE '%"malicious":0%' THEN 1 ELSE 0 END) as clean,
                    SUM(CASE WHEN result IS NULL OR result = '' OR result LIKE '%error%' THEN 1 ELSE 0 END) as errors
                FROM scans
            ''')
            breakdown = cursor.fetchone()
            
            conn.close()
            
            stats = {
                'total_scans': total_scans,
                'malicious_scans': malicious_scans,
                'today_scans': today_scans,
                'total_users': total_users,
                'scan_breakdown': {
                    'malicious': breakdown[0],
                    'clean': breakdown[1],
                    'errors': breakdown[2]
                },
                'last_updated': datetime.now().isoformat()
            }
            
            with self._cache_lock:
                self._stats_cache = stats
                self._last_update = time.time()
                
        except Exception as e:
            self.logger.error(f"Error updating stats: {e}")
    
    def _update_stats_thread(self):
        """Background thread to update statistics periodically"""
        while self._running:
            try:
                self._update_stats()
                time.sleep(60)  # Update every minute
            except Exception as e:
                self.logger.error(f"Error in stats update thread: {e}")
                time.sleep(60)
    
    def run(self, host='0.0.0.0', port=5000, debug=False):
        """Run the web interface"""
        self.logger.info(f"🌐 Starting web interface on {host}:{port}")
        self.app.run(host=host, port=port, debug=debug, use_reloader=False)
    
    def stop(self):
        """Stop the web interface"""
        self._running = False
        if self.update_thread.is_alive():
            self.update_thread.join(timeout=5)
        self.logger.info("Web interface stopped")


def main():
    """Main entry point for the web interface"""
    try:
        web_interface = WebInterface()
        web_interface.run(
            host=os.getenv('WEB_HOST', '0.0.0.0'),
            port=int(os.getenv('WEB_PORT', 5000)),
            debug=os.getenv('WEB_DEBUG', 'false').lower() == 'true'
        )
    except Exception as e:
        logger = setup_logger(__name__)
        logger.error(f"Failed to start web interface: {e}")
        raise


if __name__ == "__main__":
    main()
