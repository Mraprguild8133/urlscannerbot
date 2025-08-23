#!/usr/bin/env python3
"""
Web Interface for Telegram Security Bot
Provides API key management and connection status monitoring
"""

import os
import json
import logging
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from config import Config
from services.url_scanner import URLScanner
from services.cloudflare_radar import CloudflareRadar
import requests

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-change-this')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class APIStatus:
    def __init__(self):
        # Don't initialize Config if environment variables are missing
        self.config = None
    
    def check_telegram_bot(self):
        """Check Telegram Bot API connection"""
        try:
            token = os.getenv('TELEGRAM_BOT_TOKEN')
            if not token:
                return {'status': 'error', 'message': 'Token not provided'}
            
            response = requests.get(f'https://api.telegram.org/bot{token}/getMe', timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    bot_info = data.get('result', {})
                    return {
                        'status': 'connected',
                        'message': f"Bot @{bot_info.get('username', 'unknown')} is connected",
                        'details': bot_info
                    }
            return {'status': 'error', 'message': 'Invalid token or API error'}
        except Exception as e:
            return {'status': 'error', 'message': f'Connection failed: {str(e)}'}
    
    def check_urlscan_api(self):
        """Check URLScan.io API connection"""
        try:
            api_key = os.getenv('URLSCAN_API_KEY')
            if not api_key:
                return {'status': 'not_configured', 'message': 'API key not provided'}
            
            scanner = URLScanner(api_key)
            # Test with a simple quota check
            response = requests.get(
                'https://urlscan.io/api/v1/user/quotas/',
                headers={'API-Key': api_key},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'status': 'connected',
                    'message': 'URLScan.io API connected',
                    'details': data
                }
            return {'status': 'error', 'message': f'API error: {response.status_code}'}
        except Exception as e:
            return {'status': 'error', 'message': f'Connection failed: {str(e)}'}
    
    def check_cloudflare_api(self):
        """Check Cloudflare Radar API connection"""
        try:
            api_key = os.getenv('CLOUDFLARE_API_KEY')
            if not api_key:
                return {'status': 'not_configured', 'message': 'API key not provided'}
            
            # Test with a simple API call
            response = requests.get(
                'https://api.cloudflare.com/client/v4/radar/ranking/top',
                headers={'Authorization': f'Bearer {api_key}'},
                params={'limit': 1},
                timeout=10
            )
            
            if response.status_code == 200:
                return {
                    'status': 'connected',
                    'message': 'Cloudflare Radar API connected'
                }
            return {'status': 'error', 'message': f'API error: {response.status_code}'}
        except Exception as e:
            return {'status': 'error', 'message': f'Connection failed: {str(e)}'}

@app.route('/')
def index():
    """Main dashboard showing API status"""
    api_status = APIStatus()
    
    status_data = {
        'telegram': api_status.check_telegram_bot(),
        'urlscan': api_status.check_urlscan_api(),
        'cloudflare': api_status.check_cloudflare_api(),
        'timestamp': datetime.now().isoformat()
    }
    
    return render_template('dashboard.html', status=status_data)

@app.route('/api/status')
def api_status():
    """API endpoint for status checks"""
    api_status = APIStatus()
    
    return jsonify({
        'telegram': api_status.check_telegram_bot(),
        'urlscan': api_status.check_urlscan_api(),
        'cloudflare': api_status.check_cloudflare_api(),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/health')
def health():
    """Health check endpoint for Render.com"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

@app.route('/config')
def config_page():
    """Configuration page for API keys"""
    return render_template('config.html')

@app.route('/docs')
def documentation():
    """Documentation page"""
    return render_template('docs.html')

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    host = '0.0.0.0'  # Required for Render.com
    
    logger.info(f"Starting web interface on {host}:{port}")
    app.run(host=host, port=port, debug=False)
