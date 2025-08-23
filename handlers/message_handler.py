"""
Message handler for Telegram Security Bot
Handles user messages, URL detection, and scanning
"""

import asyncio
import time
from typing import List, Dict, Optional
from datetime import datetime, timedelta

import telebot
from telebot.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton

from database import Database
from services.threat_analyzer import ThreatAnalyzer
from services.admin_manager import AdminManager
from utils.logger import BotLogger
from utils.url_detector import URLDetector

class MessageHandler:
    """Handles all message processing and URL scanning"""
    
    def __init__(self, bot: telebot.TeleBot, threat_analyzer: ThreatAnalyzer, 
                 admin_manager: AdminManager, db: Database):
        self.bot = bot
        self.threat_analyzer = threat_analyzer
        self.admin_manager = admin_manager
        self.db = db
        self.logger = BotLogger(__name__)
        self.url_detector = URLDetector()
        
        # Track recent scans to avoid duplicates
        self.recent_scans = {}  # url -> timestamp
        self.scan_cooldown = 300  # 5 minutes
        
        self.logger.info("💬 Message handler initialized")
    
    def handle_start(self, message: Message):
        """Handle /start command"""
        try:
            user_id = message.from_user.id
            username = message.from_user.username or "Unknown"
            chat_id = message.chat.id
            
            self.logger.log_user_action(user_id, username, chat_id, "Started bot")
            
            welcome_text = """
🤖 <b>Telegram Security Bot</b>

🛡️ <b>Features:</b>
• Real-time URL threat analysis
• Automatic malicious link detection
• URLScan.io and Cloudflare Radar integration
• Admin group management tools
• Configurable security thresholds

🔧 <b>Commands:</b>
/help - Show help message
/scan &lt;url&gt; - Manually scan a URL
/stats - View scanning statistics
/settings - View current settings

👥 <b>Admin Commands:</b>
/admin - Admin panel
/addadmin - Add bot admin
/ban - Ban user
/whitelist - Manage whitelist

🚀 <b>Getting Started:</b>
Just send a message with a URL and I'll automatically analyze it for threats!

For groups: Add me as admin to automatically scan all URLs posted by members.
            """
            
            self.bot.send_message(
                chat_id,
                welcome_text,
                parse_mode='HTML',
                disable_web_page_preview=True
            )
            
        except Exception as e:
            self.logger.error(f"Error in start handler: {e}")
            self._send_error_message(message.chat.id, "Failed to process start command")
    
    def handle_help(self, message: Message):
        """Handle /help command"""
        try:
            user_id = message.from_user.id
            username = message.from_user.username or "Unknown"
            chat_id = message.chat.id
            
            self.logger.log_user_action(user_id, username, chat_id, "Requested help")
            
            help_text = """
🆘 <b>Telegram Security Bot - Help</b>

<b>🔍 URL Scanning:</b>
The bot automatically scans all URLs posted in chats. No setup required!

<b>📊 Threat Analysis:</b>
• Combines URLScan.io and Cloudflare Radar
• Analyzes URL structure and patterns
• Checks domain reputation
• Detects phishing and malware

<b>⚙️ User Commands:</b>
/start - Welcome message
/help - This help message
/scan &lt;url&gt; - Manually scan a URL
/stats - View scanning statistics
/settings - View current chat settings

<b>👨‍💼 Admin Commands:</b>
/admin - Open admin panel
/addadmin @username - Add bot admin
/removeadmin @username - Remove bot admin
/ban @username - Ban user
/unban @username - Unban user
/whitelist add/remove/list domain.com - Manage whitelist
/blacklist add/remove/list domain.com - Manage blacklist
/threshold &lt;1-100&gt; - Set threat threshold

<b>🎯 Threat Levels:</b>
🔴 High (80-100): Definitely malicious
🟠 Medium (50-79): Likely malicious
🟡 Low (20-49): Potentially suspicious
🟢 Safe (0-19): Appears clean

<b>📈 Score Factors:</b>
• URLScan.io verdict (40%)
• Cloudflare intelligence (30%)
• Domain reputation (20%)
• URL structure (10%)

<b>🛠️ Configuration:</b>
Admins can adjust threat thresholds and manage whitelists/blacklists per chat.

<b>🔗 Supported URLs:</b>
• HTTP/HTTPS links
• Telegram links (t.me)
• URL shorteners
• IP addresses
• Email addresses
            """
            
            self.bot.send_message(
                chat_id,
                help_text,
                parse_mode='HTML',
                disable_web_page_preview=True
            )
            
        except Exception as e:
            self.logger.error(f"Error in help handler: {e}")
            self._send_error_message(message.chat.id, "Failed to display help")
    
    def handle_manual_scan(self, message: Message):
        """Handle /scan command for manual URL scanning"""
        try:
            user_id = message.from_user.id
            username = message.from_user.username or "Unknown"
            chat_id = message.chat.id
            
            # Check if user is banned
            if self.admin_manager.is_user_banned(chat_id, user_id):
                self.bot.send_message(chat_id, "❌ You are banned from using this bot.")
                return
            
            # Extract URL from command
            command_parts = message.text.split(None, 1)
            if len(command_parts) < 2:
                self.bot.send_message(
                    chat_id,
                    "❌ Please provide a URL to scan.\n\n"
                    "Example: <code>/scan https://example.com</code>",
                    parse_mode='HTML'
                )
                return
            
            url = command_parts[1].strip()
            
            # Validate URL
            if not self.url_detector._is_valid_url(url):
                self.bot.send_message(
                    chat_id,
                    "❌ Invalid URL format. Please provide a valid URL."
                )
                return
            
            self.logger.log_user_action(
                user_id, username, chat_id, f"Manual scan request", f"URL: {url}"
            )
            
            # Send initial message
            status_msg = self.bot.send_message(
                chat_id,
                f"🔍 <b>Scanning URL...</b>\n\n"
                f"🔗 <code>{url}</code>\n\n"
                f"⏳ Please wait while I analyze this URL...",
                parse_mode='HTML',
                disable_web_page_preview=True
            )
            
            # Perform scan
            try:
                result = self.threat_analyzer.analyze_url_comprehensive(
                    url, chat_id, user_id, message.message_id, max_wait=45
                )
                
                # Send results
                self._send_scan_results(chat_id, result, status_msg.message_id)
                
            except Exception as scan_error:
                self.logger.error(f"Scan error: {scan_error}")
                self.bot.edit_message_text(
                    f"❌ <b>Scan Failed</b>\n\n"
                    f"🔗 <code>{url}</code>\n\n"
                    f"Error: {str(scan_error)}",
                    chat_id,
                    status_msg.message_id,
                    parse_mode='HTML',
                    disable_web_page_preview=True
                )
            
        except Exception as e:
            self.logger.error(f"Error in manual scan handler: {e}")
            self._send_error_message(message.chat.id, "Failed to process scan command")
    
    def handle_stats(self, message: Message):
        """Handle /stats command"""
        try:
            user_id = message.from_user.id
            username = message.from_user.username or "Unknown"
            chat_id = message.chat.id
            
            self.logger.log_user_action(user_id, username, chat_id, "Requested stats")
            
            # Get statistics
            stats_7d = self.db.get_stats(days=7)
            stats_30d = self.db.get_stats(days=30)
            recent_scans = self.db.get_recent_scans(chat_id, hours=24, limit=10)
            chat_settings = self.db.get_chat_settings(chat_id)
            
            # Format statistics message
            stats_text = f"""
📊 <b>Security Bot Statistics</b>

<b>🗓️ Last 7 Days:</b>
• URLs Scanned: {stats_7d['total_urls_scanned']}
• Threats Detected: {stats_7d['total_threats_detected']}
• Active Chats: {stats_7d['max_chats_active']}
• Detection Rate: {(stats_7d['total_threats_detected'] / max(stats_7d['total_urls_scanned'], 1) * 100):.1f}%

<b>🗓️ Last 30 Days:</b>
• URLs Scanned: {stats_30d['total_urls_scanned']}
• Threats Detected: {stats_30d['total_threats_detected']}
• Detection Rate: {(stats_30d['total_threats_detected'] / max(stats_30d['total_urls_scanned'], 1) * 100):.1f}%

<b>🏠 This Chat (24h):</b>
• Recent Scans: {len(recent_scans)}
• Threat Threshold: {chat_settings['threat_threshold']}/100
• Auto Scan: {'✅' if chat_settings['auto_scan_enabled'] else '❌'}
            """
            
            # Add recent scans if any
            if recent_scans:
                stats_text += "\n<b>🔍 Recent Scans:</b>\n"
                for scan in recent_scans[:5]:
                    threat_emoji = "🔴" if scan['is_malicious'] else "🟢"
                    domain = scan['url'].split('/')[2] if '://' in scan['url'] else scan['url'][:30]
                    stats_text += f"• {threat_emoji} {domain} ({scan['threat_score']}/100)\n"
            
            self.bot.send_message(
                chat_id,
                stats_text,
                parse_mode='HTML',
                disable_web_page_preview=True
            )
            
        except Exception as e:
            self.logger.error(f"Error in stats handler: {e}")
            self._send_error_message(message.chat.id, "Failed to retrieve statistics")
    
    def handle_settings(self, message: Message):
        """Handle /settings command"""
        try:
            user_id = message.from_user.id
            username = message.from_user.username or "Unknown"
            chat_id = message.chat.id
            
            self.logger.log_user_action(user_id, username, chat_id, "Requested settings")
            
            chat_settings = self.db.get_chat_settings(chat_id)
            
            settings_text = f"""
⚙️ <b>Chat Security Settings</b>

<b>🔧 Current Configuration:</b>
• Auto Scan: {'✅ Enabled' if chat_settings['auto_scan_enabled'] else '❌ Disabled'}
• Threat Threshold: {chat_settings['threat_threshold']}/100
• Alert Admins: {'✅ Enabled' if chat_settings['alert_admins'] else '❌ Disabled'}
• Delete Malicious: {'✅ Enabled' if chat_settings['delete_malicious'] else '❌ Disabled'}

<b>📝 Whitelist ({len(chat_settings['whitelist'])} domains):</b>
{self._format_domain_list(chat_settings['whitelist'])}

<b>⛔ Blacklist ({len(chat_settings['blacklist'])} domains):</b>
{self._format_domain_list(chat_settings['blacklist'])}

<b>👨‍💼 Admin Actions Required:</b>
• Use /threshold &lt;number&gt; to change threat threshold
• Use /whitelist add/remove domain.com to manage whitelist
• Use /blacklist add/remove domain.com to manage blacklist
            """
            
            # Create inline keyboard for quick actions
            keyboard = InlineKeyboardMarkup()
            keyboard.row(
                InlineKeyboardButton("🔄 Refresh", callback_data="settings_refresh"),
                InlineKeyboardButton("📊 Stats", callback_data="show_stats")
            )
            
            if self.admin_manager.is_user_admin(chat_id, user_id, self.bot):
                keyboard.row(
                    InlineKeyboardButton("👨‍💼 Admin Panel", callback_data="admin_panel")
                )
            
            self.bot.send_message(
                chat_id,
                settings_text,
                parse_mode='HTML',
                reply_markup=keyboard,
                disable_web_page_preview=True
            )
            
        except Exception as e:
            self.logger.error(f"Error in settings handler: {e}")
            self._send_error_message(message.chat.id, "Failed to display settings")
    
    def handle_text_message(self, message: Message):
        """Handle regular text messages and scan for URLs"""
        try:
            user_id = message.from_user.id
            username = message.from_user.username or "Unknown"
            chat_id = message.chat.id
            
            # Check if user is banned
            if self.admin_manager.is_user_banned(chat_id, user_id):
                return  # Silently ignore banned users
            
            # Check if auto-scan is enabled
            chat_settings = self.db.get_chat_settings(chat_id)
            if not chat_settings['auto_scan_enabled']:
                return
            
            # Extract URLs from message
            urls = self.url_detector.extract_urls(message.text)
            
            if not urls:
                return  # No URLs found
            
            self.logger.log_user_action(
                user_id, username, chat_id, f"Posted URLs", f"URLs: {len(urls)}"
            )
            
            # Scan URLs (limit to prevent spam)
            for url in urls[:3]:  # Limit to 3 URLs per message
                try:
                    # Check cooldown
                    if self._is_scan_on_cooldown(url):
                        continue
                    
                    # Mark URL as scanned
                    self.recent_scans[url] = time.time()
                    
                    # Perform quick analysis first
                    result = self.threat_analyzer.analyze_url_comprehensive(
                        url, chat_id, user_id, message.message_id, max_wait=30
                    )
                    
                    # Send alert if malicious
                    if result['is_malicious']:
                        self._send_threat_alert(chat_id, result, message)
                    
                except Exception as url_error:
                    self.logger.error(f"Error scanning URL {url}: {url_error}")
            
        except Exception as e:
            self.logger.error(f"Error in text message handler: {e}")
    
    def handle_callback(self, call: CallbackQuery):
        """Handle inline keyboard callbacks"""
        try:
            user_id = call.from_user.id
            username = call.from_user.username or "Unknown"
            chat_id = call.message.chat.id
            data = call.data
            
            self.logger.log_user_action(user_id, username, chat_id, f"Callback", f"Data: {data}")
            
            if data == "settings_refresh":
                self.bot.answer_callback_query(call.id, "🔄 Refreshing settings...")
                # Recreate settings message
                self.handle_settings_refresh(call.message)
            
            elif data == "show_stats":
                self.bot.answer_callback_query(call.id, "📊 Loading statistics...")
                self.handle_stats(call.message)
            
            elif data == "admin_panel":
                if self.admin_manager.is_user_admin(chat_id, user_id, self.bot):
                    self.bot.answer_callback_query(call.id, "👨‍💼 Opening admin panel...")
                    self._send_admin_panel(chat_id)
                else:
                    self.bot.answer_callback_query(call.id, "❌ Admin access required", show_alert=True)
            
            elif data.startswith("scan_detail_"):
                scan_id = int(data.split("_")[2])
                self._show_scan_details(call, scan_id)
            
            elif data.startswith("delete_msg_"):
                message_id = int(data.split("_")[2])
                if self.admin_manager.has_permission(chat_id, user_id, 'delete_messages', self.bot):
                    self._delete_malicious_message(call, message_id)
                else:
                    self.bot.answer_callback_query(call.id, "❌ Permission denied", show_alert=True)
            
        except Exception as e:
            self.logger.error(f"Error in callback handler: {e}")
            try:
                self.bot.answer_callback_query(call.id, "❌ An error occurred")
            except Exception:
                pass
    
    def _send_scan_results(self, chat_id: int, result: Dict, message_id: Optional[int] = None):
        """Send scan results to chat"""
        try:
            # Format result message
            url = result['url']
            score = result['threat_score']
            is_malicious = result['is_malicious']
            explanation = result['verdict_explanation']
            
            # Choose emoji and color based on threat level
            if score >= 80:
                emoji = "🔴"
                status = "HIGH THREAT"
            elif score >= 50:
                emoji = "🟠"
                status = "MODERATE THREAT"
            elif score >= 20:
                emoji = "🟡"
                status = "LOW THREAT"
            else:
                emoji = "🟢"
                status = "APPEARS SAFE"
            
            # Format message
            result_text = f"""
{emoji} <b>{status}</b>
Score: {score}/100

🔗 <b>URL:</b>
<code>{url}</code>

📋 <b>Analysis:</b>
{explanation}

🕐 <i>Scanned at {datetime.now().strftime('%H:%M:%S')}</i>
            """
            
            # Create inline keyboard
            keyboard = InlineKeyboardMarkup()
            keyboard.row(
                InlineKeyboardButton("📊 Details", callback_data=f"scan_detail_{result['scan_id']}")
            )
            
            if is_malicious:
                keyboard.row(
                    InlineKeyboardButton("🗑️ Delete Message", callback_data=f"delete_msg_{result['scan_id']}")
                )
            
            # Send or edit message
            if message_id:
                self.bot.edit_message_text(
                    result_text,
                    chat_id,
                    message_id,
                    parse_mode='HTML',
                    reply_markup=keyboard,
                    disable_web_page_preview=True
                )
            else:
                self.bot.send_message(
                    chat_id,
                    result_text,
                    parse_mode='HTML',
                    reply_markup=keyboard,
                    disable_web_page_preview=True
                )
            
        except Exception as e:
            self.logger.error(f"Error sending scan results: {e}")
    
    def _send_threat_alert(self, chat_id: int, result: Dict, original_message: Message):
        """Send threat alert for malicious URL"""
        try:
            url = result['url']
            score = result['threat_score']
            domain = result.get('domain', 'unknown')
            
            # Format alert message
            alert_text = f"""
🚨 <b>THREAT DETECTED</b>

⚠️ <b>Malicious URL blocked!</b>
Score: {score}/100

🔗 <b>URL:</b> <code>{domain}</code>
👤 <b>Posted by:</b> @{original_message.from_user.username or 'Unknown'}

🛡️ <b>Recommendation:</b> Do not visit this URL

📊 Use /scan command for detailed analysis
            """
            
            # Create alert keyboard
            keyboard = InlineKeyboardMarkup()
            keyboard.row(
                InlineKeyboardButton("📊 Full Report", callback_data=f"scan_detail_{result['scan_id']}"),
                InlineKeyboardButton("🗑️ Delete", callback_data=f"delete_msg_{original_message.message_id}")
            )
            
            self.bot.send_message(
                chat_id,
                alert_text,
                parse_mode='HTML',
                reply_markup=keyboard,
                disable_web_page_preview=True
            )
            
            # Log security event
            self.logger.log_security_event(
                "MALICIOUS_URL_DETECTED",
                original_message.from_user.id,
                chat_id,
                f"URL: {url}, Score: {score}"
            )
            
        except Exception as e:
            self.logger.error(f"Error sending threat alert: {e}")
    
    def _show_scan_details(self, call: CallbackQuery, scan_id: int):
        """Show detailed scan information"""
        try:
            scan_data = self.db.get_url_scan(scan_id)
            if not scan_data:
                self.bot.answer_callback_query(call.id, "❌ Scan data not found", show_alert=True)
                return
            
            # Format detailed information
            scan_result = scan_data.get('scan_result', {})
            
            detail_text = f"""
📊 <b>Detailed Scan Report</b>

🔗 <b>URL:</b> <code>{scan_data['url']}</code>
🏆 <b>Final Score:</b> {scan_data['threat_score']}/100
🎯 <b>Verdict:</b> {'🔴 Malicious' if scan_data['is_malicious'] else '🟢 Safe'}

<b>🔍 Component Scores:</b>
• URLScan.io: {scan_result.get('component_scores', {}).get('urlscan', 'N/A')}/100
• Cloudflare: {scan_result.get('component_scores', {}).get('cloudflare', 'N/A')}/100
• Domain Rep: {scan_result.get('component_scores', {}).get('domain_reputation', 'N/A')}/100
• URL Structure: {scan_result.get('component_scores', {}).get('url_structure', 'N/A')}/100

<b>🌐 Services Used:</b>
{', '.join(scan_result.get('services_used', ['None']))}

<b>🕐 Scan Time:</b>
{scan_data['created_at']}
            """
            
            # Show analysis results if available
            analysis = scan_result.get('analysis_results', {})
            if analysis.get('urlscan'):
                urlscan_data = analysis['urlscan']
                if urlscan_data.get('page_info'):
                    page_info = urlscan_data['page_info']
                    detail_text += f"\n<b>🌍 Page Info:</b>\n"
                    if page_info.get('title'):
                        detail_text += f"• Title: {page_info['title'][:50]}...\n"
                    if page_info.get('ip'):
                        detail_text += f"• IP: {page_info['ip']}\n"
                    if page_info.get('country'):
                        detail_text += f"• Country: {page_info['country']}\n"
            
            self.bot.send_message(
                call.message.chat.id,
                detail_text,
                parse_mode='HTML',
                disable_web_page_preview=True
            )
            
            self.bot.answer_callback_query(call.id, "📊 Detailed report sent!")
            
        except Exception as e:
            self.logger.error(f"Error showing scan details: {e}")
            self.bot.answer_callback_query(call.id, "❌ Failed to load details", show_alert=True)
    
    def _delete_malicious_message(self, call: CallbackQuery, message_id: int):
        """Delete malicious message"""
        try:
            chat_id = call.message.chat.id
            user_id = call.from_user.id
            
            if not self.admin_manager.has_permission(chat_id, user_id, 'delete_messages', self.bot):
                self.bot.answer_callback_query(call.id, "❌ No permission to delete", show_alert=True)
                return
            
            # Try to delete the message
            try:
                self.bot.delete_message(chat_id, message_id)
                self.bot.answer_callback_query(call.id, "🗑️ Message deleted")
                
                self.logger.log_admin_action(
                    user_id, call.from_user.username or "Unknown", chat_id,
                    "Deleted malicious message", message_id
                )
                
            except Exception as delete_error:
                self.logger.error(f"Failed to delete message: {delete_error}")
                self.bot.answer_callback_query(
                    call.id, "❌ Failed to delete (insufficient permissions)", show_alert=True
                )
            
        except Exception as e:
            self.logger.error(f"Error in delete message handler: {e}")
            self.bot.answer_callback_query(call.id, "❌ An error occurred", show_alert=True)
    
    def handle_settings_refresh(self, message: Message):
        """Refresh settings display"""
        try:
            # Delete old message and send new one
            self.bot.delete_message(message.chat.id, message.message_id)
            self.handle_settings(message)
        except Exception as e:
            self.logger.error(f"Error refreshing settings: {e}")
    
    def _send_admin_panel(self, chat_id: int):
        """Send admin panel interface"""
        try:
            admin_text = """
👨‍💼 <b>Admin Panel</b>

🔧 <b>Quick Actions:</b>
• /addadmin @username - Add admin
• /ban @username - Ban user
• /whitelist add domain.com - Whitelist domain
• /threshold 75 - Set threat threshold

📊 <b>Management:</b>
• /admin - Full admin menu
• /stats - View statistics
• /settings - Chat settings

Use /help for complete command list.
            """
            
            keyboard = InlineKeyboardMarkup()
            keyboard.row(
                InlineKeyboardButton("📊 Statistics", callback_data="show_stats"),
                InlineKeyboardButton("⚙️ Settings", callback_data="settings_refresh")
            )
            
            self.bot.send_message(
                chat_id,
                admin_text,
                parse_mode='HTML',
                reply_markup=keyboard,
                disable_web_page_preview=True
            )
            
        except Exception as e:
            self.logger.error(f"Error sending admin panel: {e}")
    
    def _is_scan_on_cooldown(self, url: str) -> bool:
        """Check if URL is on scan cooldown"""
        if url not in self.recent_scans:
            return False
        
        last_scan = self.recent_scans[url]
        return (time.time() - last_scan) < self.scan_cooldown
    
    def _format_domain_list(self, domains: List[str]) -> str:
        """Format domain list for display"""
        if not domains:
            return "• <i>None</i>"
        
        if len(domains) <= 5:
            return '\n'.join([f"• <code>{domain}</code>" for domain in domains])
        else:
            visible = domains[:3]
            result = '\n'.join([f"• <code>{domain}</code>" for domain in visible])
            result += f"\n• <i>... and {len(domains) - 3} more</i>"
            return result
    
    def _send_error_message(self, chat_id: int, error_msg: str):
        """Send error message to user"""
        try:
            self.bot.send_message(
                chat_id,
                f"❌ <b>Error</b>\n\n{error_msg}",
                parse_mode='HTML'
            )
        except Exception as e:
            self.logger.error(f"Failed to send error message: {e}")
