"""
Admin handler for Telegram Security Bot
Handles admin commands and group management
"""

import re
from typing import List, Optional, Dict, Any

import telebot
from telebot.types import Message, InlineKeyboardMarkup, InlineKeyboardButton

from database import Database
from services.admin_manager import AdminManager
from utils.logger import BotLogger

class AdminHandler:
    """Handles admin commands and group management"""
    
    def __init__(self, bot: telebot.TeleBot, admin_manager: AdminManager, db: Database):
        self.bot = bot
        self.admin_manager = admin_manager
        self.db = db
        self.logger = BotLogger(__name__)
        
        self.logger.info("👨‍💼 Admin handler initialized")
    
    def handle_admin(self, message: Message):
        """Handle /admin command - show admin panel"""
        try:
            user_id = message.from_user.id
            username = message.from_user.username or "Unknown"
            chat_id = message.chat.id
            
            # Check if user is admin
            if not self.admin_manager.is_user_admin(chat_id, user_id, self.bot):
                self.bot.reply_to(message, "❌ Admin access required.")
                return
            
            self.logger.log_admin_action(user_id, username, chat_id, "Opened admin panel")
            
            # Get admin summary
            summary = self.admin_manager.get_admin_summary(chat_id, self.bot)
            chat_settings = self.db.get_chat_settings(chat_id)
            
            admin_text = f"""
👨‍💼 <b>Administration Panel</b>

<b>📊 Chat Overview:</b>
• Chat ID: <code>{chat_id}</code>
• Telegram Admins: {summary['telegram_admins_count']}
• Bot Admins: {summary['bot_admins_count']}

<b>🔧 Current Settings:</b>
• Auto Scan: {'✅' if chat_settings['auto_scan_enabled'] else '❌'}
• Threat Threshold: {chat_settings['threat_threshold']}/100
• Alert Admins: {'✅' if chat_settings['alert_admins'] else '❌'}
• Delete Malicious: {'✅' if chat_settings['delete_malicious'] else '❌'}

<b>📝 Lists:</b>
• Whitelist: {len(chat_settings['whitelist'])} domains
• Blacklist: {len(chat_settings['blacklist'])} domains

<b>🔨 Quick Commands:</b>
• /addadmin @user - Add bot admin
• /ban @user - Ban user
• /threshold &lt;50-90&gt; - Set threshold
• /whitelist add domain.com - Add to whitelist
            """
            
            # Create admin panel keyboard
            keyboard = InlineKeyboardMarkup()
            keyboard.row(
                InlineKeyboardButton("👥 Manage Admins", callback_data="admin_manage_admins"),
                InlineKeyboardButton("⚙️ Settings", callback_data="admin_settings")
            )
            keyboard.row(
                InlineKeyboardButton("📝 Whitelist", callback_data="admin_whitelist"),
                InlineKeyboardButton("⛔ Blacklist", callback_data="admin_blacklist")
            )
            keyboard.row(
                InlineKeyboardButton("🚫 Banned Users", callback_data="admin_banned"),
                InlineKeyboardButton("📊 Statistics", callback_data="admin_stats")
            )
            keyboard.row(
                InlineKeyboardButton("🔄 Sync TG Admins", callback_data="admin_sync"),
                InlineKeyboardButton("🧹 Cleanup", callback_data="admin_cleanup")
            )
            
            self.bot.send_message(
                chat_id,
                admin_text,
                parse_mode='HTML',
                reply_markup=keyboard,
                disable_web_page_preview=True
            )
            
        except Exception as e:
            self.logger.error(f"Error in admin handler: {e}")
            self.bot.reply_to(message, "❌ Failed to load admin panel.")
    
    def handle_add_admin(self, message: Message):
        """Handle /addadmin command"""
        try:
            user_id = message.from_user.id
            username = message.from_user.username or "Unknown"
            chat_id = message.chat.id
            
            # Check if user has admin management permission
            if not self.admin_manager.has_permission(chat_id, user_id, 'manage_admins', self.bot):
                self.bot.reply_to(message, "❌ You don't have permission to manage admins.")
                return
            
            # Parse command
            command_parts = message.text.split()
            if len(command_parts) < 2:
                self.bot.reply_to(
                    message,
                    "❌ Usage: /addadmin @username [role]\n\n"
                    "Available roles: admin, moderator, scanner\n"
                    "Default role: admin"
                )
                return
            
            # Extract target username
            target_username = command_parts[1].lstrip('@')
            role = command_parts[2] if len(command_parts) > 2 else 'admin'
            
            if role not in ['admin', 'moderator', 'scanner']:
                self.bot.reply_to(message, "❌ Invalid role. Use: admin, moderator, or scanner")
                return
            
            # Try to get user info
            try:
                # In a group, we can try to find the user by username
                target_user = None
                target_user_id = None
                
                # If replying to a message, use that user
                if message.reply_to_message:
                    target_user = message.reply_to_message.from_user
                    target_user_id = target_user.id
                    target_username = target_user.username or target_username
                else:
                    # Try to parse user ID if provided as number
                    if command_parts[1].isdigit():
                        target_user_id = int(command_parts[1])
                        target_username = f"User{target_user_id}"
                    else:
                        self.bot.reply_to(
                            message,
                            "❌ Please reply to a user's message or provide their user ID.\n"
                            "Usage: /addadmin @username or /addadmin 123456789"
                        )
                        return
                
                # Add admin
                success = self.admin_manager.add_admin(
                    chat_id=chat_id,
                    user_id=target_user_id,
                    username=target_username,
                    role=role,
                    added_by=user_id
                )
                
                if success:
                    self.bot.reply_to(
                        message,
                        f"✅ Successfully added @{target_username} as {role}."
                    )
                    
                    self.logger.log_admin_action(
                        user_id, username, chat_id,
                        f"Added admin: @{target_username} as {role}",
                        target_user_id
                    )
                else:
                    self.bot.reply_to(message, "❌ Failed to add admin (already exists?).")
                
            except Exception as user_error:
                self.logger.error(f"Error finding user: {user_error}")
                self.bot.reply_to(
                    message,
                    "❌ Could not find user. Please reply to their message or provide user ID."
                )
            
        except Exception as e:
            self.logger.error(f"Error in add admin handler: {e}")
            self.bot.reply_to(message, "❌ Failed to add admin.")
    
    def handle_remove_admin(self, message: Message):
        """Handle /removeadmin command"""
        try:
            user_id = message.from_user.id
            username = message.from_user.username or "Unknown"
            chat_id = message.chat.id
            
            # Check permissions
            if not self.admin_manager.has_permission(chat_id, user_id, 'manage_admins', self.bot):
                self.bot.reply_to(message, "❌ You don't have permission to manage admins.")
                return
            
            # Parse command
            command_parts = message.text.split()
            if len(command_parts) < 2:
                self.bot.reply_to(message, "❌ Usage: /removeadmin @username or reply to user's message")
                return
            
            # Get target user
            target_user_id = None
            target_username = "Unknown"
            
            if message.reply_to_message:
                target_user_id = message.reply_to_message.from_user.id
                target_username = message.reply_to_message.from_user.username or "Unknown"
            elif command_parts[1].isdigit():
                target_user_id = int(command_parts[1])
                target_username = f"User{target_user_id}"
            else:
                # Try to find by username in admin list
                admins = self.admin_manager.get_chat_admins(chat_id)
                target_username = command_parts[1].lstrip('@')
                
                for admin in admins:
                    if admin['username'] == target_username:
                        target_user_id = admin['user_id']
                        break
                
                if not target_user_id:
                    self.bot.reply_to(message, "❌ Admin not found. Reply to their message or use user ID.")
                    return
            
            # Remove admin
            success = self.admin_manager.remove_admin(chat_id, target_user_id)
            
            if success:
                self.bot.reply_to(message, f"✅ Removed @{target_username} from admin list.")
                
                self.logger.log_admin_action(
                    user_id, username, chat_id,
                    f"Removed admin: @{target_username}",
                    target_user_id
                )
            else:
                self.bot.reply_to(message, "❌ Failed to remove admin (not found?).")
            
        except Exception as e:
            self.logger.error(f"Error in remove admin handler: {e}")
            self.bot.reply_to(message, "❌ Failed to remove admin.")
    
    def handle_ban(self, message: Message):
        """Handle /ban command"""
        try:
            user_id = message.from_user.id
            username = message.from_user.username or "Unknown"
            chat_id = message.chat.id
            
            # Check permissions
            if not self.admin_manager.has_permission(chat_id, user_id, 'ban_users', self.bot):
                self.bot.reply_to(message, "❌ You don't have permission to ban users.")
                return
            
            # Must reply to a message
            if not message.reply_to_message:
                self.bot.reply_to(message, "❌ Reply to a user's message to ban them.")
                return
            
            target_user = message.reply_to_message.from_user
            target_user_id = target_user.id
            target_username = target_user.username or "Unknown"
            
            # Don't ban other admins
            if self.admin_manager.is_user_admin(chat_id, target_user_id, self.bot):
                self.bot.reply_to(message, "❌ Cannot ban other admins.")
                return
            
            # Parse reason
            command_parts = message.text.split(None, 1)
            reason = command_parts[1] if len(command_parts) > 1 else "No reason provided"
            
            # Ban user
            success = self.admin_manager.ban_user(
                chat_id=chat_id,
                user_id=target_user_id,
                username=target_username,
                reason=reason,
                banned_by=user_id,
                bot=self.bot
            )
            
            if success:
                self.bot.reply_to(
                    message,
                    f"🚫 Banned @{target_username}\n"
                    f"Reason: {reason}"
                )
                
                self.logger.log_admin_action(
                    user_id, username, chat_id,
                    f"Banned user: @{target_username}",
                    target_user_id,
                    f"Reason: {reason}"
                )
            else:
                self.bot.reply_to(message, "❌ Failed to ban user (already banned?).")
            
        except Exception as e:
            self.logger.error(f"Error in ban handler: {e}")
            self.bot.reply_to(message, "❌ Failed to ban user.")
    
    def handle_unban(self, message: Message):
        """Handle /unban command"""
        try:
            user_id = message.from_user.id
            username = message.from_user.username or "Unknown"
            chat_id = message.chat.id
            
            # Check permissions
            if not self.admin_manager.has_permission(chat_id, user_id, 'ban_users', self.bot):
                self.bot.reply_to(message, "❌ You don't have permission to unban users.")
                return
            
            # Parse command
            command_parts = message.text.split()
            if len(command_parts) < 2:
                self.bot.reply_to(message, "❌ Usage: /unban @username or /unban 123456789")
                return
            
            # Get target user
            target_input = command_parts[1]
            target_user_id = None
            target_username = "Unknown"
            
            if target_input.isdigit():
                target_user_id = int(target_input)
                target_username = f"User{target_user_id}"
            elif message.reply_to_message:
                target_user_id = message.reply_to_message.from_user.id
                target_username = message.reply_to_message.from_user.username or "Unknown"
            else:
                self.bot.reply_to(message, "❌ Provide user ID or reply to their message.")
                return
            
            # Unban user
            success = self.admin_manager.unban_user(chat_id, target_user_id, self.bot)
            
            if success:
                self.bot.reply_to(message, f"✅ Unbanned @{target_username}")
                
                self.logger.log_admin_action(
                    user_id, username, chat_id,
                    f"Unbanned user: @{target_username}",
                    target_user_id
                )
            else:
                self.bot.reply_to(message, "❌ Failed to unban user (not banned?).")
            
        except Exception as e:
            self.logger.error(f"Error in unban handler: {e}")
            self.bot.reply_to(message, "❌ Failed to unban user.")
    
    def handle_whitelist(self, message: Message):
        """Handle /whitelist command"""
        try:
            user_id = message.from_user.id
            username = message.from_user.username or "Unknown"
            chat_id = message.chat.id
            
            # Check permissions
            if not self.admin_manager.has_permission(chat_id, user_id, 'manage_whitelist', self.bot):
                self.bot.reply_to(message, "❌ You don't have permission to manage whitelist.")
                return
            
            # Parse command
            command_parts = message.text.split()
            if len(command_parts) < 2:
                self._show_whitelist_help(message)
                return
            
            action = command_parts[1].lower()
            chat_settings = self.db.get_chat_settings(chat_id)
            whitelist = chat_settings['whitelist']
            
            if action == 'list':
                self._show_whitelist(message, whitelist)
                
            elif action == 'add' and len(command_parts) >= 3:
                domain = command_parts[2].lower().strip()
                
                if self._is_valid_domain(domain):
                    if domain not in whitelist:
                        whitelist.append(domain)
                        self.db.update_chat_settings(chat_id, whitelist=whitelist)
                        
                        self.bot.reply_to(message, f"✅ Added {domain} to whitelist.")
                        
                        self.logger.log_admin_action(
                            user_id, username, chat_id,
                            f"Added to whitelist: {domain}"
                        )
                    else:
                        self.bot.reply_to(message, f"❌ {domain} is already in whitelist.")
                else:
                    self.bot.reply_to(message, "❌ Invalid domain format.")
                    
            elif action == 'remove' and len(command_parts) >= 3:
                domain = command_parts[2].lower().strip()
                
                if domain in whitelist:
                    whitelist.remove(domain)
                    self.db.update_chat_settings(chat_id, whitelist=whitelist)
                    
                    self.bot.reply_to(message, f"✅ Removed {domain} from whitelist.")
                    
                    self.logger.log_admin_action(
                        user_id, username, chat_id,
                        f"Removed from whitelist: {domain}"
                    )
                else:
                    self.bot.reply_to(message, f"❌ {domain} is not in whitelist.")
            
            elif action == 'clear':
                self.db.update_chat_settings(chat_id, whitelist=[])
                self.bot.reply_to(message, "✅ Whitelist cleared.")
                
                self.logger.log_admin_action(user_id, username, chat_id, "Cleared whitelist")
            
            else:
                self._show_whitelist_help(message)
            
        except Exception as e:
            self.logger.error(f"Error in whitelist handler: {e}")
            self.bot.reply_to(message, "❌ Failed to manage whitelist.")
    
    def handle_blacklist(self, message: Message):
        """Handle /blacklist command"""
        try:
            user_id = message.from_user.id
            username = message.from_user.username or "Unknown"
            chat_id = message.chat.id
            
            # Check permissions
            if not self.admin_manager.has_permission(chat_id, user_id, 'manage_blacklist', self.bot):
                self.bot.reply_to(message, "❌ You don't have permission to manage blacklist.")
                return
            
            # Parse command
            command_parts = message.text.split()
            if len(command_parts) < 2:
                self._show_blacklist_help(message)
                return
            
            action = command_parts[1].lower()
            chat_settings = self.db.get_chat_settings(chat_id)
            blacklist = chat_settings['blacklist']
            
            if action == 'list':
                self._show_blacklist(message, blacklist)
                
            elif action == 'add' and len(command_parts) >= 3:
                domain = command_parts[2].lower().strip()
                
                if self._is_valid_domain(domain):
                    if domain not in blacklist:
                        blacklist.append(domain)
                        self.db.update_chat_settings(chat_id, blacklist=blacklist)
                        
                        self.bot.reply_to(message, f"✅ Added {domain} to blacklist.")
                        
                        self.logger.log_admin_action(
                            user_id, username, chat_id,
                            f"Added to blacklist: {domain}"
                        )
                    else:
                        self.bot.reply_to(message, f"❌ {domain} is already in blacklist.")
                else:
                    self.bot.reply_to(message, "❌ Invalid domain format.")
                    
            elif action == 'remove' and len(command_parts) >= 3:
                domain = command_parts[2].lower().strip()
                
                if domain in blacklist:
                    blacklist.remove(domain)
                    self.db.update_chat_settings(chat_id, blacklist=blacklist)
                    
                    self.bot.reply_to(message, f"✅ Removed {domain} from blacklist.")
                    
                    self.logger.log_admin_action(
                        user_id, username, chat_id,
                        f"Removed from blacklist: {domain}"
                    )
                else:
                    self.bot.reply_to(message, f"❌ {domain} is not in blacklist.")
            
            elif action == 'clear':
                self.db.update_chat_settings(chat_id, blacklist=[])
                self.bot.reply_to(message, "✅ Blacklist cleared.")
                
                self.logger.log_admin_action(user_id, username, chat_id, "Cleared blacklist")
            
            else:
                self._show_blacklist_help(message)
            
        except Exception as e:
            self.logger.error(f"Error in blacklist handler: {e}")
            self.bot.reply_to(message, "❌ Failed to manage blacklist.")
    
    def handle_threshold(self, message: Message):
        """Handle /threshold command"""
        try:
            user_id = message.from_user.id
            username = message.from_user.username or "Unknown"
            chat_id = message.chat.id
            
            # Check permissions
            if not self.admin_manager.has_permission(chat_id, user_id, 'modify_settings', self.bot):
                self.bot.reply_to(message, "❌ You don't have permission to modify settings.")
                return
            
            # Parse command
            command_parts = message.text.split()
            if len(command_parts) < 2:
                chat_settings = self.db.get_chat_settings(chat_id)
                current_threshold = chat_settings['threat_threshold']
                
                self.bot.reply_to(
                    message,
                    f"🎯 <b>Current Threat Threshold: {current_threshold}/100</b>\n\n"
                    f"Usage: /threshold &lt;1-100&gt;\n\n"
                    f"<b>Recommended values:</b>\n"
                    f"• 30-40: Very sensitive (catch more)\n"
                    f"• 50-60: Balanced (default)\n"
                    f"• 70-80: Conservative (catch less)\n"
                    f"• 90+: Only high confidence threats",
                    parse_mode='HTML'
                )
                return
            
            try:
                new_threshold = int(command_parts[1])
                
                if not 1 <= new_threshold <= 100:
                    self.bot.reply_to(message, "❌ Threshold must be between 1 and 100.")
                    return
                
                self.db.update_chat_settings(chat_id, threat_threshold=new_threshold)
                
                self.bot.reply_to(
                    message,
                    f"✅ Threat threshold set to {new_threshold}/100"
                )
                
                self.logger.log_admin_action(
                    user_id, username, chat_id,
                    f"Changed threat threshold to {new_threshold}"
                )
                
            except ValueError:
                self.bot.reply_to(message, "❌ Invalid threshold value. Use a number between 1-100.")
            
        except Exception as e:
            self.logger.error(f"Error in threshold handler: {e}")
            self.bot.reply_to(message, "❌ Failed to set threshold.")
    
    def _show_whitelist_help(self, message: Message):
        """Show whitelist help"""
        help_text = """
📝 <b>Whitelist Management</b>

<b>Commands:</b>
• <code>/whitelist list</code> - Show current whitelist
• <code>/whitelist add domain.com</code> - Add domain
• <code>/whitelist remove domain.com</code> - Remove domain
• <code>/whitelist clear</code> - Clear all entries

<b>Note:</b> Whitelisted domains are never flagged as malicious.
        """
        
        self.bot.reply_to(message, help_text, parse_mode='HTML')
    
    def _show_blacklist_help(self, message: Message):
        """Show blacklist help"""
        help_text = """
⛔ <b>Blacklist Management</b>

<b>Commands:</b>
• <code>/blacklist list</code> - Show current blacklist
• <code>/blacklist add domain.com</code> - Add domain
• <code>/blacklist remove domain.com</code> - Remove domain
• <code>/blacklist clear</code> - Clear all entries

<b>Note:</b> Blacklisted domains are always flagged as malicious.
        """
        
        self.bot.reply_to(message, help_text, parse_mode='HTML')
    
    def _show_whitelist(self, message: Message, whitelist: List[str]):
        """Show current whitelist"""
        if not whitelist:
            self.bot.reply_to(message, "📝 Whitelist is empty.")
            return
        
        whitelist_text = f"📝 <b>Whitelist ({len(whitelist)} domains):</b>\n\n"
        
        for i, domain in enumerate(whitelist, 1):
            whitelist_text += f"{i}. <code>{domain}</code>\n"
            
            # Split long messages
            if len(whitelist_text) > 3500:
                whitelist_text += f"\n<i>... and {len(whitelist) - i} more domains</i>"
                break
        
        self.bot.reply_to(message, whitelist_text, parse_mode='HTML')
    
    def _show_blacklist(self, message: Message, blacklist: List[str]):
        """Show current blacklist"""
        if not blacklist:
            self.bot.reply_to(message, "⛔ Blacklist is empty.")
            return
        
        blacklist_text = f"⛔ <b>Blacklist ({len(blacklist)} domains):</b>\n\n"
        
        for i, domain in enumerate(blacklist, 1):
            blacklist_text += f"{i}. <code>{domain}</code>\n"
            
            # Split long messages
            if len(blacklist_text) > 3500:
                blacklist_text += f"\n<i>... and {len(blacklist) - i} more domains</i>"
                break
        
        self.bot.reply_to(message, blacklist_text, parse_mode='HTML')
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format"""
        # Basic domain validation
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        return (
            domain and
            len(domain) <= 253 and
            '.' in domain and
            domain_pattern.match(domain) and
            not domain.startswith('.') and
            not domain.endswith('.')
        )
