"""
Admin management service for Telegram Security Bot
Handles group/channel administration and permissions
"""

from typing import Dict, List, Optional, Set, Tuple
import telebot
from telebot.types import ChatMember

from database import Database
from utils.logger import setup_logger

class AdminManager:
    """Manages bot administration and permissions"""
    
    def __init__(self, db: Database):
        self.db = db
        self.logger = setup_logger(__name__)
        
        # Define permission levels
        self.PERMISSIONS = {
            'scan_urls': 'Can manually scan URLs',
            'modify_settings': 'Can modify chat settings',
            'manage_whitelist': 'Can manage URL whitelist',
            'manage_blacklist': 'Can manage URL blacklist', 
            'ban_users': 'Can ban/unban users',
            'manage_admins': 'Can add/remove bot admins',
            'view_stats': 'Can view bot statistics',
            'delete_messages': 'Can delete malicious messages'
        }
        
        # Default permissions for different roles
        self.DEFAULT_PERMISSIONS = {
            'admin': ['scan_urls', 'modify_settings', 'view_stats'],
            'moderator': ['scan_urls', 'ban_users', 'delete_messages'],
            'scanner': ['scan_urls', 'view_stats']
        }
        
        self.logger.info("👥 Admin manager initialized")
    
    def is_user_admin(self, chat_id: int, user_id: int, bot: telebot.TeleBot) -> bool:
        """
        Check if user is admin (Telegram admin or bot admin)
        
        Args:
            chat_id: Chat ID
            user_id: User ID
            bot: Bot instance
        
        Returns:
            True if user is admin
        """
        try:
            # Check if user is Telegram chat admin
            chat_member = bot.get_chat_member(chat_id, user_id)
            if chat_member.status in ['creator', 'administrator']:
                return True
            
            # Check if user is bot admin
            return self.db.is_chat_admin(chat_id, user_id)
            
        except Exception as e:
            self.logger.error(f"Error checking admin status: {e}")
            return False
    
    def has_permission(self, chat_id: int, user_id: int, permission: str, bot: telebot.TeleBot) -> bool:
        """
        Check if user has specific permission
        
        Args:
            chat_id: Chat ID
            user_id: User ID
            permission: Permission to check
            bot: Bot instance
        
        Returns:
            True if user has permission
        """
        try:
            # Telegram admins have all permissions
            chat_member = bot.get_chat_member(chat_id, user_id)
            if chat_member.status in ['creator', 'administrator']:
                return True
            
            # Check bot admin permissions
            admins = self.db.get_chat_admins(chat_id)
            for admin in admins:
                if admin['user_id'] == user_id:
                    return permission in admin['permissions']
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking permission: {e}")
            return False
    
    def add_admin(self, chat_id: int, user_id: int, username: Optional[str] = None,
                  role: str = 'admin', added_by: Optional[int] = None) -> bool:
        """
        Add bot admin with default permissions for role
        
        Args:
            chat_id: Chat ID
            user_id: User ID to make admin
            username: Username (optional)
            role: Admin role (admin, moderator, scanner)
            added_by: User ID who added the admin
        
        Returns:
            True if successful
        """
        try:
            permissions = self.DEFAULT_PERMISSIONS.get(role, self.DEFAULT_PERMISSIONS['scanner'])
            
            success = self.db.add_chat_admin(
                chat_id=chat_id,
                user_id=user_id,
                username=username,
                permissions=permissions,
                added_by=added_by
            )
            
            if success:
                self.logger.info(f"✅ Added admin {user_id} to chat {chat_id} with role {role}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error adding admin: {e}")
            return False
    
    def remove_admin(self, chat_id: int, user_id: int) -> bool:
        """
        Remove bot admin
        
        Args:
            chat_id: Chat ID
            user_id: User ID to remove
        
        Returns:
            True if successful
        """
        try:
            success = self.db.remove_chat_admin(chat_id, user_id)
            
            if success:
                self.logger.info(f"🗑️ Removed admin {user_id} from chat {chat_id}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error removing admin: {e}")
            return False
    
    def update_admin_permissions(self, chat_id: int, user_id: int, 
                               permissions: List[str]) -> bool:
        """
        Update admin permissions
        
        Args:
            chat_id: Chat ID
            user_id: User ID
            permissions: List of permissions
        
        Returns:
            True if successful
        """
        try:
            # Validate permissions
            valid_permissions = [p for p in permissions if p in self.PERMISSIONS]
            
            success = self.db.add_chat_admin(
                chat_id=chat_id,
                user_id=user_id,
                permissions=valid_permissions
            )
            
            if success:
                self.logger.info(f"🔧 Updated permissions for admin {user_id} in chat {chat_id}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error updating admin permissions: {e}")
            return False
    
    def ban_user(self, chat_id: int, user_id: int, username: Optional[str] = None,
                reason: Optional[str] = None, banned_by: Optional[int] = None,
                bot: Optional[telebot.TeleBot] = None) -> bool:
        """
        Ban user from chat
        
        Args:
            chat_id: Chat ID
            user_id: User ID to ban
            username: Username (optional)
            reason: Ban reason
            banned_by: User ID who issued the ban
            bot: Bot instance for Telegram actions
        
        Returns:
            True if successful
        """
        try:
            # Add to database
            success = self.db.ban_user(
                chat_id=chat_id,
                user_id=user_id,
                username=username,
                reason=reason,
                banned_by=banned_by
            )
            
            # Try to ban in Telegram if bot instance provided
            if success and bot and chat_id < 0:  # Group chat
                try:
                    bot.ban_chat_member(chat_id, user_id)
                    self.logger.info(f"🚫 Banned user {user_id} from Telegram chat {chat_id}")
                except Exception as e:
                    self.logger.warning(f"Could not ban user in Telegram: {e}")
            
            if success:
                self.logger.info(f"🚫 Banned user {user_id} from chat {chat_id}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error banning user: {e}")
            return False
    
    def unban_user(self, chat_id: int, user_id: int, bot: Optional[telebot.TeleBot] = None) -> bool:
        """
        Unban user from chat
        
        Args:
            chat_id: Chat ID
            user_id: User ID to unban
            bot: Bot instance for Telegram actions
        
        Returns:
            True if successful
        """
        try:
            # Remove from database
            success = self.db.unban_user(chat_id, user_id)
            
            # Try to unban in Telegram if bot instance provided
            if success and bot and chat_id < 0:  # Group chat
                try:
                    bot.unban_chat_member(chat_id, user_id)
                    self.logger.info(f"✅ Unbanned user {user_id} from Telegram chat {chat_id}")
                except Exception as e:
                    self.logger.warning(f"Could not unban user in Telegram: {e}")
            
            if success:
                self.logger.info(f"✅ Unbanned user {user_id} from chat {chat_id}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error unbanning user: {e}")
            return False
    
    def is_user_banned(self, chat_id: int, user_id: int) -> bool:
        """
        Check if user is banned
        
        Args:
            chat_id: Chat ID
            user_id: User ID
        
        Returns:
            True if user is banned
        """
        return self.db.is_user_banned(chat_id, user_id)
    
    def get_chat_admins(self, chat_id: int) -> List[Dict]:
        """
        Get all bot admins for chat
        
        Args:
            chat_id: Chat ID
        
        Returns:
            List of admin information
        """
        return self.db.get_chat_admins(chat_id)
    
    def get_telegram_admins(self, chat_id: int, bot: telebot.TeleBot) -> List[Dict]:
        """
        Get Telegram chat administrators
        
        Args:
            chat_id: Chat ID
            bot: Bot instance
        
        Returns:
            List of Telegram admin information
        """
        try:
            administrators = bot.get_chat_administrators(chat_id)
            
            admin_list = []
            for admin in administrators:
                admin_info = {
                    'user_id': admin.user.id,
                    'username': admin.user.username,
                    'first_name': admin.user.first_name,
                    'last_name': admin.user.last_name,
                    'status': admin.status,
                    'is_bot': admin.user.is_bot
                }
                
                # Add admin-specific permissions if available
                if hasattr(admin, 'can_delete_messages'):
                    admin_info['can_delete_messages'] = admin.can_delete_messages
                if hasattr(admin, 'can_restrict_members'):
                    admin_info['can_restrict_members'] = admin.can_restrict_members
                
                admin_list.append(admin_info)
            
            return admin_list
            
        except Exception as e:
            self.logger.error(f"Error getting Telegram admins: {e}")
            return []
    
    def sync_telegram_admins(self, chat_id: int, bot: telebot.TeleBot) -> int:
        """
        Sync Telegram administrators as bot admins
        
        Args:
            chat_id: Chat ID
            bot: Bot instance
        
        Returns:
            Number of admins synced
        """
        try:
            telegram_admins = self.get_telegram_admins(chat_id, bot)
            synced_count = 0
            
            for admin in telegram_admins:
                if not admin['is_bot']:  # Don't sync bot accounts
                    success = self.add_admin(
                        chat_id=chat_id,
                        user_id=admin['user_id'],
                        username=admin['username'],
                        role='admin'
                    )
                    if success:
                        synced_count += 1
            
            self.logger.info(f"🔄 Synced {synced_count} Telegram admins for chat {chat_id}")
            return synced_count
            
        except Exception as e:
            self.logger.error(f"Error syncing Telegram admins: {e}")
            return 0
    
    def get_admin_summary(self, chat_id: int, bot: telebot.TeleBot) -> Dict:
        """
        Get comprehensive admin summary for chat
        
        Args:
            chat_id: Chat ID
            bot: Bot instance
        
        Returns:
            Admin summary information
        """
        try:
            bot_admins = self.get_chat_admins(chat_id)
            telegram_admins = self.get_telegram_admins(chat_id, bot)
            
            return {
                'chat_id': chat_id,
                'bot_admins_count': len(bot_admins),
                'telegram_admins_count': len(telegram_admins),
                'bot_admins': bot_admins,
                'telegram_admins': telegram_admins,
                'available_permissions': self.PERMISSIONS,
                'default_roles': self.DEFAULT_PERMISSIONS
            }
            
        except Exception as e:
            self.logger.error(f"Error getting admin summary: {e}")
            return {
                'chat_id': chat_id,
                'bot_admins_count': 0,
                'telegram_admins_count': 0,
                'bot_admins': [],
                'telegram_admins': [],
                'error': str(e)
            }
    
    def cleanup_inactive_admins(self, chat_id: int, bot: telebot.TeleBot) -> int:
        """
        Remove bot admins who are no longer Telegram admins
        
        Args:
            chat_id: Chat ID
            bot: Bot instance
        
        Returns:
            Number of admins removed
        """
        try:
            bot_admins = self.get_chat_admins(chat_id)
            telegram_admins = self.get_telegram_admins(chat_id, bot)
            telegram_admin_ids = {admin['user_id'] for admin in telegram_admins}
            
            removed_count = 0
            for bot_admin in bot_admins:
                user_id = bot_admin['user_id']
                
                # Check if still Telegram admin
                if user_id not in telegram_admin_ids:
                    # Check if user is still in chat
                    try:
                        member = bot.get_chat_member(chat_id, user_id)
                        if member.status in ['left', 'kicked']:
                            success = self.remove_admin(chat_id, user_id)
                            if success:
                                removed_count += 1
                    except Exception:
                        # User probably left, remove admin status
                        success = self.remove_admin(chat_id, user_id)
                        if success:
                            removed_count += 1
            
            if removed_count > 0:
                self.logger.info(f"🧹 Removed {removed_count} inactive admins from chat {chat_id}")
            
            return removed_count
            
        except Exception as e:
            self.logger.error(f"Error cleaning up admins: {e}")
            return 0
