"""
URL detection utility for Telegram messages
Extracts and validates URLs from text
"""

import re
from typing import List, Set, Tuple, Dict
from urllib.parse import urlparse, urljoin
import socket

from utils.logger import setup_logger

class URLDetector:
    """Detects and validates URLs in text messages"""
    
    def __init__(self):
        self.logger = setup_logger(__name__)
        
        # Comprehensive URL regex patterns
        self.url_patterns = [
            # Standard HTTP/HTTPS URLs
            re.compile(
                r'https?://(?:[-\w.])+(?::[0-9]+)?(?:/(?:[\w/_.])*)?(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?',
                re.IGNORECASE
            ),
            # URLs without protocol
            re.compile(
                r'(?:www\.)?[-\w.]+\.(?:com|org|net|edu|gov|mil|int|co|io|ly|me|tv|cc|in|de|uk|us|ca|au|jp|cn|ru|br|fr|it|es|nl|se|no|dk|fi|pl|cz|at|ch|be|gr|pt|ie|hu|ro|bg|hr|si|sk|ee|lv|lt|lu|mt|cy|is|li|ad|mc|sm|va|al|ba|mk|me|rs|xk|md|ua|by|ru|ge|am|az|kz|kg|tj|tm|uz|af|pk|in|lk|mv|bt|bd|np|mm|th|la|vn|kh|my|sg|id|ph|bn|tl|pg|sb|vu|nc|fj|tv|ws|to|nz|ck|nu|pn)(?:/(?:[\w/_.])*)?(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?',
                re.IGNORECASE
            ),
            # IP addresses with protocol
            re.compile(
                r'https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?(?:/(?:[\w/_.])*)?(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?',
                re.IGNORECASE
            ),
            # Common URL shorteners
            re.compile(
                r'(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|short\.link|ow\.ly|buff\.ly|is\.gd|v\.gd|tiny\.cc|x\.co|scrnch\.me|filoops\.info|9nl\.com|9nl\.it|adb\.ug|adf\.ly|adfoc\.us|afx\.cc|al\.ly|bc\.vc|buzurl\.com|captur\.in|cf\.ly|cort\.as|cur\.lv|cutt\.us|db\.tt|dft\.ba|dyo\.gs|fas\.li|fur\.ly|gg\.gg|git\.io|goo\.gl|hop\.kz|ick\.li|ift\.tt|ino\.to|j\.mp|lc\.chat|link\.tl|lnk\.co|migre\.me|ow\.ly|po\.st|qr\.ae|qr\.net|rb\.gy|s2r\.co|sh\.st|short\.link|shortcm\.li|shorturl\.at|shr\.lc|snip\.ly|soo\.gd|t2m\.io|t\.ly|tinu\.be|tiny\.cc|tiny\.one|tinyurl\.com|tweez\.me|u\.to|ulvis\.net|ur\.ly|url\.today|urlr\.me|urls\.fr|v\.gd|vzturl\.com|w\.wiki|x\.co|xn--1ca\.to|xurl\.es|y2u\.be|yfrog\.com|ymlp\.com|youtu\.be|zagl\.in)/[A-Za-z0-9_.-]+',
                re.IGNORECASE
            )
        ]
        
        # Common file extensions that might be URLs
        self.file_extensions = {
            '.html', '.htm', '.php', '.asp', '.aspx', '.jsp', '.do', '.action',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.zip',
            '.rar', '.tar', '.gz', '.exe', '.msi', '.dmg', '.pkg', '.deb', '.rpm'
        }
        
        # Common social media and platform domains
        self.known_platforms = {
            'twitter.com', 'facebook.com', 'instagram.com', 'linkedin.com',
            'youtube.com', 'tiktok.com', 'reddit.com', 'telegram.me', 't.me',
            'whatsapp.com', 'discord.gg', 'github.com', 'gitlab.com',
            'stackoverflow.com', 'medium.com', 'pinterest.com', 'tumblr.com'
        }
        
        self.logger.info("🔗 URL detector initialized")
    
    def extract_urls(self, text: str) -> List[str]:
        """
        Extract all URLs from text
        
        Args:
            text: Text to search for URLs
        
        Returns:
            List of unique URLs found
        """
        if not text:
            return []
        
        urls = set()
        
        # Apply all URL patterns
        for pattern in self.url_patterns:
            matches = pattern.findall(text)
            for match in matches:
                clean_url = self._clean_url(match)
                if clean_url and self._is_valid_url(clean_url):
                    urls.add(clean_url)
        
        # Look for Telegram links specifically
        telegram_urls = self._extract_telegram_links(text)
        urls.update(telegram_urls)
        
        # Look for email addresses that might be phishing
        email_urls = self._extract_suspicious_emails(text)
        urls.update(email_urls)
        
        return list(urls)
    
    def _extract_telegram_links(self, text: str) -> List[str]:
        """Extract Telegram-specific links"""
        telegram_patterns = [
            re.compile(r't\.me/[A-Za-z0-9_]+(?:/[0-9]+)?', re.IGNORECASE),
            re.compile(r'telegram\.me/[A-Za-z0-9_]+', re.IGNORECASE),
            re.compile(r'tg://resolve\?domain=[A-Za-z0-9_]+', re.IGNORECASE)
        ]
        
        urls = set()
        for pattern in telegram_patterns:
            matches = pattern.findall(text)
            for match in matches:
                if not match.startswith('http'):
                    match = 'https://' + match
                urls.add(match)
        
        return list(urls)
    
    def _extract_suspicious_emails(self, text: str) -> List[str]:
        """Extract suspicious email addresses that might be phishing"""
        email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
        
        emails = email_pattern.findall(text)
        suspicious_emails = []
        
        for email in emails:
            domain = email.split('@')[1].lower()
            
            # Check for suspicious email domains
            suspicious_keywords = [
                'secure', 'verify', 'update', 'confirm', 'account',
                'support', 'service', 'noreply', 'notification'
            ]
            
            if any(keyword in domain for keyword in suspicious_keywords):
                suspicious_emails.append(f"mailto:{email}")
        
        return suspicious_emails
    
    def _clean_url(self, url: str) -> str:
        """Clean and normalize URL"""
        if not url:
            return ""
        
        url = url.strip()
        
        # Remove trailing punctuation that's not part of URL
        while url and url[-1] in '.,!?;:)]}>"\'':
            url = url[:-1]
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://', 'ftp://', 'mailto:')):
            # Check if it looks like a domain
            if '.' in url and not url.startswith('www.'):
                url = 'http://' + url
            elif url.startswith('www.'):
                url = 'http://' + url
        
        return url
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format and accessibility"""
        try:
            parsed = urlparse(url)
            
            # Must have scheme and netloc
            if not parsed.scheme or not parsed.netloc:
                return False
            
            # Scheme must be valid
            if parsed.scheme not in ['http', 'https', 'ftp', 'mailto', 'tg']:
                return False
            
            # Netloc must be reasonable
            if len(parsed.netloc) < 3 or len(parsed.netloc) > 253:
                return False
            
            # Skip localhost and private IPs for most cases
            if parsed.netloc in ['localhost', '127.0.0.1']:
                return False
            
            # Check for valid domain structure
            if '.' not in parsed.netloc and parsed.scheme in ['http', 'https']:
                return False
            
            return True
            
        except Exception:
            return False
    
    def categorize_urls(self, urls: List[str]) -> Dict[str, List[str]]:
        """
        Categorize URLs by type
        
        Args:
            urls: List of URLs to categorize
        
        Returns:
            Dictionary with categorized URLs
        """
        categories = {
            'social_media': [],
            'url_shorteners': [],
            'file_downloads': [],
            'ip_addresses': [],
            'suspicious': [],
            'telegram': [],
            'email': [],
            'other': []
        }
        
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                path = parsed.path.lower()
                
                # Email addresses
                if url.startswith('mailto:'):
                    categories['email'].append(url)
                # Telegram links
                elif domain in ['t.me', 'telegram.me'] or url.startswith('tg://'):
                    categories['telegram'].append(url)
                # IP addresses
                elif re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', domain):
                    categories['ip_addresses'].append(url)
                # URL shorteners
                elif any(shortener in domain for shortener in [
                    'bit.ly', 'tinyurl', 't.co', 'goo.gl', 'short.link'
                ]):
                    categories['url_shorteners'].append(url)
                # Social media platforms
                elif any(platform in domain for platform in self.known_platforms):
                    categories['social_media'].append(url)
                # File downloads
                elif any(path.endswith(ext) for ext in self.file_extensions):
                    categories['file_downloads'].append(url)
                # Suspicious indicators
                elif self._is_suspicious_url(url):
                    categories['suspicious'].append(url)
                else:
                    categories['other'].append(url)
                    
            except Exception:
                categories['other'].append(url)
        
        return categories
    
    def _is_suspicious_url(self, url: str) -> bool:
        """Check if URL has suspicious characteristics"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # Very long URLs
            if len(url) > 200:
                return True
            
            # Excessive subdomains
            if domain.count('.') > 4:
                return True
            
            # Suspicious keywords in domain
            suspicious_keywords = [
                'secure', 'verify', 'update', 'confirm', 'login',
                'account', 'support', 'service', 'bank', 'paypal'
            ]
            
            if any(keyword in domain for keyword in suspicious_keywords):
                return True
            
            # Suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                return True
            
            # URL with many parameters (potential phishing)
            if parsed.query and parsed.query.count('&') > 10:
                return True
            
            # Mixed case domains (potential homograph attack)
            if domain != domain.lower() and domain != domain.upper():
                return True
            
            return False
            
        except Exception:
            return False
    
    def get_url_info(self, url: str) -> Dict[str, any]:
        """
        Get detailed information about a URL
        
        Args:
            url: URL to analyze
        
        Returns:
            Dictionary with URL information
        """
        try:
            parsed = urlparse(url)
            
            info = {
                'original_url': url,
                'scheme': parsed.scheme,
                'domain': parsed.netloc.lower(),
                'path': parsed.path,
                'query': parsed.query,
                'fragment': parsed.fragment,
                'is_valid': self._is_valid_url(url),
                'is_suspicious': self._is_suspicious_url(url),
                'url_length': len(url),
                'subdomain_count': parsed.netloc.count('.'),
                'has_query_params': bool(parsed.query),
                'has_fragment': bool(parsed.fragment)
            }
            
            # Add category information
            categories = self.categorize_urls([url])
            for category, urls in categories.items():
                if url in urls:
                    info['category'] = category
                    break
            else:
                info['category'] = 'unknown'
            
            # Add port information if present
            if ':' in parsed.netloc:
                try:
                    port = int(parsed.netloc.split(':')[1])
                    info['port'] = port
                    info['non_standard_port'] = port not in [80, 443]
                except ValueError:
                    pass
            
            return info
            
        except Exception as e:
            return {
                'original_url': url,
                'error': str(e),
                'is_valid': False,
                'is_suspicious': True
            }
    
    def extract_domains(self, urls: List[str]) -> Set[str]:
        """
        Extract unique domains from list of URLs
        
        Args:
            urls: List of URLs
        
        Returns:
            Set of unique domains
        """
        domains = set()
        
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    domains.add(parsed.netloc.lower())
            except Exception:
                continue
        
        return domains
    
    def is_url_reachable(self, url: str, timeout: int = 5) -> Tuple[bool, str]:
        """
        Check if URL is reachable (basic connectivity test)
        
        Args:
            url: URL to check
            timeout: Timeout in seconds
        
        Returns:
            Tuple of (is_reachable, status_message)
        """
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return False, "Invalid URL format"
            
            # Extract host and port
            host = parsed.netloc
            port = 80 if parsed.scheme == 'http' else 443
            
            if ':' in host:
                host, port_str = host.split(':')
                try:
                    port = int(port_str)
                except ValueError:
                    return False, "Invalid port number"
            
            # Try to connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                return True, "URL is reachable"
            else:
                return False, f"Connection failed (error {result})"
                
        except socket.gaierror:
            return False, "Domain name resolution failed"
        except socket.timeout:
            return False, "Connection timeout"
        except Exception as e:
            return False, f"Connection error: {str(e)}"
