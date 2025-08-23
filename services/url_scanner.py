"""
URLScan.io API integration service
Provides comprehensive URL scanning and threat analysis
"""

import time
import requests
from typing import Dict, Optional, Tuple, List
from datetime import datetime, timedelta

from utils.logger import setup_logger
from utils.rate_limiter import RateLimiter

class URLScanner:
    """URLScan.io API integration for URL threat analysis"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.logger = setup_logger(__name__)
        self.base_url = "https://urlscan.io/api/v1"
        self.rate_limiter = RateLimiter(max_requests=10, time_window=60)  # 10 requests per minute
        
        # Session for connection pooling
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'TelegramSecurityBot/1.0',
            'Content-Type': 'application/json'
        })
        
        if api_key:
            self.session.headers.update({'API-Key': api_key})
        
        self.logger.info(f"🔍 URLScan.io service initialized (API key: {'✓' if api_key else '✗'})")
    
    def submit_url(self, url: str, visibility: str = "unlisted") -> Optional[str]:
        """
        Submit URL for scanning
        
        Args:
            url: URL to scan
            visibility: 'public', 'unlisted', or 'private'
        
        Returns:
            Scan UUID if successful, None otherwise
        """
        if not self.api_key:
            self.logger.warning("URLScan.io API key not available")
            return None
        
        if not self.rate_limiter.can_make_request():
            self.logger.warning("URLScan.io rate limit reached")
            return None
        
        try:
            payload = {
                "url": url,
                "visibility": visibility,
                "tags": ["telegram-security-bot"]
            }
            
            response = self.session.post(
                f"{self.base_url}/scan/",
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                uuid = data.get('uuid')
                self.logger.info(f"✅ URL submitted for scanning: {uuid}")
                return uuid
            
            elif response.status_code == 429:
                self.logger.warning("URLScan.io rate limit exceeded")
                return None
            
            else:
                self.logger.error(f"URLScan.io submission failed: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"URLScan.io request error: {e}")
            return None
        except Exception as e:
            self.logger.error(f"URLScan.io unexpected error: {e}")
            return None
    
    def get_scan_result(self, uuid: str, max_wait: int = 60) -> Optional[Dict]:
        """
        Get scan result by UUID with polling
        
        Args:
            uuid: Scan UUID
            max_wait: Maximum time to wait for results in seconds
        
        Returns:
            Scan result dictionary if successful, None otherwise
        """
        if not uuid:
            return None
        
        start_time = time.time()
        poll_interval = 5  # Start with 5 seconds
        
        while time.time() - start_time < max_wait:
            try:
                response = self.session.get(
                    f"{self.base_url}/result/{uuid}/",
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    self.logger.info(f"✅ Scan results retrieved: {uuid}")
                    return data
                
                elif response.status_code == 404:
                    # Scan still processing
                    self.logger.debug(f"⏳ Scan still processing: {uuid}")
                    time.sleep(poll_interval)
                    poll_interval = min(poll_interval + 2, 15)  # Increase interval, max 15s
                    continue
                
                else:
                    self.logger.error(f"URLScan.io result error: {response.status_code} - {response.text}")
                    return None
                    
            except requests.exceptions.RequestException as e:
                self.logger.error(f"URLScan.io result request error: {e}")
                return None
            except Exception as e:
                self.logger.error(f"URLScan.io result unexpected error: {e}")
                return None
        
        self.logger.warning(f"⏰ Scan result timeout: {uuid}")
        return None
    
    def search_scans(self, query: str, size: int = 10) -> List[Dict]:
        """
        Search previous scans
        
        Args:
            query: Search query (ElasticSearch syntax)
            size: Number of results to return
        
        Returns:
            List of scan results
        """
        try:
            params = {
                'q': query,
                'size': size,
                'format': 'json'
            }
            
            response = self.session.get(
                f"{self.base_url}/search/",
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('results', [])
            else:
                self.logger.error(f"URLScan.io search error: {response.status_code}")
                return []
                
        except Exception as e:
            self.logger.error(f"URLScan.io search error: {e}")
            return []
    
    def analyze_url_quick(self, url: str) -> Dict:
        """
        Quick URL analysis without full scanning
        
        Args:
            url: URL to analyze
        
        Returns:
            Analysis results
        """
        try:
            # Search for existing scans of this URL
            domain = self._extract_domain(url)
            search_results = self.search_scans(f'page.url:"{url}" OR page.domain:"{domain}"', size=5)
            
            if search_results:
                # Use most recent scan
                latest_scan = sorted(search_results, key=lambda x: x.get('task', {}).get('time', ''), reverse=True)[0]
                
                return {
                    'source': 'urlscan_search',
                    'url': url,
                    'scan_date': latest_scan.get('task', {}).get('time'),
                    'verdict': latest_scan.get('verdicts', {}).get('overall', {}),
                    'malicious': latest_scan.get('verdicts', {}).get('overall', {}).get('malicious', False),
                    'score': latest_scan.get('verdicts', {}).get('overall', {}).get('score', 0),
                    'brands': latest_scan.get('verdicts', {}).get('brands', []),
                    'categories': latest_scan.get('verdicts', {}).get('categories', [])
                }
        
        except Exception as e:
            self.logger.error(f"Quick analysis error: {e}")
        
        return {
            'source': 'urlscan_unknown',
            'url': url,
            'malicious': False,
            'score': 0
        }
    
    def full_scan_analysis(self, url: str, visibility: str = "unlisted", max_wait: int = 60) -> Dict:
        """
        Perform full URL scan and analysis
        
        Args:
            url: URL to scan
            visibility: Scan visibility setting
            max_wait: Maximum wait time for results
        
        Returns:
            Complete analysis results
        """
        # First try quick analysis
        quick_result = self.analyze_url_quick(url)
        
        # If we have recent results, use them
        if quick_result.get('source') == 'urlscan_search':
            scan_date = quick_result.get('scan_date', '')
            if scan_date:
                try:
                    scan_time = datetime.fromisoformat(scan_date.replace('Z', '+00:00'))
                    if datetime.now().timestamp() - scan_time.timestamp() < 3600:  # Less than 1 hour old
                        return quick_result
                except Exception:
                    pass
        
        # Submit new scan
        uuid = self.submit_url(url, visibility)
        if not uuid:
            return quick_result  # Fallback to quick analysis
        
        # Get full results
        full_result = self.get_scan_result(uuid, max_wait)
        if not full_result:
            return quick_result  # Fallback to quick analysis
        
        return self._parse_scan_result(full_result, url)
    
    def _parse_scan_result(self, scan_data: Dict, url: str) -> Dict:
        """Parse URLScan.io scan result into standardized format"""
        try:
            verdicts = scan_data.get('verdicts', {})
            overall = verdicts.get('overall', {})
            stats = scan_data.get('stats', {})
            page = scan_data.get('page', {})
            
            return {
                'source': 'urlscan_full',
                'url': url,
                'uuid': scan_data.get('task', {}).get('uuid'),
                'scan_date': scan_data.get('task', {}).get('time'),
                'malicious': overall.get('malicious', False),
                'score': overall.get('score', 0),
                'verdict': overall,
                'brands': verdicts.get('brands', []),
                'categories': verdicts.get('categories', []),
                'page_info': {
                    'title': page.get('title', ''),
                    'status': page.get('status', ''),
                    'server': page.get('server', ''),
                    'ip': page.get('ip', ''),
                    'country': page.get('country', '')
                },
                'stats': {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'unrated': stats.get('unrated', 0),
                    'harmless': stats.get('harmless', 0)
                },
                'screenshot_url': f"https://urlscan.io/screenshots/{scan_data.get('task', {}).get('uuid')}.png" if scan_data.get('task', {}).get('uuid') else None
            }
            
        except Exception as e:
            self.logger.error(f"Error parsing scan result: {e}")
            return {
                'source': 'urlscan_error',
                'url': url,
                'malicious': False,
                'score': 0,
                'error': str(e)
            }
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return url.lower()
    
    def get_scan_screenshot(self, uuid: str) -> Optional[bytes]:
        """Download screenshot for a scan"""
        if not uuid:
            return None
        
        try:
            response = self.session.get(
                f"https://urlscan.io/screenshots/{uuid}.png",
                timeout=30
            )
            
            if response.status_code == 200:
                return response.content
            else:
                self.logger.warning(f"Screenshot not available: {uuid}")
                return None
                
        except Exception as e:
            self.logger.error(f"Screenshot download error: {e}")
            return None
