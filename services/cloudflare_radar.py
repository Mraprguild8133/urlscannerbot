"""
Cloudflare Radar API integration service
Provides threat intelligence and domain analysis
"""

import requests
from typing import Dict, Optional, List, Tuple
from urllib.parse import urlparse
from datetime import datetime, timedelta

from utils.logger import setup_logger
from utils.rate_limiter import RateLimiter

class CloudflareRadar:
    """Cloudflare Radar API integration for threat intelligence"""
    
    def __init__(self, api_key: str, account_id: str = ""):
        self.api_key = api_key
        self.account_id = account_id
        self.logger = setup_logger(__name__)
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.rate_limiter = RateLimiter(max_requests=100, time_window=60)  # 100 requests per minute
        
        # Session for connection pooling
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'TelegramSecurityBot/1.0',
            'Content-Type': 'application/json'
        })
        
        if api_key:
            self.session.headers.update({'Authorization': f'Bearer {api_key}'})
        
        self.logger.info(f"☁️ Cloudflare Radar service initialized (API key: {'✓' if api_key else '✗'})")
    
    def get_domain_intelligence(self, domain: str) -> Dict:
        """
        Get domain intelligence data
        
        Args:
            domain: Domain to analyze
        
        Returns:
            Domain intelligence results
        """
        if not self.api_key or not self.account_id:
            return self._get_fallback_result(domain)
        
        if not self.rate_limiter.can_make_request():
            self.logger.warning("Cloudflare Radar rate limit reached")
            return self._get_fallback_result(domain)
        
        try:
            response = self.session.get(
                f"{self.base_url}/accounts/{self.account_id}/intel/domain",
                params={'domain': domain},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    return self._parse_domain_intel(data.get('result', {}), domain)
                else:
                    self.logger.error(f"Cloudflare API error: {data.get('errors')}")
            
            elif response.status_code == 429:
                self.logger.warning("Cloudflare rate limit exceeded")
            
            else:
                self.logger.error(f"Cloudflare domain intel error: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Cloudflare request error: {e}")
        except Exception as e:
            self.logger.error(f"Cloudflare unexpected error: {e}")
        
        return self._get_fallback_result(domain)
    
    def get_domain_history(self, domain: str) -> Dict:
        """
        Get domain history data
        
        Args:
            domain: Domain to analyze
        
        Returns:
            Domain history results
        """
        if not self.api_key or not self.account_id:
            return {'domain': domain, 'history': []}
        
        try:
            response = self.session.get(
                f"{self.base_url}/accounts/{self.account_id}/intel/domain-history",
                params={'domain': domain},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    return {
                        'domain': domain,
                        'history': data.get('result', [])
                    }
            
        except Exception as e:
            self.logger.error(f"Domain history error: {e}")
        
        return {'domain': domain, 'history': []}
    
    def get_whois_data(self, domain: str) -> Dict:
        """
        Get WHOIS data for domain
        
        Args:
            domain: Domain to lookup
        
        Returns:
            WHOIS data
        """
        if not self.api_key or not self.account_id:
            return {'domain': domain, 'whois': {}}
        
        try:
            response = self.session.get(
                f"{self.base_url}/accounts/{self.account_id}/intel/whois",
                params={'domain': domain},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    return {
                        'domain': domain,
                        'whois': data.get('result', {})
                    }
            
        except Exception as e:
            self.logger.error(f"WHOIS lookup error: {e}")
        
        return {'domain': domain, 'whois': {}}
    
    def scan_url_with_radar(self, url: str) -> Dict:
        """
        Scan URL using Cloudflare URL Scanner
        
        Args:
            url: URL to scan
        
        Returns:
            Scan results
        """
        if not self.api_key or not self.account_id:
            return self._get_fallback_scan_result(url)
        
        try:
            # Submit URL for scanning
            scan_data = {
                "url": url,
                "visibility": "unlisted"
            }
            
            response = self.session.post(
                f"{self.base_url}/accounts/{self.account_id}/urlscanner/v2/scan",
                json=scan_data,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    scan_uuid = data.get('result', {}).get('uuid')
                    if scan_uuid:
                        # Wait a moment and get results
                        import time
                        time.sleep(10)  # Wait for scan to complete
                        return self._get_scan_results(scan_uuid, url)
            
        except Exception as e:
            self.logger.error(f"Cloudflare URL scan error: {e}")
        
        return self._get_fallback_scan_result(url)
    
    def _get_scan_results(self, uuid: str, url: str) -> Dict:
        """Get scan results by UUID"""
        try:
            response = self.session.get(
                f"{self.base_url}/accounts/{self.account_id}/urlscanner/v2/scan/{uuid}",
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    return self._parse_scan_result(data.get('result', {}), url)
            
        except Exception as e:
            self.logger.error(f"Scan results error: {e}")
        
        return self._get_fallback_scan_result(url)
    
    def get_threat_categories(self, domain: str) -> List[str]:
        """
        Get threat categories for domain
        
        Args:
            domain: Domain to check
        
        Returns:
            List of threat categories
        """
        intel_data = self.get_domain_intelligence(domain)
        return intel_data.get('categories', [])
    
    def is_domain_malicious(self, domain: str) -> Tuple[bool, int, str]:
        """
        Check if domain is malicious
        
        Args:
            domain: Domain to check
        
        Returns:
            Tuple of (is_malicious, confidence_score, reason)
        """
        intel_data = self.get_domain_intelligence(domain)
        
        # Check for malicious categories
        malicious_categories = [
            'malware', 'phishing', 'spam', 'botnet', 'ransomware',
            'trojan', 'adware', 'suspicious', 'threat'
        ]
        
        categories = intel_data.get('categories', [])
        reputation = intel_data.get('reputation', 'unknown')
        
        is_malicious = False
        confidence = 0
        reason = "Clean"
        
        # Check categories
        for category in categories:
            if any(mal_cat in category.lower() for mal_cat in malicious_categories):
                is_malicious = True
                confidence = 80
                reason = f"Malicious category: {category}"
                break
        
        # Check reputation
        if reputation in ['malicious', 'suspicious']:
            is_malicious = True
            confidence = max(confidence, 70)
            reason = f"Bad reputation: {reputation}"
        elif reputation == 'clean':
            confidence = max(confidence, 90) if not is_malicious else confidence
            reason = "Good reputation" if not is_malicious else reason
        
        return is_malicious, confidence, reason
    
    def _parse_domain_intel(self, data: Dict, domain: str) -> Dict:
        """Parse domain intelligence data"""
        try:
            return {
                'domain': domain,
                'reputation': data.get('reputation', 'unknown'),
                'categories': data.get('categories', []),
                'security_categories': data.get('security_categories', []),
                'content_categories': data.get('content_categories', []),
                'risk_score': data.get('risk_score', 0),
                'popularity_rank': data.get('popularity_rank'),
                'first_seen': data.get('first_seen'),
                'last_seen': data.get('last_seen')
            }
        except Exception as e:
            self.logger.error(f"Error parsing domain intel: {e}")
            return self._get_fallback_result(domain)
    
    def _parse_scan_result(self, data: Dict, url: str) -> Dict:
        """Parse URL scan result"""
        try:
            verdicts = data.get('verdicts', {})
            overall = verdicts.get('overall', {})
            
            return {
                'source': 'cloudflare_radar',
                'url': url,
                'uuid': data.get('uuid'),
                'scan_date': data.get('time'),
                'malicious': overall.get('malicious', False),
                'score': self._calculate_threat_score(verdicts),
                'verdict': overall,
                'categories': data.get('categories', []),
                'screenshot_url': data.get('screenshot_url')
            }
            
        except Exception as e:
            self.logger.error(f"Error parsing scan result: {e}")
            return self._get_fallback_scan_result(url)
    
    def _calculate_threat_score(self, verdicts: Dict) -> int:
        """Calculate threat score from verdicts (0-100)"""
        overall = verdicts.get('overall', {})
        
        if overall.get('malicious'):
            return 90
        elif overall.get('suspicious'):
            return 60
        elif overall.get('categories'):
            return 30
        else:
            return 10
    
    def _get_fallback_result(self, domain: str) -> Dict:
        """Get fallback result when API is not available"""
        return {
            'domain': domain,
            'reputation': 'unknown',
            'categories': [],
            'security_categories': [],
            'content_categories': [],
            'risk_score': 0,
            'popularity_rank': None,
            'first_seen': None,
            'last_seen': None,
            'api_available': False
        }
    
    def _get_fallback_scan_result(self, url: str) -> Dict:
        """Get fallback scan result when API is not available"""
        return {
            'source': 'cloudflare_unavailable',
            'url': url,
            'malicious': False,
            'score': 0,
            'api_available': False
        }
    
    def analyze_url_comprehensive(self, url: str) -> Dict:
        """
        Comprehensive URL analysis combining multiple Cloudflare services
        
        Args:
            url: URL to analyze
        
        Returns:
            Comprehensive analysis results
        """
        try:
            # Extract domain from URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Get domain intelligence
            domain_intel = self.get_domain_intelligence(domain)
            
            # Get WHOIS data
            whois_data = self.get_whois_data(domain)
            
            # Perform URL scan if available
            url_scan = self.scan_url_with_radar(url)
            
            # Combine results
            return {
                'url': url,
                'domain': domain,
                'domain_intelligence': domain_intel,
                'whois': whois_data,
                'url_scan': url_scan,
                'analysis_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Comprehensive analysis error: {e}")
            return {
                'url': url,
                'error': str(e),
                'analysis_timestamp': datetime.now().isoformat()
            }
