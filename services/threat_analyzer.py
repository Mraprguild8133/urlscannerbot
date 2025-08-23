"""
Threat analysis service that combines URLScan.io and Cloudflare Radar results
Provides comprehensive threat scoring and analysis
"""

import asyncio
import concurrent.futures
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse
from datetime import datetime
import re

from database import Database
from services.url_scanner import URLScanner
from services.cloudflare_radar import CloudflareRadar
from utils.logger import setup_logger
from utils.url_detector import URLDetector

class ThreatAnalyzer:
    """Comprehensive threat analysis combining multiple security services"""
    
    def __init__(self, url_scanner: URLScanner, cloudflare_radar: CloudflareRadar, db: Database):
        self.url_scanner = url_scanner
        self.cloudflare_radar = cloudflare_radar
        self.db = db
        self.logger = setup_logger(__name__)
        self.url_detector = URLDetector()
        
        # Threat scoring weights
        self.SCORING_WEIGHTS = {
            'urlscan_verdict': 0.4,      # URLScan.io verdict weight
            'cloudflare_intel': 0.3,     # Cloudflare intelligence weight
            'domain_reputation': 0.2,    # Domain reputation weight
            'url_structure': 0.1         # URL structure analysis weight
        }
        
        # Malicious indicators
        self.MALICIOUS_INDICATORS = {
            'suspicious_tlds': ['.tk', '.ml', '.ga', '.cf', '.click', '.download'],
            'phishing_keywords': ['secure', 'verify', 'update', 'confirm', 'login', 'account'],
            'suspicious_patterns': [
                r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
                r'[a-z0-9]{20,}',  # Long random strings
                r'bit\.ly|tinyurl|t\.co|goo\.gl',  # URL shorteners
                r'[^a-z0-9\-](?:login|signin|account|secure|verify|update)',  # Phishing terms
            ]
        }
        
        self.logger.info("🛡️ Threat analyzer initialized")
    
    def analyze_url_comprehensive(self, url: str, chat_id: int, user_id: int, 
                                message_id: int, max_wait: int = 45) -> Dict:
        """
        Perform comprehensive threat analysis of URL
        
        Args:
            url: URL to analyze
            chat_id: Telegram chat ID
            user_id: User ID who posted the URL
            message_id: Message ID containing URL
            max_wait: Maximum wait time for scanning
        
        Returns:
            Comprehensive threat analysis results
        """
        self.logger.info(f"🔍 Starting comprehensive analysis for: {url}")
        
        # Save initial scan record
        scan_id = self.db.save_url_scan(
            chat_id=chat_id,
            user_id=user_id,
            message_id=message_id,
            url=url
        )
        
        try:
            # Check whitelist/blacklist first
            chat_settings = self.db.get_chat_settings(chat_id)
            domain = self._extract_domain(url)
            
            if domain in chat_settings.get('whitelist', []):
                result = self._create_whitelist_result(url, scan_id)
                self._update_scan_record(scan_id, result)
                return result
            
            if domain in chat_settings.get('blacklist', []):
                result = self._create_blacklist_result(url, scan_id)
                self._update_scan_record(scan_id, result)
                return result
            
            # Perform parallel analysis
            analysis_results = self._run_parallel_analysis(url, max_wait)
            
            # Combine results and calculate threat score
            combined_result = self._combine_analysis_results(
                url, scan_id, analysis_results, chat_settings
            )
            
            # Update database record
            self._update_scan_record(scan_id, combined_result)
            
            # Update daily statistics
            self.db.update_daily_stats(
                urls_scanned=1,
                threats_detected=1 if combined_result['is_malicious'] else 0
            )
            
            self.logger.info(f"✅ Analysis complete for {url}: Score {combined_result['threat_score']}/100")
            return combined_result
            
        except Exception as e:
            self.logger.error(f"Error in comprehensive analysis: {e}")
            error_result = self._create_error_result(url, scan_id, str(e))
            self._update_scan_record(scan_id, error_result)
            return error_result
    
    def _run_parallel_analysis(self, url: str, max_wait: int) -> Dict:
        """Run URLScan.io and Cloudflare analysis in parallel"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            # Submit tasks
            futures = {}
            
            if self.url_scanner.api_key:
                futures['urlscan'] = executor.submit(
                    self.url_scanner.full_scan_analysis, url, "unlisted", max_wait
                )
            
            if self.cloudflare_radar.api_key:
                futures['cloudflare'] = executor.submit(
                    self.cloudflare_radar.analyze_url_comprehensive, url
                )
            
            futures['structure'] = executor.submit(
                self._analyze_url_structure, url
            )
            
            # Collect results
            results = {}
            for service, future in futures.items():
                try:
                    results[service] = future.result(timeout=max_wait)
                except concurrent.futures.TimeoutError:
                    self.logger.warning(f"{service} analysis timed out")
                    results[service] = None
                except Exception as e:
                    self.logger.error(f"{service} analysis error: {e}")
                    results[service] = None
            
            return results
    
    def _combine_analysis_results(self, url: str, scan_id: int, 
                                analysis_results: Dict, chat_settings: Dict) -> Dict:
        """Combine analysis results and calculate final threat score"""
        
        # Extract individual results
        urlscan_result = analysis_results.get('urlscan')
        cloudflare_result = analysis_results.get('cloudflare')
        structure_result = analysis_results.get('structure', {})
        
        # Calculate component scores (0-100)
        urlscan_score = self._calculate_urlscan_score(urlscan_result)
        cloudflare_score = self._calculate_cloudflare_score(cloudflare_result)
        structure_score = structure_result.get('threat_score', 0)
        domain_score = self._calculate_domain_reputation_score(cloudflare_result)
        
        # Calculate weighted final score
        final_score = (
            urlscan_score * self.SCORING_WEIGHTS['urlscan_verdict'] +
            cloudflare_score * self.SCORING_WEIGHTS['cloudflare_intel'] +
            domain_score * self.SCORING_WEIGHTS['domain_reputation'] +
            structure_score * self.SCORING_WEIGHTS['url_structure']
        )
        
        final_score = int(round(final_score))
        
        # Determine if malicious based on threshold
        threshold = chat_settings.get('threat_threshold', 50)
        is_malicious = final_score >= threshold
        
        # Generate verdict explanation
        verdict_explanation = self._generate_verdict_explanation(
            urlscan_result, cloudflare_result, structure_result, final_score
        )
        
        return {
            'scan_id': scan_id,
            'url': url,
            'domain': self._extract_domain(url),
            'threat_score': final_score,
            'is_malicious': is_malicious,
            'threshold': threshold,
            'verdict_explanation': verdict_explanation,
            'component_scores': {
                'urlscan': urlscan_score,
                'cloudflare': cloudflare_score,
                'domain_reputation': domain_score,
                'url_structure': structure_score
            },
            'analysis_results': {
                'urlscan': urlscan_result,
                'cloudflare': cloudflare_result,
                'url_structure': structure_result
            },
            'analysis_timestamp': datetime.now().isoformat(),
            'services_used': [
                service for service, result in analysis_results.items() 
                if result is not None
            ]
        }
    
    def _calculate_urlscan_score(self, urlscan_result: Optional[Dict]) -> int:
        """Calculate threat score from URLScan.io results"""
        if not urlscan_result:
            return 0
        
        if urlscan_result.get('malicious'):
            return min(urlscan_result.get('score', 90), 100)
        
        # Check for suspicious indicators
        score = 0
        
        # Verdicts and categories
        verdicts = urlscan_result.get('verdicts', {})
        brands = urlscan_result.get('brands', [])
        categories = urlscan_result.get('categories', [])
        
        if verdicts.get('overall', {}).get('malicious'):
            score += 90
        elif brands:
            score += 60  # Brand impersonation
        elif categories:
            score += 30  # Categorized content
        
        # Stats analysis
        stats = urlscan_result.get('stats', {})
        malicious_count = stats.get('malicious', 0)
        suspicious_count = stats.get('suspicious', 0)
        
        if malicious_count > 0:
            score += min(malicious_count * 20, 80)
        elif suspicious_count > 0:
            score += min(suspicious_count * 10, 40)
        
        return min(score, 100)
    
    def _calculate_cloudflare_score(self, cloudflare_result: Optional[Dict]) -> int:
        """Calculate threat score from Cloudflare results"""
        if not cloudflare_result:
            return 0
        
        score = 0
        
        # Domain intelligence
        domain_intel = cloudflare_result.get('domain_intelligence', {})
        reputation = domain_intel.get('reputation', 'unknown')
        
        if reputation == 'malicious':
            score += 90
        elif reputation == 'suspicious':
            score += 70
        elif reputation == 'clean':
            score -= 10  # Reduce score for clean reputation
        
        # Security categories
        security_categories = domain_intel.get('security_categories', [])
        malicious_categories = ['malware', 'phishing', 'spam', 'botnet']
        
        for category in security_categories:
            if any(mal_cat in category.lower() for mal_cat in malicious_categories):
                score += 80
                break
        
        # URL scan results
        url_scan = cloudflare_result.get('url_scan', {})
        if url_scan.get('malicious'):
            score += min(url_scan.get('score', 80), 90)
        
        return min(max(score, 0), 100)
    
    def _calculate_domain_reputation_score(self, cloudflare_result: Optional[Dict]) -> int:
        """Calculate domain reputation score"""
        if not cloudflare_result:
            return 0
        
        domain_intel = cloudflare_result.get('domain_intelligence', {})
        
        # Risk score (if available)
        risk_score = domain_intel.get('risk_score', 0)
        if risk_score > 0:
            return min(risk_score, 100)
        
        # Domain age and popularity
        first_seen = domain_intel.get('first_seen')
        popularity_rank = domain_intel.get('popularity_rank')
        
        score = 0
        
        # New domains are slightly more suspicious
        if first_seen:
            try:
                from datetime import datetime
                first_seen_date = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
                days_old = (datetime.now().timestamp() - first_seen_date.timestamp()) / 86400
                
                if days_old < 30:  # Less than 30 days old
                    score += 20
                elif days_old < 90:  # Less than 90 days old
                    score += 10
            except Exception:
                pass
        
        # Popular domains are generally safer
        if popularity_rank and popularity_rank < 100000:  # Top 100k sites
            score -= 20
        
        return max(score, 0)
    
    def _analyze_url_structure(self, url: str) -> Dict:
        """Analyze URL structure for suspicious patterns"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
            
            threat_score = 0
            indicators = []
            
            # Check TLD
            for suspicious_tld in self.MALICIOUS_INDICATORS['suspicious_tlds']:
                if domain.endswith(suspicious_tld):
                    threat_score += 30
                    indicators.append(f"Suspicious TLD: {suspicious_tld}")
                    break
            
            # Check for IP address instead of domain
            ip_pattern = self.MALICIOUS_INDICATORS['suspicious_patterns'][0]
            if re.match(ip_pattern, domain):
                threat_score += 50
                indicators.append("Using IP address instead of domain")
            
            # Check for suspicious patterns
            full_url = url.lower()
            for pattern in self.MALICIOUS_INDICATORS['suspicious_patterns'][1:]:
                if re.search(pattern, full_url):
                    threat_score += 20
                    indicators.append(f"Suspicious pattern detected")
            
            # Check for phishing keywords
            for keyword in self.MALICIOUS_INDICATORS['phishing_keywords']:
                if keyword in domain or keyword in path:
                    threat_score += 15
                    indicators.append(f"Phishing keyword: {keyword}")
            
            # Check URL length (very long URLs can be suspicious)
            if len(url) > 200:
                threat_score += 10
                indicators.append("Unusually long URL")
            
            # Check for excessive subdomains
            subdomain_count = domain.count('.')
            if subdomain_count > 3:
                threat_score += 15
                indicators.append("Excessive subdomains")
            
            # Check for homograph attacks (similar looking characters)
            if self._detect_homograph_attack(domain):
                threat_score += 40
                indicators.append("Potential homograph attack")
            
            return {
                'threat_score': min(threat_score, 100),
                'indicators': indicators,
                'domain_analysis': {
                    'domain': domain,
                    'subdomain_count': subdomain_count,
                    'url_length': len(url),
                    'has_query_params': bool(query)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing URL structure: {e}")
            return {'threat_score': 0, 'indicators': [], 'error': str(e)}
    
    def _detect_homograph_attack(self, domain: str) -> bool:
        """Detect potential homograph attacks in domain"""
        # Common homograph characters
        homograph_chars = {
            'a': ['à', 'á', 'â', 'ã', 'ä', 'å', 'ą'],
            'e': ['è', 'é', 'ê', 'ë', 'ę'],
            'i': ['ì', 'í', 'î', 'ï'],
            'o': ['ò', 'ó', 'ô', 'õ', 'ö', 'ø'],
            'u': ['ù', 'ú', 'û', 'ü'],
            'n': ['ñ'],
            'c': ['ç'],
        }
        
        for char in domain:
            for normal_char, variants in homograph_chars.items():
                if char in variants:
                    return True
        
        return False
    
    def _generate_verdict_explanation(self, urlscan_result: Optional[Dict], 
                                    cloudflare_result: Optional[Dict],
                                    structure_result: Dict, threat_score: int) -> str:
        """Generate human-readable verdict explanation"""
        explanations = []
        
        if threat_score >= 80:
            explanations.append("🔴 HIGH THREAT DETECTED")
        elif threat_score >= 50:
            explanations.append("🟠 MODERATE THREAT DETECTED")
        elif threat_score >= 20:
            explanations.append("🟡 LOW THREAT DETECTED")
        else:
            explanations.append("🟢 APPEARS SAFE")
        
        # URLScan.io findings
        if urlscan_result:
            if urlscan_result.get('malicious'):
                explanations.append("• URLScan.io flagged as malicious")
            
            brands = urlscan_result.get('brands', [])
            if brands:
                explanations.append(f"• Potential brand impersonation: {', '.join(brands[:2])}")
            
            stats = urlscan_result.get('stats', {})
            if stats.get('malicious', 0) > 0:
                explanations.append(f"• {stats['malicious']} malicious resources detected")
        
        # Cloudflare findings
        if cloudflare_result:
            domain_intel = cloudflare_result.get('domain_intelligence', {})
            reputation = domain_intel.get('reputation')
            
            if reputation == 'malicious':
                explanations.append("• Cloudflare flags domain as malicious")
            elif reputation == 'suspicious':
                explanations.append("• Cloudflare flags domain as suspicious")
            
            security_categories = domain_intel.get('security_categories', [])
            if security_categories:
                explanations.append(f"• Security categories: {', '.join(security_categories[:2])}")
        
        # Structure analysis findings
        indicators = structure_result.get('indicators', [])
        if indicators:
            explanations.append(f"• URL structure issues: {indicators[0]}")
            if len(indicators) > 1:
                explanations.append(f"  (+{len(indicators)-1} more issues)")
        
        return '\n'.join(explanations)
    
    def _create_whitelist_result(self, url: str, scan_id: int) -> Dict:
        """Create result for whitelisted URL"""
        return {
            'scan_id': scan_id,
            'url': url,
            'domain': self._extract_domain(url),
            'threat_score': 0,
            'is_malicious': False,
            'verdict_explanation': "🟢 WHITELISTED DOMAIN\n• Domain is in chat whitelist",
            'whitelisted': True,
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def _create_blacklist_result(self, url: str, scan_id: int) -> Dict:
        """Create result for blacklisted URL"""
        return {
            'scan_id': scan_id,
            'url': url,
            'domain': self._extract_domain(url),
            'threat_score': 100,
            'is_malicious': True,
            'verdict_explanation': "🔴 BLACKLISTED DOMAIN\n• Domain is in chat blacklist",
            'blacklisted': True,
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def _create_error_result(self, url: str, scan_id: int, error: str) -> Dict:
        """Create result for analysis error"""
        return {
            'scan_id': scan_id,
            'url': url,
            'domain': self._extract_domain(url),
            'threat_score': 0,
            'is_malicious': False,
            'verdict_explanation': f"⚠️ ANALYSIS ERROR\n• {error}",
            'error': error,
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def _update_scan_record(self, scan_id: int, result: Dict):
        """Update database scan record with results"""
        try:
            self.db.update_url_scan(
                scan_id=scan_id,
                scan_uuid=result.get('analysis_results', {}).get('urlscan', {}).get('uuid'),
                urlscan_verdict=result.get('component_scores', {}).get('urlscan', 0),
                cloudflare_verdict=result.get('analysis_results', {}).get('cloudflare', {}).get('verdict'),
                threat_score=result.get('threat_score', 0),
                is_malicious=result.get('is_malicious', False),
                scan_result=result
            )
        except Exception as e:
            self.logger.error(f"Error updating scan record: {e}")
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return url.lower()
    
    def get_url_analysis_summary(self, scan_id: int) -> Optional[Dict]:
        """Get analysis summary by scan ID"""
        return self.db.get_url_scan(scan_id)
    
    def analyze_multiple_urls(self, urls: List[str], chat_id: int, 
                            user_id: int, message_id: int) -> List[Dict]:
        """Analyze multiple URLs from a single message"""
        results = []
        
        for url in urls[:5]:  # Limit to 5 URLs per message
            try:
                result = self.analyze_url_comprehensive(
                    url, chat_id, user_id, message_id, max_wait=30
                )
                results.append(result)
            except Exception as e:
                self.logger.error(f"Error analyzing URL {url}: {e}")
                results.append(self._create_error_result(url, 0, str(e)))
        
        return results
