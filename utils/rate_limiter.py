"""
Rate limiter utility for API calls
Implements token bucket algorithm for rate limiting
"""

import time
import threading
from typing import Dict, Optional
from dataclasses import dataclass, field
from collections import defaultdict

from utils.logger import setup_logger

@dataclass
class RateLimitBucket:
    """Token bucket for rate limiting"""
    max_tokens: int
    refill_rate: float  # tokens per second
    current_tokens: float = field(default=0.0)
    last_refill: float = field(default_factory=time.time)
    lock: threading.Lock = field(default_factory=threading.Lock)
    
    def __post_init__(self):
        if self.current_tokens == 0.0:
            self.current_tokens = float(self.max_tokens)

class RateLimiter:
    """Thread-safe rate limiter using token bucket algorithm"""
    
    def __init__(self, max_requests: int, time_window: int, burst_allowance: float = 1.5):
        """
        Initialize rate limiter
        
        Args:
            max_requests: Maximum requests allowed in time window
            time_window: Time window in seconds
            burst_allowance: Allow burst up to this multiplier of max_requests
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.refill_rate = max_requests / time_window  # tokens per second
        self.max_tokens = int(max_requests * burst_allowance)
        
        self.bucket = RateLimitBucket(
            max_tokens=self.max_tokens,
            refill_rate=self.refill_rate
        )
        
        self.logger = setup_logger(__name__)
        
        self.logger.debug(f"Rate limiter initialized: {max_requests} requests per {time_window}s")
    
    def can_make_request(self, tokens_needed: int = 1) -> bool:
        """
        Check if request can be made (and consume tokens if yes)
        
        Args:
            tokens_needed: Number of tokens needed for request
        
        Returns:
            True if request is allowed
        """
        with self.bucket.lock:
            self._refill_bucket()
            
            if self.bucket.current_tokens >= tokens_needed:
                self.bucket.current_tokens -= tokens_needed
                return True
            
            return False
    
    def _refill_bucket(self):
        """Refill bucket based on elapsed time"""
        now = time.time()
        elapsed = now - self.bucket.last_refill
        
        if elapsed > 0:
            tokens_to_add = elapsed * self.bucket.refill_rate
            self.bucket.current_tokens = min(
                self.bucket.max_tokens,
                self.bucket.current_tokens + tokens_to_add
            )
            self.bucket.last_refill = now
    
    def get_wait_time(self, tokens_needed: int = 1) -> float:
        """
        Get time to wait before making request
        
        Args:
            tokens_needed: Number of tokens needed
        
        Returns:
            Wait time in seconds (0 if can make request immediately)
        """
        with self.bucket.lock:
            self._refill_bucket()
            
            if self.bucket.current_tokens >= tokens_needed:
                return 0.0
            
            tokens_deficit = tokens_needed - self.bucket.current_tokens
            wait_time = tokens_deficit / self.bucket.refill_rate
            return wait_time
    
    def get_status(self) -> Dict:
        """Get current rate limiter status"""
        with self.bucket.lock:
            self._refill_bucket()
            
            return {
                'current_tokens': self.bucket.current_tokens,
                'max_tokens': self.bucket.max_tokens,
                'refill_rate': self.bucket.refill_rate,
                'utilization_percent': (1 - self.bucket.current_tokens / self.bucket.max_tokens) * 100,
                'time_to_full': (self.bucket.max_tokens - self.bucket.current_tokens) / self.bucket.refill_rate
            }
    
    def reset(self):
        """Reset rate limiter to full capacity"""
        with self.bucket.lock:
            self.bucket.current_tokens = float(self.bucket.max_tokens)
            self.bucket.last_refill = time.time()
    
    def wait_if_needed(self, tokens_needed: int = 1, max_wait: float = 60.0) -> bool:
        """
        Wait if needed before making request
        
        Args:
            tokens_needed: Number of tokens needed
            max_wait: Maximum time to wait in seconds
        
        Returns:
            True if can proceed, False if wait time exceeds max_wait
        """
        wait_time = self.get_wait_time(tokens_needed)
        
        if wait_time > max_wait:
            return False
        
        if wait_time > 0:
            self.logger.debug(f"Rate limit: waiting {wait_time:.2f}s")
            time.sleep(wait_time)
        
        return self.can_make_request(tokens_needed)

class MultiServiceRateLimiter:
    """Rate limiter for multiple services"""
    
    def __init__(self):
        self.limiters: Dict[str, RateLimiter] = {}
        self.logger = setup_logger(__name__)
    
    def add_service(self, service_name: str, max_requests: int, 
                   time_window: int, burst_allowance: float = 1.5):
        """Add rate limiter for a service"""
        self.limiters[service_name] = RateLimiter(
            max_requests, time_window, burst_allowance
        )
        self.logger.info(f"Added rate limiter for {service_name}: {max_requests}/{time_window}s")
    
    def can_make_request(self, service_name: str, tokens_needed: int = 1) -> bool:
        """Check if request can be made for service"""
        if service_name not in self.limiters:
            return True  # No limit if service not configured
        
        return self.limiters[service_name].can_make_request(tokens_needed)
    
    def get_wait_time(self, service_name: str, tokens_needed: int = 1) -> float:
        """Get wait time for service"""
        if service_name not in self.limiters:
            return 0.0
        
        return self.limiters[service_name].get_wait_time(tokens_needed)
    
    def wait_if_needed(self, service_name: str, tokens_needed: int = 1, 
                      max_wait: float = 60.0) -> bool:
        """Wait if needed for service"""
        if service_name not in self.limiters:
            return True
        
        return self.limiters[service_name].wait_if_needed(tokens_needed, max_wait)
    
    def get_all_status(self) -> Dict[str, Dict]:
        """Get status for all services"""
        return {
            service: limiter.get_status() 
            for service, limiter in self.limiters.items()
        }
    
    def reset_all(self):
        """Reset all rate limiters"""
        for limiter in self.limiters.values():
            limiter.reset()

class AdaptiveRateLimiter:
    """Rate limiter that adapts based on API responses"""
    
    def __init__(self, initial_rate: int, time_window: int):
        self.base_rate = initial_rate
        self.current_rate = initial_rate
        self.time_window = time_window
        self.rate_limiter = RateLimiter(initial_rate, time_window)
        
        self.success_count = 0
        self.failure_count = 0
        self.last_adjustment = time.time()
        
        self.logger = setup_logger(__name__)
    
    def can_make_request(self, tokens_needed: int = 1) -> bool:
        """Check if request can be made"""
        return self.rate_limiter.can_make_request(tokens_needed)
    
    def record_success(self):
        """Record successful API call"""
        self.success_count += 1
        self._maybe_adjust_rate()
    
    def record_failure(self, is_rate_limit: bool = False):
        """Record failed API call"""
        self.failure_count += 1
        
        if is_rate_limit:
            # Immediate rate reduction for rate limit errors
            self._reduce_rate(factor=0.5)
        else:
            self._maybe_adjust_rate()
    
    def _maybe_adjust_rate(self):
        """Adjust rate based on success/failure ratio"""
        now = time.time()
        if now - self.last_adjustment < 60:  # Adjust at most once per minute
            return
        
        total_calls = self.success_count + self.failure_count
        if total_calls < 10:  # Need minimum sample size
            return
        
        success_rate = self.success_count / total_calls
        
        if success_rate > 0.95 and self.current_rate < self.base_rate * 2:
            # High success rate, increase rate gradually
            self._increase_rate(factor=1.1)
        elif success_rate < 0.8:
            # Low success rate, decrease rate
            self._reduce_rate(factor=0.8)
        
        # Reset counters
        self.success_count = 0
        self.failure_count = 0
        self.last_adjustment = now
    
    def _increase_rate(self, factor: float):
        """Increase rate limit"""
        new_rate = int(self.current_rate * factor)
        new_rate = min(new_rate, self.base_rate * 2)  # Don't exceed 2x base rate
        
        if new_rate != self.current_rate:
            self.current_rate = new_rate
            self.rate_limiter = RateLimiter(new_rate, self.time_window)
            self.logger.info(f"Increased rate limit to {new_rate}/{self.time_window}s")
    
    def _reduce_rate(self, factor: float):
        """Reduce rate limit"""
        new_rate = int(self.current_rate * factor)
        new_rate = max(new_rate, 1)  # Don't go below 1 request
        
        if new_rate != self.current_rate:
            self.current_rate = new_rate
            self.rate_limiter = RateLimiter(new_rate, self.time_window)
            self.logger.warning(f"Reduced rate limit to {new_rate}/{self.time_window}s")
    
    def get_current_rate(self) -> int:
        """Get current rate limit"""
        return self.current_rate
    
    def reset(self):
        """Reset to base rate"""
        self.current_rate = self.base_rate
        self.rate_limiter = RateLimiter(self.base_rate, self.time_window)
        self.success_count = 0
        self.failure_count = 0

# Global rate limiter instances for services
GLOBAL_RATE_LIMITERS = MultiServiceRateLimiter()

def setup_global_rate_limiters():
    """Setup global rate limiters for all services"""
    # URLScan.io - typically 10 requests per minute for free accounts
    GLOBAL_RATE_LIMITERS.add_service('urlscan', 10, 60)
    
    # Cloudflare Radar - typically 100 requests per minute
    GLOBAL_RATE_LIMITERS.add_service('cloudflare', 100, 60)
    
    # Telegram Bot API - typically 30 requests per second
    GLOBAL_RATE_LIMITERS.add_service('telegram', 30, 1)

def get_rate_limiter(service_name: str) -> Optional[RateLimiter]:
    """Get rate limiter for specific service"""
    return GLOBAL_RATE_LIMITERS.limiters.get(service_name)

# Initialize global rate limiters
setup_global_rate_limiters()
