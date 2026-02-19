"""
Stealth Mode Module
Implements rate limiting and stealth features for penetration testing
"""

import logging
import time
import random
from typing import Optional, Callable, Any
from functools import wraps

logger = logging.getLogger(__name__)


class StealthMode:
    """Implements stealth features for LDAP queries."""
    
    def __init__(self, enabled: bool = False, rate_limit: float = 2.0, 
                 random_delay: Optional[tuple] = None, min_logging: bool = False):
        """
        Initialize stealth mode.
        
        Args:
            enabled: Enable stealth mode
            rate_limit: Minimum seconds between queries
            random_delay: Tuple (min, max) for random delay in seconds
            min_logging: Minimize logging output
        """
        self.enabled = enabled
        self.rate_limit = rate_limit
        self.random_delay = random_delay or (0, 0)
        self.min_logging = min_logging
        self.last_query_time: Optional[float] = None
        
        if self.enabled and self.min_logging:
            # Only suppress AtilKurt loggers, not the global root logger
            logging.getLogger('core').setLevel(logging.WARNING)
            logging.getLogger('analysis').setLevel(logging.WARNING)
            logging.getLogger('reporting').setLevel(logging.WARNING)
            logging.getLogger('scoring').setLevel(logging.WARNING)
            logging.getLogger('risk').setLevel(logging.WARNING)
    
    def apply_delay(self) -> None:
        """Apply rate limiting and random delay."""
        if not self.enabled:
            return
        
        # Rate limiting
        if self.last_query_time is not None:
            elapsed = time.time() - self.last_query_time
            if elapsed < self.rate_limit:
                sleep_time = self.rate_limit - elapsed
                if not self.min_logging:
                    logger.debug(f"Rate limiting: sleeping {sleep_time:.2f} seconds")
                time.sleep(sleep_time)
        
        # Random delay
        if self.random_delay[1] > 0:
            delay = random.uniform(self.random_delay[0], self.random_delay[1])
            if not self.min_logging:
                logger.debug(f"Random delay: sleeping {delay:.2f} seconds")
            time.sleep(delay)
        
        self.last_query_time = time.time()
    
    def stealth_wrapper(self, func: Callable) -> Callable:
        """
        Decorator to apply stealth mode to functions.
        
        Args:
            func: Function to wrap
        
        Returns:
            Wrapped function
        """
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            self.apply_delay()
            return func(*args, **kwargs)
        return wrapper


def create_stealth_mode(enabled: bool = False, rate_limit: float = 2.0,
                       random_delay_min: float = 0.0, random_delay_max: float = 0.0,
                       min_logging: bool = False) -> StealthMode:
    """
    Create stealth mode instance.
    
    Args:
        enabled: Enable stealth mode
        rate_limit: Minimum seconds between queries
        random_delay_min: Minimum random delay in seconds
        random_delay_max: Maximum random delay in seconds
        min_logging: Minimize logging
    
    Returns:
        StealthMode instance
    """
    return StealthMode(
        enabled=enabled,
        rate_limit=rate_limit,
        random_delay=(random_delay_min, random_delay_max),
        min_logging=min_logging
    )
