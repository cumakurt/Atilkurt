"""
Caching Module
LRU cache implementation for LDAP queries and other expensive operations
"""

import hashlib
from copy import deepcopy
import json
import logging
import threading
import time
from collections import OrderedDict
from functools import lru_cache, wraps
from typing import Any, Callable, Optional
from collections.abc import Sequence

logger = logging.getLogger(__name__)


class TimedCache:
    """Thread-safe time-based cache with expiration and a bounded LRU size."""

    def __init__(self, default_ttl: int = 3600, maxsize: int = 4096) -> None:
        """
        Initialize timed cache.

        Args:
            default_ttl: Default time-to-live in seconds
            maxsize: Maximum number of live entries to retain
        """
        if maxsize < 1:
            raise ValueError("maxsize must be at least 1")
        self._cache: OrderedDict[str, tuple[Any, float]] = OrderedDict()
        self._next_expiration = float('inf')
        self.default_ttl = default_ttl
        self.maxsize = maxsize
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache if not expired.

        Args:
            key: Cache key

        Returns:
            Cached value or None if expired/not found
        """
        with self._lock:
            if key not in self._cache:
                return None

            value, expiration = self._cache[key]

            if time.monotonic() >= expiration:
                del self._cache[key]
                return None

            self._cache.move_to_end(key)
            return value

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """
        Set value in cache with expiration.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (uses default if None)
        """
        ttl = self.default_ttl if ttl is None else ttl
        expiration = time.monotonic() + ttl
        with self._lock:
            if ttl <= 0:
                self._cache.pop(key, None)
                return
            self._purge_expired_locked()
            self._next_expiration = min(self._next_expiration, expiration)
            if key in self._cache:
                self._cache[key] = (value, expiration)
                self._cache.move_to_end(key)
                return
            self._evict_if_needed_locked()
            self._cache[key] = (value, expiration)

    def _evict_if_needed_locked(self) -> None:
        """Evict the least-recently-used item after expired entries are removed."""
        while len(self._cache) >= self.maxsize:
            self._cache.popitem(last=False)

    def _purge_expired_locked(self) -> None:
        """Scan only when an entry can have expired, not on every insertion."""
        now = time.monotonic()
        if now < self._next_expiration:
            return
        expired = [key for key, (_, deadline) in self._cache.items() if now >= deadline]
        for key in expired:
            del self._cache[key]
        self._next_expiration = min((deadline for _, deadline in self._cache.values()), default=float('inf'))

    def clear(self) -> None:
        """Clear all cached values."""
        with self._lock:
            self._cache.clear()
            self._next_expiration = float('inf')

    def remove(self, key: str) -> None:
        """
        Remove a specific key from cache.

        Args:
            key: Cache key to remove
        """
        with self._lock:
            self._cache.pop(key, None)

    def size(self) -> int:
        """
        Get current cache size.

        Returns:
            Number of cached items
        """
        with self._lock:
            self._purge_expired_locked()
            return len(self._cache)


def cache_key(*args: Any, **kwargs: Any) -> str:
    """
    Generate cache key from function arguments.

    Args:
        *args: Positional arguments
        **kwargs: Keyword arguments

    Returns:
        Cache key string (SHA-256 hash)
    """
    # Create a stable representation of arguments
    key_data = {
        'args': args,
        'kwargs': sorted(kwargs.items())
    }
    key_str = json.dumps(key_data, sort_keys=True, default=str)
    return hashlib.sha256(key_str.encode()).hexdigest()


def cached(ttl: Optional[int] = None, maxsize: int = 128):
    """
    Decorator for caching function results.

    Args:
        ttl: Time-to-live in seconds (None for LRU cache)
        maxsize: Maximum cache size for LRU cache

    Returns:
        Decorated function
    """
    if ttl is not None:
        # Use timed cache
        _cache = TimedCache(default_ttl=ttl, maxsize=maxsize)

        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                key = cache_key(*args, **kwargs)
                cached_value = _cache.get(key)

                if cached_value is not None:
                    logger.debug(f"Cache hit for {func.__name__}")
                    return cached_value

                result = func(*args, **kwargs)
                _cache.set(key, result, ttl)
                logger.debug(f"Cache miss for {func.__name__}, cached result")
                return result

            wrapper.cache_clear = _cache.clear
            wrapper.cache_remove = _cache.remove
            wrapper.cache_size = _cache.size

            return wrapper
    else:
        # Use LRU cache
        def decorator(func: Callable) -> Callable:
            cached_func = lru_cache(maxsize=maxsize)(func)

            @wraps(cached_func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                return cached_func(*args, **kwargs)

            wrapper.cache_clear = cached_func.cache_clear
            wrapper.cache_info = cached_func.cache_info

            return wrapper

    return decorator


class LDAPQueryCache:
    """Specialized cache for LDAP queries."""

    def __init__(self, default_ttl: int = 300) -> None:
        """
        Initialize LDAP query cache.

        Args:
            default_ttl: Default time-to-live in seconds (5 minutes)
        """
        self.cache = TimedCache(default_ttl=default_ttl)

    def get_query_result(
        self,
        search_filter: str,
        search_base: Optional[str] = None,
        attributes: Optional[Sequence[str]] = None,
        size_limit: int = 0,
        page_size: Optional[int] = None,
        enable_paging: Optional[bool] = None,
    ) -> Optional[Any]:
        """
        Get cached LDAP query result.

        Args:
            search_filter: LDAP search filter
            search_base: LDAP search base

        Returns:
            Cached result or None
        """
        key = self._make_key(
            search_filter,
            search_base,
            attributes=attributes,
            size_limit=size_limit,
            page_size=page_size,
            enable_paging=enable_paging,
        )
        # Consumers annotate and redact directory records in place. Neither a
        # returned result nor the caller's original list may mutate evidence.
        return deepcopy(self.cache.get(key))

    def set_query_result(
        self,
        search_filter: str,
        result: Any,
        search_base: Optional[str] = None,
        ttl: Optional[int] = None,
        attributes: Optional[Sequence[str]] = None,
        size_limit: int = 0,
        page_size: Optional[int] = None,
        enable_paging: Optional[bool] = None,
    ) -> None:
        """
        Cache LDAP query result.

        Args:
            search_filter: LDAP search filter
            result: Query result to cache
            search_base: LDAP search base
            ttl: Time-to-live in seconds
        """
        key = self._make_key(
            search_filter,
            search_base,
            attributes=attributes,
            size_limit=size_limit,
            page_size=page_size,
            enable_paging=enable_paging,
        )
        self.cache.set(key, deepcopy(result), ttl)

    def _make_key(
        self,
        search_filter: str,
        search_base: Optional[str],
        attributes: Optional[Sequence[str]] = None,
        size_limit: int = 0,
        page_size: Optional[int] = None,
        enable_paging: Optional[bool] = None,
    ) -> str:
        """
        Create cache key from query parameters.

        Args:
            search_filter: LDAP search filter
            search_base: LDAP search base

        Returns:
            Cache key (SHA-256 hash)
        """
        normalized_attributes = None
        if attributes is not None:
            normalized_attributes = sorted(str(attr) for attr in attributes)
        key_data = {
            'filter': search_filter,
            'base': search_base or '',
            'attributes': normalized_attributes,
            'size_limit': int(size_limit or 0),
            'page_size': page_size,
            'enable_paging': enable_paging,
        }
        key_str = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(key_str.encode()).hexdigest()

    def clear(self) -> None:
        """Clear all cached queries."""
        self.cache.clear()
