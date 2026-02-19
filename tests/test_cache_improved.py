"""
Tests for Cache Module improvements
Validates SHA-256 hashing, thread safety, and TTL expiration
"""

import hashlib
import threading
import time
import unittest
from core.cache import TimedCache, LDAPQueryCache, cache_key


class TestTimedCache(unittest.TestCase):
    """Test cases for TimedCache with thread safety."""

    def test_set_and_get(self):
        """Basic set/get works."""
        cache = TimedCache(default_ttl=60)
        cache.set("key1", "value1")
        self.assertEqual(cache.get("key1"), "value1")

    def test_get_missing_key(self):
        """Missing key returns None."""
        cache = TimedCache(default_ttl=60)
        self.assertIsNone(cache.get("nonexistent"))

    def test_expiration(self):
        """Expired entries return None."""
        cache = TimedCache(default_ttl=1)
        cache.set("key1", "value1", ttl=1)
        time.sleep(1.1)
        self.assertIsNone(cache.get("key1"))

    def test_clear(self):
        """clear() removes all entries."""
        cache = TimedCache(default_ttl=60)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.clear()
        self.assertIsNone(cache.get("a"))
        self.assertIsNone(cache.get("b"))

    def test_remove(self):
        """remove() deletes only specified key."""
        cache = TimedCache(default_ttl=60)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.remove("a")
        self.assertIsNone(cache.get("a"))
        self.assertEqual(cache.get("b"), 2)

    def test_size_cleans_expired(self):
        """size() purges expired entries."""
        cache = TimedCache(default_ttl=1)
        cache.set("a", 1, ttl=1)
        cache.set("b", 2, ttl=60)
        time.sleep(1.1)
        self.assertEqual(cache.size(), 1)

    def test_thread_safety(self):
        """Concurrent access should not raise."""
        cache = TimedCache(default_ttl=60)
        errors = []

        def writer(n):
            try:
                for i in range(100):
                    cache.set(f"key_{n}_{i}", i)
            except Exception as e:
                errors.append(e)

        def reader(n):
            try:
                for i in range(100):
                    cache.get(f"key_{n}_{i}")
            except Exception as e:
                errors.append(e)

        threads = []
        for n in range(5):
            threads.append(threading.Thread(target=writer, args=(n,)))
            threads.append(threading.Thread(target=reader, args=(n,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Thread safety errors: {errors}")


class TestCacheKey(unittest.TestCase):
    """Test cases for cache_key function."""

    def test_sha256_output(self):
        """cache_key should produce a valid SHA-256 hex string."""
        key = cache_key("arg1", "arg2", opt=True)
        self.assertEqual(len(key), 64)  # SHA-256 hex = 64 chars

    def test_deterministic(self):
        """Same arguments → same key."""
        k1 = cache_key("x", y=1)
        k2 = cache_key("x", y=1)
        self.assertEqual(k1, k2)

    def test_different_args_different_keys(self):
        """Different arguments → different keys."""
        k1 = cache_key("a")
        k2 = cache_key("b")
        self.assertNotEqual(k1, k2)


class TestLDAPQueryCache(unittest.TestCase):
    """Test cases for LDAPQueryCache."""

    def test_set_and_get(self):
        cache = LDAPQueryCache(default_ttl=60)
        cache.set_query_result("(objectClass=user)", ["user1", "user2"])
        result = cache.get_query_result("(objectClass=user)")
        self.assertEqual(result, ["user1", "user2"])

    def test_cache_miss(self):
        cache = LDAPQueryCache(default_ttl=60)
        result = cache.get_query_result("(objectClass=computer)")
        self.assertIsNone(result)

    def test_uses_sha256(self):
        """Internal key should be a SHA-256 hash."""
        cache = LDAPQueryCache(default_ttl=60)
        key = cache._make_key("(objectClass=user)", "DC=test,DC=com")
        self.assertEqual(len(key), 64)


if __name__ == '__main__':
    unittest.main()
