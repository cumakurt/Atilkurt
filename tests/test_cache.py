"""
Tests for Caching Module
"""

import unittest
import time
from core.cache import TimedCache, cache_key, cached, LDAPQueryCache


class TestTimedCache(unittest.TestCase):
    """Test cases for TimedCache."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.cache = TimedCache(default_ttl=1)  # 1 second TTL
    
    def test_set_get(self):
        """Test setting and getting values."""
        self.cache.set('key1', 'value1')
        self.assertEqual(self.cache.get('key1'), 'value1')
    
    def test_expiration(self):
        """Test cache expiration."""
        self.cache.set('key1', 'value1', ttl=1)
        time.sleep(1.1)
        self.assertIsNone(self.cache.get('key1'))
    
    def test_clear(self):
        """Test clearing cache."""
        self.cache.set('key1', 'value1')
        self.cache.set('key2', 'value2')
        self.cache.clear()
        self.assertIsNone(self.cache.get('key1'))
        self.assertIsNone(self.cache.get('key2'))
    
    def test_remove(self):
        """Test removing specific key."""
        self.cache.set('key1', 'value1')
        self.cache.set('key2', 'value2')
        self.cache.remove('key1')
        self.assertIsNone(self.cache.get('key1'))
        self.assertEqual(self.cache.get('key2'), 'value2')


class TestCacheKey(unittest.TestCase):
    """Test cases for cache key generation."""
    
    def test_cache_key_stable(self):
        """Test that cache key is stable for same inputs."""
        key1 = cache_key('arg1', 'arg2', kwarg1='value1')
        key2 = cache_key('arg1', 'arg2', kwarg1='value1')
        self.assertEqual(key1, key2)
    
    def test_cache_key_different(self):
        """Test that cache key is different for different inputs."""
        key1 = cache_key('arg1', 'arg2')
        key2 = cache_key('arg1', 'arg3')
        self.assertNotEqual(key1, key2)


class TestCachedDecorator(unittest.TestCase):
    """Test cases for cached decorator."""
    
    def test_cached_function(self):
        """Test caching function results."""
        call_count = [0]
        
        @cached(ttl=60)
        def test_func(x):
            call_count[0] += 1
            return x * 2
        
        result1 = test_func(5)
        result2 = test_func(5)  # Should use cache
        
        self.assertEqual(result1, 10)
        self.assertEqual(result2, 10)
        self.assertEqual(call_count[0], 1)  # Function called only once


class TestLDAPQueryCache(unittest.TestCase):
    """Test cases for LDAPQueryCache."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.cache = LDAPQueryCache(default_ttl=60)
    
    def test_get_set_query_result(self):
        """Test getting and setting query results."""
        search_filter = '(objectClass=user)'
        result = ['user1', 'user2']
        
        self.cache.set_query_result(search_filter, result)
        cached_result = self.cache.get_query_result(search_filter)
        
        self.assertEqual(cached_result, result)
    
    def test_query_with_base(self):
        """Test query caching with search base."""
        search_filter = '(objectClass=user)'
        search_base = 'DC=example,DC=com'
        result = ['user1']
        
        self.cache.set_query_result(search_filter, result, search_base)
        cached_result = self.cache.get_query_result(search_filter, search_base)
        
        self.assertEqual(cached_result, result)
    
    def test_clear_cache(self):
        """Test clearing cache."""
        self.cache.set_query_result('(objectClass=user)', ['user1'])
        self.cache.clear()
        
        result = self.cache.get_query_result('(objectClass=user)')
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
