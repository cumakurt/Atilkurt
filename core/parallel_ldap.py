"""
Parallel LDAP Query Module
Enables parallel LDAP queries with multi-threading support
"""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Callable
from queue import Queue
import time

logger = logging.getLogger(__name__)


class ParallelLDAPExecutor:
    """
    Executes LDAP queries in parallel using thread pool.
    """
    
    def __init__(self, ldap_connection, max_workers: int = 5, rate_limit: float = 0.5):
        """
        Initialize parallel LDAP executor.
        
        Args:
            ldap_connection: LDAPConnection instance (will create per-thread connections)
            max_workers: Maximum number of parallel threads
            rate_limit: Minimum seconds between queries per thread
        """
        self.base_ldap_config = {
            'domain': ldap_connection.domain,
            'username': ldap_connection.username,
            'password': ldap_connection.password,
            'dc_ip': ldap_connection.dc_ip,
            'use_ssl': ldap_connection.use_ssl,
            'timeout': ldap_connection.base_timeout,
            'page_size': ldap_connection.page_size,
            'enable_paging': ldap_connection.enable_paging,
            'max_retries': ldap_connection.max_retries
        }
        self.max_workers = max_workers
        self.rate_limit = rate_limit
        self.executor: Optional[ThreadPoolExecutor] = None
        self._thread_local = threading.local()
    
    def _get_ldap_connection(self):
        """Get or create LDAP connection for current thread."""
        if not hasattr(self._thread_local, 'ldap_conn'):
            from core.ldap_connection import LDAPConnection
            conn = LDAPConnection(**self.base_ldap_config)
            try:
                conn.connect()
                self._thread_local.ldap_conn = conn
            except Exception as e:
                logger.error(f"Failed to create LDAP connection in thread: {str(e)}")
                raise
        return self._thread_local.ldap_conn
    
    def execute_query(self, search_filter: str, search_base: Optional[str] = None,
                     attributes: Optional[List[str]] = None, size_limit: int = 0) -> List[Dict[str, Any]]:
        """
        Execute single LDAP query in current thread.
        
        Args:
            search_filter: LDAP search filter
            search_base: Base DN for search
            attributes: Attributes to retrieve
            size_limit: Maximum results
            
        Returns:
            List of query results
        """
        conn = self._get_ldap_connection()
        time.sleep(self.rate_limit)  # Rate limiting per thread
        return conn.search(
            search_base=search_base,
            search_filter=search_filter,
            attributes=attributes,
            size_limit=size_limit,
            use_cache=True
        )
    
    def execute_parallel(self, queries: List[Dict[str, Any]], 
                        progress_callback: Optional[Callable] = None) -> Dict[str, List[Dict[str, Any]]]:
        """
        Execute multiple LDAP queries in parallel.
        
        Args:
            queries: List of query dicts with keys: 'filter', 'base', 'attributes', 'size_limit', 'id'
            progress_callback: Optional callback function(current, total)
            
        Returns:
            Dict mapping query IDs to results
        """
        results = {}
        completed = 0
        total = len(queries)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all queries
            future_to_query = {}
            for query in queries:
                query_id = query.get('id', f"query_{len(future_to_query)}")
                future = executor.submit(
                    self.execute_query,
                    query.get('filter', '(objectClass=*)'),
                    query.get('base'),
                    query.get('attributes'),
                    query.get('size_limit', 0)
                )
                future_to_query[future] = query_id
            
            # Collect results as they complete
            for future in as_completed(future_to_query):
                query_id = future_to_query[future]
                try:
                    result = future.result()
                    results[query_id] = result
                    completed += 1
                    if progress_callback:
                        progress_callback(completed, total)
                except Exception as e:
                    logger.error(f"Query {query_id} failed: {str(e)}")
                    results[query_id] = []
        
        return results
    
    def cleanup(self):
        """Cleanup thread-local connections."""
        if hasattr(self._thread_local, 'ldap_conn'):
            try:
                self._thread_local.ldap_conn.disconnect()
            except Exception:
                pass
            delattr(self._thread_local, 'ldap_conn')


class ParallelCollector:
    """
    Base class for parallel data collection.
    """
    
    def __init__(self, parallel_executor: ParallelLDAPExecutor, show_progress: bool = True):
        """
        Initialize parallel collector.
        
        Args:
            parallel_executor: ParallelLDAPExecutor instance
            show_progress: Whether to show progress
        """
        self.executor = parallel_executor
        self.show_progress = show_progress
    
    def collect_parallel(self, queries: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Collect data using parallel queries.
        
        Args:
            queries: List of query dictionaries
            
        Returns:
            Dict mapping query IDs to results
        """
        from core.progress_tracker import create_progress_callback
        
        progress_callback = None
        if self.show_progress:
            progress_callback = create_progress_callback(
                operation_name="Parallel collection",
                total_items=len(queries)
            )
        
        return self.executor.execute_parallel(queries, progress_callback)
