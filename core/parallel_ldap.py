"""
Parallel LDAP Query Module
Enables parallel LDAP queries with multi-threading support
"""

import logging
import threading
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Any, Optional, Callable
import time
import math

from core.exceptions import LDAPSearchError, ValidationError

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
        if not isinstance(max_workers, int) or not 1 <= max_workers <= 64:
            raise ValidationError('Parallel workers must be between 1 and 64')
        if not isinstance(rate_limit, (int, float)) or not math.isfinite(rate_limit) or rate_limit < 0:
            raise ValidationError('Parallel rate limit must be a finite non-negative number')
        self.base_ldap_config = {
            'domain': ldap_connection.domain,
            'username': ldap_connection.username,
            'password': ldap_connection.password,
            'dc_ip': ldap_connection.dc_ip,
            'use_ssl': ldap_connection.use_ssl,
            'timeout': ldap_connection.base_timeout,
            'page_size': ldap_connection.page_size,
            'enable_paging': ldap_connection.enable_paging,
            'max_retries': ldap_connection.max_retries,
            'retry_delay': ldap_connection.retry_delay,
            'adaptive_timeout': ldap_connection.adaptive_timeout,
            'enable_cache': ldap_connection.enable_cache,
            'validate_certificate': ldap_connection.validate_certificate,
        }
        self.max_workers = max_workers
        self.rate_limit = rate_limit
        self.base_connection = ldap_connection
        self.assessment_scope = getattr(ldap_connection, 'assessment_scope', None)
        self.pre_search_hook = getattr(ldap_connection, 'pre_search_hook', None)
        self.executor: Optional[ThreadPoolExecutor] = None
        self._thread_local = threading.local()
        self._connections = []
        self._connections_lock = threading.Lock()
        self._execution_lock = threading.Lock()

    def _get_ldap_connection(self):
        """Get or create LDAP connection for current thread."""
        if not hasattr(self._thread_local, 'ldap_conn'):
            from core.ldap_connection import LDAPConnection
            conn = LDAPConnection(**self.base_ldap_config)
            conn.assessment_scope = self.assessment_scope
            conn.pre_search_hook = self.pre_search_hook
            try:
                conn.connect()
                self._thread_local.ldap_conn = conn
                with self._connections_lock:
                    self._connections.append(conn)
            except Exception as e:
                conn.disconnect()
                logger.error(f"Failed to create LDAP connection in thread: {str(e)}")
                raise
        return self._thread_local.ldap_conn

    def execute_query(self, search_filter: str, search_base: Optional[str] = None,
                     attributes: Optional[list[str]] = None, size_limit: int = 0) -> list[dict[str, Any]]:
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

    def execute_parallel(self, queries: list[dict[str, Any]],
                        progress_callback: Optional[Callable] = None) -> dict[str, list[dict[str, Any]]]:
        """
        Execute multiple LDAP queries in parallel.

        Args:
            queries: List of query dicts with keys: 'filter', 'base', 'attributes', 'size_limit', 'id'
            progress_callback: Optional callback function(current, total)

        Returns:
            Dict mapping query IDs to results
        """
        identifiers = []
        for index, query in enumerate(queries):
            if not isinstance(query, dict):
                raise ValidationError('Parallel queries must be objects')
            identifier = query.get('id', f'query_{index}')
            if not isinstance(identifier, str) or not identifier:
                raise ValidationError('Parallel query IDs must be non-empty strings')
            identifiers.append(identifier)
        if len(set(identifiers)) != len(identifiers):
            raise ValidationError('Parallel query IDs must be unique')

        results, failures = {}, []
        completed, total = 0, len(queries)
        with self._execution_lock:
            try:
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    pending, next_index = {}, 0
                    while next_index < total or pending:
                        # Bound queued work as well as active threads.
                        while next_index < total and len(pending) < 2 * self.max_workers:
                            query = queries[next_index]
                            future = executor.submit(
                                self.execute_query, query.get('filter', '(objectClass=*)'),
                                query.get('base'), query.get('attributes'), query.get('size_limit', 0),
                            )
                            pending[future] = identifiers[next_index]
                            next_index += 1
                        done, _ = wait(pending, return_when=FIRST_COMPLETED)
                        for future in done:
                            identifier = pending.pop(future)
                            try:
                                results[identifier] = future.result()
                            except Exception as exc:
                                failures.append(exc)
                            completed += 1
                            if progress_callback:
                                progress_callback(completed, total)
            finally:
                self.cleanup()
        if failures:
            raise LDAPSearchError(f'{len(failures)} of {total} parallel LDAP queries failed; partial results discarded') from failures[0]
        return results

    def cleanup(self):
        """Close all worker connections after the pool has stopped."""
        with self._connections_lock:
            connections, self._connections = self._connections, []
        for connection in connections:
            if hasattr(self.base_connection, 'merge_query_audit'):
                self.base_connection.merge_query_audit(getattr(connection, 'query_audit', []))
                if getattr(connection, 'query_audit_overflow', False):
                    self.base_connection.query_audit_overflow = True
            try:
                connection.disconnect()
            except Exception:
                logger.warning('Could not disconnect a parallel LDAP worker')
        if hasattr(self._thread_local, 'ldap_conn'):
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

    def collect_parallel(self, queries: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        """
        Collect data using parallel queries.

        Args:
            queries: List of query dictionaries

        Returns:
            Dict mapping query IDs to results
        """
        from core.progress_tracker import ProgressTracker, create_progress_callback

        progress_callback = None
        tracker = None
        if self.show_progress:
            tracker = ProgressTracker('Parallel collection', total_items=len(queries))
            progress_callback = create_progress_callback(tracker)

        results = self.executor.execute_parallel(queries, progress_callback)
        if tracker:
            tracker.finish()
        return results
