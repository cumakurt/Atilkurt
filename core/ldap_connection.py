"""
LDAP Connection Module
Read-only LDAP connection using ldap3 library
"""

from typing import Optional, List, Dict, Any
from ldap3 import Server, Connection, ALL, Tls, NTLM, SIMPLE
from ldap3.core.exceptions import LDAPException, LDAPOperationResult
import ssl
import logging
import time

from core.exceptions import LDAPConnectionError, LDAPSearchError, ValidationError
from core.validators import validate_domain, validate_ip_address, validate_username, validate_password, validate_timeout
from core.cache import LDAPQueryCache
from core.config import LDAPConfig, get_config

logger = logging.getLogger(__name__)


class LDAPConnection:
    """
    Secure read-only LDAP connection class.
    Only performs SEARCH operations, never write/modify/delete.
    """
    
    def __init__(self, domain: str, username: str, password: str, dc_ip: str, 
                 use_ssl: bool = False, timeout: Optional[int] = None, page_size: Optional[int] = None,
                 enable_paging: bool = True, max_retries: Optional[int] = None, 
                 retry_delay: Optional[float] = None, adaptive_timeout: bool = True,
                 enable_cache: bool = True, cache_ttl: int = 300,
                 validate_certificate: bool = True):
        """
        Initialize LDAP connection parameters.
        
        Args:
            domain: Domain name (e.g., example.com)
            username: LDAP username (without domain prefix, domain is specified separately)
                     Can also accept domain\\username or username@domain format for compatibility
            password: LDAP password
            dc_ip: Domain Controller IP address
            use_ssl: Enable SSL/TLS (default: False)
            timeout: Base connection timeout in seconds (default: 30)
            page_size: Page size for paged searches (default: 1000)
            enable_paging: Enable LDAP paging for large result sets (default: True)
            max_retries: Maximum number of retry attempts (default: 3)
            retry_delay: Delay between retries in seconds (default: 2.0)
            adaptive_timeout: Enable adaptive timeout based on result size (default: True)
            validate_certificate: If True, validate SSL/TLS server certificate (default: True;
                                 set False only for lab environments with self-signed certs)
        
        Raises:
            ValidationError: If input validation fails
        """
        # Get config defaults if not provided
        config = get_config()
        ldap_config = config.ldap if config else None
        
        # Validate inputs and use config defaults if not provided
        self.domain = validate_domain(domain)
        self.username = validate_username(username)
        self.password = validate_password(password)
        self.dc_ip = validate_ip_address(dc_ip)
        self.use_ssl = bool(use_ssl)
        self.base_timeout = validate_timeout(timeout if timeout is not None else (ldap_config.default_timeout if ldap_config else 30))
        # Default page size, but respect AD server limits
        # Some AD servers have MaxPageSize limit of 1000, so we use min(5000, requested)
        default_page_size = ldap_config.page_size if ldap_config else 5000
        requested_page_size = page_size if page_size is not None else default_page_size
        # Cap at 1000 to avoid AD server limits, but allow override
        self.page_size = max(1, min(requested_page_size, 5000))
        self.enable_paging = bool(enable_paging)
        self.max_retries = max(1, max_retries if max_retries is not None else (ldap_config.max_retries if ldap_config else 3))
        self.retry_delay = max(0.0, retry_delay if retry_delay is not None else (ldap_config.retry_delay if ldap_config else 2.0))
        self.adaptive_timeout = bool(adaptive_timeout)
        self.validate_certificate = bool(validate_certificate)
        
        # Caching
        self.enable_cache = bool(enable_cache)
        self.query_cache = LDAPQueryCache(default_ttl=cache_ttl) if enable_cache else None
        
        # Normalize username format
        self.username = self._normalize_username(self.username, self.domain)
        self.connection: Optional[Connection] = None
        self.base_dn = self._get_base_dn(self.domain)
        
        # Adaptive timeout tracking
        self.estimated_result_size = 0
        self.last_query_duration = 0.0
    
    def _normalize_username(self, username: str, domain: str) -> str:
        """
        Normalize username to domain\\username format.
        Supports username only (domain will be prepended), domain\\username, or username@domain formats.
        
        Args:
            username: Username (can be just username, domain\\username, or username@domain)
            domain: Domain name (used if username doesn't contain domain)
        
        Returns:
            str: Normalized username in domain\\username format
        """
        # If already in domain\username format, return as is
        if '\\' in username:
            return username
        
        # If in username@domain format, convert to domain\username
        if '@' in username:
            parts = username.split('@')
            if len(parts) == 2:
                return f"{parts[1]}\\{parts[0]}"
        
        # Otherwise, prepend domain
        return f"{domain}\\{username}"
        
    def _get_base_dn(self, domain: str) -> str:
        """Convert domain name to base DN format."""
        return ','.join([f'DC={part}' for part in domain.split('.')])
    
    def connect(self) -> bool:
        """
        Establish LDAP connection.
        Tries SSL first if enabled, then falls back to non-SSL.
        
        Returns:
            bool: True if connection successful, False otherwise
        
        Raises:
            LDAPConnectionError: If all connection attempts fail
        """
        # Try SSL first if enabled, then fallback to non-SSL
        ssl_attempts = [self.use_ssl, False] if self.use_ssl else [False]
        
        last_error: Optional[Exception] = None
        
        for use_ssl_attempt in ssl_attempts:
            try:
                # Configure TLS if SSL is enabled
                tls_config: Optional[Tls] = None
                if use_ssl_attempt:
                    # Validate certificate if requested (recommended for production)
                    tls_validate = ssl.CERT_REQUIRED if self.validate_certificate else ssl.CERT_NONE
                    tls_config = Tls(validate=tls_validate)
                
                # Create server object
                port = 636 if use_ssl_attempt else 389
                try:
                    server = Server(
                        self.dc_ip,
                        port=port,
                        use_ssl=use_ssl_attempt,
                        tls=tls_config,
                        get_info=ALL
                    )
                except (LDAPException, Exception) as server_error:
                    # If get_info=ALL fails, try without it
                    logger.debug(f"Server creation with get_info=ALL failed: {str(server_error)}")
                    try:
                        server = Server(
                            self.dc_ip,
                            port=port,
                            use_ssl=use_ssl_attempt,
                            tls=tls_config,
                            get_info=None
                        )
                    except Exception as e:
                        logger.warning(f"Server creation failed: {str(e)}")
                        last_error = e
                        continue
                
                # Try different authentication methods
                auth_methods = [NTLM, SIMPLE]
                
                for auth_method in auth_methods:
                    try:
                        self.connection = Connection(
                            server,
                            user=self.username,
                            password=self.password,
                            authentication=auth_method,
                            auto_bind=True,
                            receive_timeout=self.base_timeout
                        )
                        
                        # Connection successful
                        ssl_status = "SSL" if use_ssl_attempt else "non-SSL"
                        auth_status = "NTLM" if auth_method == NTLM else "SIMPLE"
                        logger.info(f"LDAP connection established to {self.dc_ip}:{port} ({ssl_status}, {auth_status})")
                        self.use_ssl = use_ssl_attempt  # Update actual SSL status
                        return True
                        
                    except LDAPException as auth_error:
                        # Try next authentication method
                        logger.debug(f"Authentication method {auth_method} failed: {str(auth_error)}")
                        last_error = auth_error
                        continue
                
                # If all auth methods failed, try next SSL option
                logger.debug(f"All authentication methods failed for {self.dc_ip}:{port}")
                continue
                
            except LDAPException as e:
                error_msg = str(e).lower()
                if 'invalid server address' in error_msg or 'connection' in error_msg:
                    logger.debug(f"Connection failed to {self.dc_ip}:{port} ({'SSL' if use_ssl_attempt else 'non-SSL'}): {str(e)}")
                    last_error = e
                    continue
                else:
                    logger.error(f"LDAP connection error: {str(e)}")
                    last_error = e
                    continue
            except Exception as e:
                logger.error(f"Unexpected error during connection: {str(e)}")
                last_error = e
                continue
        
        # All connection attempts failed
        error_msg = f"Failed to establish LDAP connection to {self.dc_ip} (tried SSL and non-SSL)"
        if last_error:
            raise LDAPConnectionError(f"{error_msg}: {str(last_error)}") from last_error
        raise LDAPConnectionError(error_msg)
    
    def search(self, search_base: Optional[str] = None, 
               search_filter: str = '(objectClass=*)', 
               attributes: Optional[List[str]] = None, 
               size_limit: int = 0,
               progress_callback: Optional[callable] = None,
               use_cache: bool = True) -> List[Dict[str, Any]]:
        """
        Perform LDAP search operation (READ-ONLY) with optional paging support and retry logic.
        
        Args:
            search_base: Base DN for search (default: domain base DN)
            search_filter: LDAP search filter
            attributes: List of attributes to retrieve (None = all)
            size_limit: Maximum number of results (0 = unlimited)
            progress_callback: Optional callback function(count, total) for progress tracking
        
        Returns:
            list: List of search results (entries)
        
        Raises:
            LDAPSearchError: If connection is not established or search fails
        """
        if not self.connection:
            raise LDAPSearchError("LDAP connection not established. Call connect() first.")
        
        if search_base is None:
            search_base = self.base_dn
        
        # Check cache first if enabled
        if self.enable_cache and use_cache and self.query_cache:
            cached_result = self.query_cache.get_query_result(search_filter, search_base)
            if cached_result is not None:
                logger.debug(f"Cache hit for LDAP query: {search_filter[:50]}...")
                if progress_callback:
                    progress_callback(len(cached_result), len(cached_result))
                return cached_result
        
        # Calculate adaptive timeout if enabled
        timeout = self._calculate_timeout(size_limit)
        
        last_error = None
        for attempt in range(self.max_retries):
            try:
                # Use paged search for large result sets if enabled
                # But skip paging for single object searches (size_limit=1) to avoid retry issues
                if self.enable_paging and (size_limit == 0 or size_limit > self.page_size) and size_limit != 1:
                    start_time = time.time()
                    results = self._paged_search(
                        search_base=search_base,
                        search_filter=search_filter,
                        attributes=attributes,
                        size_limit=size_limit,
                        progress_callback=progress_callback,
                        timeout=timeout
                    )
                    self.last_query_duration = time.time() - start_time
                    
                    # Cache result if enabled
                    if self.enable_cache and use_cache and self.query_cache:
                        self.query_cache.set_query_result(search_filter, results, search_base)
                    
                    return results
                else:
                    # Standard search for small result sets
                    start_time = time.time()
                    self.connection.search(
                        search_base=search_base,
                        search_filter=search_filter,
                        attributes=attributes,
                        size_limit=size_limit
                    )
                    
                    results: List[Dict[str, Any]] = []
                    for entry in self.connection.entries:
                        entry_dict = self._entry_to_dict(entry)
                        results.append(entry_dict)
                    
                    self.last_query_duration = time.time() - start_time
                    
                    # Cache result if enabled
                    if self.enable_cache and use_cache and self.query_cache:
                        self.query_cache.set_query_result(search_filter, results, search_base)
                    
                    if progress_callback:
                        progress_callback(len(results), len(results))
                    
                    return results
            
            except LDAPConnectionError as e:
                # Re-raise connection errors immediately (no retry)
                logger.error(f"LDAP connection error: {str(e)}")
                raise
            except LDAPSearchError as e:
                # Re-raise search errors if not retryable
                error_msg = str(e).lower()
                if not self._is_retryable_error(error_msg) or attempt >= self.max_retries - 1:
                    logger.error(f"LDAP search error: {str(e)}")
                    raise
                last_error = e
            except LDAPException as e:
                last_error = e
                error_msg = str(e).lower()
                
                # Check if this is an "invalid attribute" error - these are usually non-critical
                if 'invalid attribute' in error_msg or 'no such attribute' in error_msg:
                    # Log at debug level for attribute errors (common when attributes don't exist)
                    logger.debug(f"LDAP attribute error (non-critical, attribute may not exist): {str(e)}")
                    # Return empty list instead of raising exception for attribute errors
                    # This allows callers to handle gracefully
                    return []
                
                # Check if error is retryable
                if self._is_retryable_error(error_msg) and attempt < self.max_retries - 1:
                    wait_time = self.retry_delay * (attempt + 1)  # Exponential backoff
                    logger.warning(
                        f"LDAP search failed (attempt {attempt + 1}/{self.max_retries}): {str(e)}. "
                        f"Retrying in {wait_time:.1f} seconds..."
                    )
                    time.sleep(wait_time)
                    
                    # Try to reconnect if connection might be lost
                    try:
                        if not self.connection.bound:
                            logger.info("Reconnecting to LDAP server...")
                            self.connect()
                    except Exception:
                        pass
                    continue
                else:
                    error_msg = f"LDAP search error: {str(e)}"
                    logger.error(error_msg)
                    raise LDAPSearchError(error_msg) from e
            except Exception as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    wait_time = self.retry_delay * (attempt + 1)
                    logger.warning(
                        f"Unexpected error during search (attempt {attempt + 1}/{self.max_retries}): "
                        f"{str(e)}. Retrying in {wait_time:.1f} seconds..."
                    )
                    time.sleep(wait_time)
                    continue
                else:
                    error_msg = f"Unexpected error during search: {str(e)}"
                    logger.error(error_msg)
                    raise LDAPSearchError(error_msg) from e
        
        # All retries exhausted
        if last_error:
            raise LDAPSearchError(f"LDAP search failed after {self.max_retries} attempts: {str(last_error)}") from last_error
        raise LDAPSearchError("LDAP search failed after multiple attempts")
    
    def _calculate_timeout(self, size_limit: int) -> int:
        """
        Calculate adaptive timeout based on expected result size.
        
        Args:
            size_limit: Maximum number of results expected
        
        Returns:
            Calculated timeout in seconds
        """
        if not self.adaptive_timeout:
            return self.base_timeout
        
        # Base timeout
        timeout = self.base_timeout
        
        # Increase timeout based on expected result size
        if size_limit > 0:
            # Estimate: ~0.1 seconds per 1000 results
            estimated_time = (size_limit / 1000) * 0.1
            timeout = max(self.base_timeout, int(estimated_time) + 10)
        elif self.estimated_result_size > 0:
            # Use previous estimate
            estimated_time = (self.estimated_result_size / 1000) * 0.1
            timeout = max(self.base_timeout, int(estimated_time) + 10)
        
        # Cap at reasonable maximum (5 minutes)
        timeout = min(timeout, 300)
        
        return timeout
    
    def _is_retryable_error(self, error_msg: str) -> bool:
        """
        Check if an error is retryable.
        
        Args:
            error_msg: Error message (lowercase)
        
        Returns:
            True if error is retryable
        """
        retryable_keywords = [
            'timeout',
            'connection',
            'network',
            'temporary',
            'busy',
            'unavailable',
            'server unavailable',
            'connection reset'
        ]
        
        return any(keyword in error_msg for keyword in retryable_keywords)
    
    def _paged_search(self, search_base: str, search_filter: str,
                     attributes: Optional[List[str]], size_limit: int,
                     progress_callback: Optional[callable] = None,
                     timeout: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Perform paged LDAP search for large result sets.
        
        Args:
            search_base: Base DN for search
            search_filter: LDAP search filter
            attributes: List of attributes to retrieve
            size_limit: Maximum number of results (0 = unlimited)
            progress_callback: Optional callback function(count, total) for progress tracking
            timeout: Timeout for this search operation
        
        Returns:
            list: List of search results (entries)
        """
        results: List[Dict[str, Any]] = []
        cookie = None
        total_count = 0
        start_time = time.time()
        
        if timeout is None:
            timeout = self._calculate_timeout(size_limit)
        
        try:
            # Use ldap3's paged search with manual cookie management
            while True:
                # Check timeout
                elapsed = time.time() - start_time
                if elapsed > timeout:
                    logger.warning(f"Paged search timeout after {elapsed:.1f} seconds")
                    break
                
                # Clear entries before each search to avoid accumulating
                # This is important for paged searches
                if hasattr(self.connection, 'entries'):
                    # Store current entries count before clearing
                    pass
                
                # Perform paged search
                try:
                    # Clear entries list before each search to avoid accumulating
                    # ldap3 accumulates entries across paged searches, so we need to track what's new
                    entries_before = len(self.connection.entries) if hasattr(self.connection, 'entries') else 0
                    
                    self.connection.search(
                        search_base=search_base,
                        search_filter=search_filter,
                        attributes=attributes,
                        paged_size=self.page_size,
                        paged_cookie=cookie
                    )
                except Exception as search_error:
                    error_msg = str(search_error).lower()
                    # Check if this is an "invalid attribute" error - these are usually non-critical
                    if 'invalid attribute' in error_msg or 'no such attribute' in error_msg:
                        # Log at debug level for attribute errors (common when attributes don't exist)
                        logger.debug(f"LDAP paged search attribute error (non-critical, attribute may not exist): {str(search_error)}")
                        # Return empty list for attribute errors on first page
                        if cookie is None:
                            return []
                        break
                    else:
                        logger.warning(f"Paged search error: {str(search_error)}")
                        # If search fails, try without paging as fallback
                        if cookie is None:
                            raise
                        break
                
                # Process entries in current page
                # ldap3 accumulates entries, so we only process new ones
                page_count = 0
                current_page_entries = []
                
                # Get all entries and process only new ones
                all_entries = list(self.connection.entries) if hasattr(self.connection, 'entries') else []
                new_entries = all_entries[entries_before:] if entries_before < len(all_entries) else all_entries
                
                for entry in new_entries:
                    entry_dict = self._entry_to_dict(entry)
                    current_page_entries.append(entry_dict)
                    page_count += 1
                    total_count += 1
                    
                    # Check size limit
                    if size_limit > 0 and total_count >= size_limit:
                        # Add remaining entries before breaking
                        results.extend(current_page_entries)
                        cookie = None
                        break
                
                # Add page entries to results
                results.extend(current_page_entries)
                
                # Get cookie for next page - try multiple methods
                next_cookie = self._get_paged_cookie()
                
                # Debug: Log cookie status
                if next_cookie is None:
                    logger.debug(f"No cookie found after page with {page_count} entries")
                elif isinstance(next_cookie, bytes):
                    logger.debug(f"Cookie found: {len(next_cookie)} bytes")
                else:
                    logger.debug(f"Cookie found: {type(next_cookie)}")
                
                # Progress callback
                if progress_callback:
                    progress_callback(total_count, None)  # None = unknown total
                
                logger.info(f"Paged search: retrieved {total_count} entries so far (page had {page_count} entries)")
                
                # If no entries in this page, we're done
                if page_count == 0:
                    logger.info("No entries in current page, ending paged search")
                    break
                
                # Check if we've reached size limit
                if size_limit > 0 and total_count >= size_limit:
                    logger.info(f"Reached size limit of {size_limit}, ending paged search")
                    break
                
                # If no cookie or empty cookie, we're done
                if next_cookie is None:
                    # Only log warning if we got entries but no cookie (unexpected)
                    # If page_count is 0, it's normal to have no cookie
                    if page_count > 0:
                        logger.debug(f"No cookie returned after {total_count} entries (page had {page_count} entries) - likely last page")
                    else:
                        logger.debug(f"No cookie returned and no entries in page - ending search")
                    break
                
                if isinstance(next_cookie, bytes) and len(next_cookie) == 0:
                    logger.debug(f"Empty cookie returned after {total_count} entries - all results retrieved")
                    break
                
                # Continue with next page
                cookie = next_cookie
                logger.debug(f"Continuing paged search with cookie (length: {len(cookie) if isinstance(cookie, bytes) else 'N/A'}) - total so far: {total_count}")
            
            # Update estimated result size for future queries
            if total_count > 0:
                self.estimated_result_size = total_count
            
            logger.info(f"Paged search completed: {total_count} total entries")
            return results
            
        except LDAPException as e:
            error_msg_lower = str(e).lower()
            # Check if this is an "invalid attribute" error - these are usually non-critical
            if 'invalid attribute' in error_msg_lower or 'no such attribute' in error_msg_lower:
                # Log at debug level and return empty list instead of raising exception
                logger.debug(f"LDAP paged search attribute error (non-critical, attribute may not exist): {str(e)}")
                return []
            error_msg = f"LDAP paged search error: {str(e)}"
            logger.error(error_msg)
            raise LDAPSearchError(error_msg) from e
    
    def _get_paged_cookie(self) -> Optional[bytes]:
        """
        Get paged search cookie from LDAP result.
        In ldap3, cookie is in connection.result['controls'], NOT connection.response!
        
        Returns:
            Cookie bytes or None if no more pages
        """
        try:
            paged_oid = '1.2.840.113556.1.4.319'  # Paged results control OID
            
            # Method 1: connection.result['controls'] - THIS IS THE CORRECT METHOD!
            # ldap3 stores paging cookie in result, not response!
            try:
                if hasattr(self.connection, 'result'):
                    result = self.connection.result
                    # Debug: Log result structure (only once)
                    if not hasattr(self, '_debugged_result'):
                        logger.info(f"Result type: {type(result)}")
                        if isinstance(result, dict):
                            logger.info(f"Result keys: {list(result.keys())}")
                            if 'controls' in result:
                                logger.info(f"Controls type: {type(result['controls'])}, keys: {list(result['controls'].keys()) if isinstance(result['controls'], dict) else 'N/A'}")
                        self._debugged_result = True
                    
                    if isinstance(result, dict) and 'controls' in result:
                        controls = result['controls']
                        if isinstance(controls, dict) and paged_oid in controls:
                            paged_control = controls[paged_oid]
                            # Debug: Log paged control structure
                            if not hasattr(self, '_debugged_paged_control'):
                                logger.info(f"Paged control type: {type(paged_control)}")
                                if isinstance(paged_control, dict):
                                    logger.info(f"Paged control keys: {list(paged_control.keys())}")
                                    if 'value' in paged_control:
                                        logger.info(f"Paged control value type: {type(paged_control['value'])}, value: {paged_control['value']}")
                                self._debugged_paged_control = True
                            
                            # Cookie is in paged_control['value']['cookie']
                            if isinstance(paged_control, dict):
                                if 'value' in paged_control:
                                    value = paged_control['value']
                                    if isinstance(value, dict) and 'cookie' in value:
                                        cookie = value['cookie']
                                        if cookie:
                                            if isinstance(cookie, bytes):
                                                logger.info(f"Found cookie via Method 1 (result['controls']['value']['cookie']) - {len(cookie)} bytes")
                                                return cookie if len(cookie) > 0 else None
                                            else:
                                                try:
                                                    cookie_bytes = bytes(cookie)
                                                    logger.info(f"Found cookie via Method 1 (result['controls']['value']['cookie'] converted) - {len(cookie_bytes)} bytes")
                                                    return cookie_bytes if len(cookie_bytes) > 0 else None
                                                except Exception:
                                                    pass
                                    # If value is directly the cookie (bytes)
                                    elif isinstance(value, bytes):
                                        logger.info(f"Found cookie via Method 1 (result['controls']['value'] as bytes) - {len(value)} bytes")
                                        return value if len(value) > 0 else None
                                # Also try direct cookie access
                                if 'cookie' in paged_control:
                                    cookie = paged_control['cookie']
                                    if cookie:
                                        if isinstance(cookie, bytes):
                                            logger.info(f"Found cookie via Method 1 (result['controls'] direct cookie) - {len(cookie)} bytes")
                                            return cookie if len(cookie) > 0 else None
                                        else:
                                            try:
                                                cookie_bytes = bytes(cookie)
                                                logger.info(f"Found cookie via Method 1 (result['controls'] direct cookie converted) - {len(cookie_bytes)} bytes")
                                                return cookie_bytes if len(cookie_bytes) > 0 else None
                                            except Exception:
                                                pass
            except Exception as e:
                logger.debug(f"Method 1 (result) failed: {str(e)}")
                import traceback
                logger.debug(traceback.format_exc())
            
            # Method 2: Try connection.response['controls'] (fallback, though usually wrong)
            try:
                if hasattr(self.connection, 'response'):
                    response = self.connection.response
                    if isinstance(response, dict) and 'controls' in response:
                        controls = response['controls']
                        if isinstance(controls, dict) and paged_oid in controls:
                            paged_control = controls[paged_oid]
                            cookie = self._extract_cookie_from_control(paged_control)
                            if cookie is not None:
                                logger.info(f"Found cookie via Method 2 (response['controls']) - {len(cookie)} bytes")
                                return cookie
                        # Also try if controls is a list
                        elif isinstance(controls, list):
                            for control in controls:
                                if hasattr(control, 'controlType') and control.controlType == paged_oid:
                                    cookie = self._extract_cookie_from_control(control)
                                    if cookie is not None:
                                        logger.info(f"Found cookie via Method 2 (response['controls'] list) - {len(cookie)} bytes")
                                        return cookie
            except Exception as e:
                logger.debug(f"Method 2 failed: {str(e)}")
            
            # Method 3: Try connection.result.controls (if result is an object)
            try:
                if hasattr(self.connection, 'result'):
                    result = self.connection.result
                    if hasattr(result, 'controls'):
                        controls = result.controls
                        if isinstance(controls, dict) and paged_oid in controls:
                            paged_control = controls[paged_oid]
                            cookie = self._extract_cookie_from_control(paged_control)
                            if cookie is not None:
                                logger.info(f"Found cookie via Method 3 (result.controls) - {len(cookie)} bytes")
                                return cookie
            except Exception as e:
                logger.debug(f"Method 3 failed: {str(e)}")
            
            # Method 4: Try connection.controls directly (some ldap3 versions)
            try:
                if hasattr(self.connection, 'controls'):
                    controls = self.connection.controls
                    if isinstance(controls, dict) and paged_oid in controls:
                        paged_control = controls[paged_oid]
                        cookie = self._extract_cookie_from_control(paged_control)
                        if cookie is not None:
                            logger.info(f"Found cookie via Method 4 (connection.controls) - {len(cookie)} bytes")
                            return cookie
            except Exception as e:
                logger.debug(f"Method 4 failed: {str(e)}")
            
            # No cookie found - this means we're on the last page
            # Only log as debug since this is normal when all pages are retrieved
            logger.debug("No cookie found in any method - likely last page (all results retrieved)")
            return None
            
        except Exception as e:
            logger.warning(f"Error getting paged cookie: {str(e)}")
            import traceback
            logger.debug(traceback.format_exc())
            return None
    
    def _extract_cookie_from_control(self, control) -> Optional[bytes]:
        """
        Extract cookie from a paged results control object.
        In ldap3, cookie is typically in control['value']['cookie'] format.
        
        Args:
            control: Control object (can be dict, object, etc.)
        
        Returns:
            Cookie bytes or None
        """
        try:
            # If control is a dict (most common in ldap3)
            if isinstance(control, dict):
                # Method 1: Try 'value' -> 'cookie' (ldap3 standard format)
                if 'value' in control:
                    value = control['value']
                    if isinstance(value, dict):
                        cookie = value.get('cookie')
                        if cookie:
                            if isinstance(cookie, bytes):
                                return cookie if len(cookie) > 0 else None
                            else:
                                try:
                                    cookie_bytes = bytes(cookie) if cookie else None
                                    return cookie_bytes if cookie_bytes and len(cookie_bytes) > 0 else None
                                except Exception:
                                    pass
                    # If value is directly the cookie (bytes)
                    elif isinstance(value, bytes):
                        return value if len(value) > 0 else None
                
                # Method 2: Try 'cookie' key directly
                cookie = control.get('cookie')
                if cookie:
                    if isinstance(cookie, bytes):
                        return cookie if len(cookie) > 0 else None
                    else:
                        try:
                            cookie_bytes = bytes(cookie) if cookie else None
                            return cookie_bytes if cookie_bytes and len(cookie_bytes) > 0 else None
                        except Exception:
                            pass
                
                # Method 3: Try 'controlValue' key
                if 'controlValue' in control:
                    control_value = control['controlValue']
                    if isinstance(control_value, dict) and 'cookie' in control_value:
                        cookie = control_value['cookie']
                        if cookie:
                            if isinstance(cookie, bytes):
                                return cookie if len(cookie) > 0 else None
                            else:
                                try:
                                    cookie_bytes = bytes(cookie) if cookie else None
                                    return cookie_bytes if cookie_bytes and len(cookie_bytes) > 0 else None
                                except Exception:
                                    pass
            
            # If control is an object with attributes
            elif hasattr(control, 'cookie'):
                cookie = control.cookie
                if cookie:
                    if isinstance(cookie, bytes):
                        return cookie if len(cookie) > 0 else None
                    else:
                        try:
                            cookie_bytes = bytes(cookie) if cookie else None
                            return cookie_bytes if cookie_bytes and len(cookie_bytes) > 0 else None
                        except Exception:
                            pass
            
            # Try value attribute
            elif hasattr(control, 'value'):
                value = control.value
                if isinstance(value, dict) and hasattr(value, 'cookie'):
                    cookie = value.cookie
                    if cookie:
                        if isinstance(cookie, bytes):
                            return cookie if len(cookie) > 0 else None
                        else:
                            try:
                                cookie_bytes = bytes(cookie) if cookie else None
                                return cookie_bytes if cookie_bytes and len(cookie_bytes) > 0 else None
                            except Exception:
                                pass
            
            elif hasattr(control, 'controlValue'):
                cookie = control.controlValue
                if cookie:
                    if isinstance(cookie, bytes):
                        return cookie if len(cookie) > 0 else None
                    else:
                        try:
                            cookie_bytes = bytes(cookie) if cookie else None
                            return cookie_bytes if cookie_bytes and len(cookie_bytes) > 0 else None
                        except Exception:
                            pass
            
            return None
            
        except Exception as e:
            logger.debug(f"Error extracting cookie from control: {str(e)}")
            return None
    
    def _entry_to_dict(self, entry) -> Dict[str, Any]:
        """
        Convert LDAP entry to dictionary.
        
        Args:
            entry: LDAP entry object
        
        Returns:
            dict: Dictionary representation of entry
        """
        entry_dict: Dict[str, Any] = {}
        for attr in entry.entry_attributes:
            values = entry[attr].values
            entry_dict[attr] = values if len(values) > 1 else values[0] if values else None
        entry_dict['dn'] = str(entry.entry_dn)
        return entry_dict
    
    def disconnect(self) -> None:
        """Close LDAP connection."""
        if self.connection:
            try:
                self.connection.unbind()
            except Exception as e:
                logger.warning(f"Error during disconnect: {str(e)}")
            finally:
                self.connection = None
                logger.info("LDAP connection closed")
    
    def __enter__(self) -> 'LDAPConnection':
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type: Optional[type], exc_val: Optional[Exception], 
                 exc_tb: Optional[Any]) -> None:
        """Context manager exit."""
        self.disconnect()
