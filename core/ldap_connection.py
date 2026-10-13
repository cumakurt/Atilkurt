"""
LDAP Connection Module
Read-only LDAP connection using ldap3 library
"""

from typing import Optional, Any, Callable
from ldap3 import Server, Connection, ALL, Tls, NTLM, SIMPLE, SASL, KERBEROS
from ldap3.core.exceptions import LDAPException
import ssl
import logging
import time
from threading import Lock

from core.exceptions import LDAPConnectionError, LDAPSearchError
from core.assessment_scope import ScopeLimitError
from core.validators import validate_domain, validate_server_address, validate_username, validate_password, validate_timeout
from core.cache import LDAPQueryCache
from core.config import get_config

logger = logging.getLogger(__name__)

# DACL + owner + group. Do not request SACL (0x08); that needs extra privilege
# and is unused by the analyzers.
_NTSECURITYDESCRIPTOR = "ntsecuritydescriptor"
_SD_FLAGS_OWNER_GROUP_DACL = 0x07
# ldap3's read_only flag rejects modify, delete and rename, but not add.
_DIRECTORY_WRITE_METHODS = ("add", "delete", "modify", "modify_dn")


def _refuse_directory_modification(connection):
    """Stop a bound client from sending a directory update."""
    connection.read_only = True

    def reject(*_args, **_kwargs):
        raise LDAPConnectionError("LDAP connection is read-only; directory modifications are refused")

    for name in _DIRECTORY_WRITE_METHODS:
        setattr(connection, name, reject)


def _security_descriptor_controls(attributes: Optional[list[str]]):
    """Return the Microsoft SD Flags control when a security descriptor is requested."""
    names = [attributes] if isinstance(attributes, str) else list(attributes or [])
    if not any(str(name).casefold() == _NTSECURITYDESCRIPTOR for name in names):
        return None
    try:
        from ldap3.protocol.microsoft import security_descriptor_control
    except ImportError:
        return None
    return security_descriptor_control(sdflags=_SD_FLAGS_OWNER_GROUP_DACL)


class LDAPConnection:
    """
    Secure read-only LDAP connection class.
    Only performs SEARCH operations, never write/modify/delete.
    """

    def __init__(self, domain: str, username: str, password: str, dc_ip: str,
                 use_ssl: bool = True, timeout: Optional[int] = None, page_size: Optional[int] = None,
                 enable_paging: bool = True, max_retries: Optional[int] = None,
                 retry_delay: Optional[float] = None, adaptive_timeout: bool = True,
                 enable_cache: bool = True, cache_ttl: int = 300,
                 validate_certificate: bool = True, start_tls: bool = False,
                 ca_certs_file: Optional[str] = None, auth_method: str = 'ntlm'):
        """
        Initialize LDAP connection parameters.

        Args:
            domain: Domain name (e.g., example.com)
            username: LDAP username (without domain prefix, domain is specified separately)
                     Can also accept domain\\username or username@domain format for compatibility
            password: LDAP password
            dc_ip: Domain Controller IP address or hostname
            use_ssl: Enable SSL/TLS (default: True)
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
        if auth_method not in ('ntlm', 'kerberos', 'simple'):
            raise LDAPConnectionError('Unsupported LDAP authentication method')
        self.auth_method = auth_method
        self.start_tls = bool(start_tls)
        if self.start_tls and use_ssl:
            raise LDAPConnectionError('LDAPS and StartTLS cannot be requested together')
        if auth_method == 'simple' and not (use_ssl or start_tls):
            raise LDAPConnectionError('SIMPLE authentication requires TLS')
        self.ca_certs_file = ca_certs_file
        self.username = validate_username(username)
        self.password = '' if auth_method == 'kerberos' else validate_password(password)
        self.dc_ip = validate_server_address(dc_ip)
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
        if auth_method == 'ntlm':
            self.username = self._normalize_username(self.username, self.domain)
        elif auth_method == 'simple':
            parts = self.username.split('\\', 1)
            self.username = f'{parts[-1]}@{parts[0] if len(parts) == 2 else self.domain}' if '@' not in self.username else self.username
        self.connection: Optional[Connection] = None
        self.base_dn = self._get_base_dn(self.domain)
        self.pre_search_hook: Optional[Callable[[], None]] = None
        self.assessment_scope = None

        # Adaptive timeout tracking
        self.estimated_result_size = 0
        self.last_query_duration = 0.0
        self.query_audit = []
        self.query_audit_overflow = False
        self.query_failure_count = 0
        self._audit_lock = Lock()

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
        Establish an LDAP or LDAPS connection without transport downgrade.

        Returns:
            bool: True if connection successful, False otherwise

        Raises:
            LDAPConnectionError: If all connection attempts fail
        """
        # An explicit TLS request must never silently downgrade to plaintext.
        ssl_attempts = [self.use_ssl]

        last_error: Optional[Exception] = None

        for use_ssl_attempt in ssl_attempts:
            try:
                # Configure TLS if SSL is enabled
                tls_config: Optional[Tls] = None
                if use_ssl_attempt or self.start_tls:
                    # Validate certificate if requested (recommended for production)
                    tls_validate = ssl.CERT_REQUIRED if self.validate_certificate else ssl.CERT_NONE
                    tls_config = Tls(validate=tls_validate, ca_certs_file=self.ca_certs_file)

                # Create server object
                port = 636 if use_ssl_attempt else 389
                try:
                    server = Server(
                        self.dc_ip,
                        port=port,
                        use_ssl=use_ssl_attempt,
                        tls=tls_config,
                        get_info=ALL,
                        connect_timeout=self.base_timeout,
                    )
                except Exception as server_error:
                    # If get_info=ALL fails, try without it
                    logger.debug(f"Server creation with get_info=ALL failed: {str(server_error)}")
                    try:
                        server = Server(
                            self.dc_ip,
                            port=port,
                            use_ssl=use_ssl_attempt,
                            tls=tls_config,
                            get_info=None,
                            connect_timeout=self.base_timeout,
                        )
                    except Exception as e:
                        logger.warning(f"Server creation failed: {str(e)}")
                        last_error = e
                        continue

                # Try different authentication methods
                # SIMPLE bind exposes the password without transport security.
                auth_methods = [{'ntlm': NTLM, 'simple': SIMPLE, 'kerberos': SASL}[self.auth_method]]

                for auth_method in auth_methods:
                    if self.assessment_scope:
                        self.assessment_scope.consume(self.dc_ip, 'ldaps' if use_ssl_attempt or self.start_tls else 'ldap')
                    candidate_connection = None
                    try:
                        options = dict(user=self.username, password=self.password,
                                       authentication=auth_method, auto_referrals=False, read_only=True,
                                       auto_bind=not self.start_tls, receive_timeout=self.base_timeout)
                        if auth_method == SASL:
                            options.update(sasl_mechanism=KERBEROS, password=None)
                        candidate_connection = Connection(server, **options)
                        if self.start_tls:
                            candidate_connection.open()
                            if not candidate_connection.start_tls():
                                candidate_connection.unbind()
                                raise LDAPConnectionError('StartTLS negotiation failed; refusing to bind')
                            if not candidate_connection.bind():
                                candidate_connection.unbind()
                                raise LDAPConnectionError('LDAP bind failed after StartTLS')
                        if not candidate_connection.bound:
                            raise LDAPConnectionError(
                                f"LDAP {auth_method} bind did not establish a bound connection"
                            )
                        _refuse_directory_modification(candidate_connection)
                        self.connection = candidate_connection

                        # Connection successful
                        ssl_status = "SSL" if use_ssl_attempt else 'StartTLS' if self.start_tls else "non-SSL"
                        auth_status = self.auth_method.upper()
                        logger.info(f"LDAP connection established to {self.dc_ip}:{port} ({ssl_status}, {auth_status})")
                        self.use_ssl = use_ssl_attempt  # Update actual SSL status
                        return True

                    except (LDAPException, LDAPConnectionError) as auth_error:
                        if candidate_connection is not None:
                            try:
                                candidate_connection.unbind()
                            except LDAPException:
                                logger.debug('Failed to close unsuccessful LDAP bind', exc_info=True)
                        # Try next authentication method
                        logger.debug(f"Authentication method {auth_method} failed: {str(auth_error)}")
                        last_error = auth_error
                        continue

                # If all auth methods failed, try next SSL option
                logger.debug(f"All authentication methods failed for {self.dc_ip}:{port}")
                continue

            except ScopeLimitError:
                # Workers use this distinction to retain partial collection
                # diagnostics rather than treating a budget stop as a bind fault.
                raise
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
        transport = "LDAPS" if self.use_ssl else ("StartTLS" if self.start_tls else f"LDAP with {self.auth_method.upper()} authentication")
        error_msg = f"Failed to establish {transport} connection to {self.dc_ip}"
        if last_error:
            raise LDAPConnectionError(f"{error_msg}: {str(last_error)}") from last_error
        raise LDAPConnectionError(error_msg)

    def search(self, search_base: Optional[str] = None,
               search_filter: str = '(objectClass=*)',
               attributes: Optional[list[str]] = None,
               size_limit: int = 0,
               progress_callback: Optional[callable] = None,
               use_cache: bool = True) -> list[dict[str, Any]]:
        """Record query completion and attribute visibility without storing values."""
        if self.assessment_scope:
            try:
                plan = self.assessment_scope.query_plan(search_base or self.base_dn, search_filter)
            except LDAPSearchError as exc:
                def rejected(error=exc):
                    raise error
                return self._audited_query(rejected, search_base or self.base_dn, search_filter, attributes, size_limit, 'SUBTREE')
            rows, seen = [], set()
            for base, query_filter in plan:
                found = self._audited_query(
                    lambda b=base, f=query_filter: self._search_impl(b, f, attributes, size_limit,
                                                                    progress_callback, use_cache),
                    base, query_filter, attributes, size_limit, 'SUBTREE')
                for row in found:
                    dn = row.get('distinguishedName') or row.get('dn')
                    if isinstance(dn, list):
                        dn = dn[0] if dn else None
                    if not dn or not self.assessment_scope.allows_dn(dn):
                        continue
                    if str(dn).casefold() not in seen:
                        seen.add(str(dn).casefold())
                        rows.append(row)
                    if size_limit and len(rows) >= size_limit:
                        return rows
            return rows
        return self._audited_query(
            lambda: self._search_impl(search_base, search_filter, attributes, size_limit,
                                      progress_callback, use_cache),
            search_base or self.base_dn, search_filter, attributes, size_limit, 'SUBTREE',
        )

    def base_search(self, dn: str, attributes: list[str]) -> list[dict[str, Any]]:
        """Read one object without paging/cache; tokenGroups requires BASE scope."""
        from ldap3 import BASE
        def query():
            if not self.connection:
                raise LDAPSearchError('LDAP connection is not established')
            if self.assessment_scope and not self.assessment_scope.allows_dn(dn):
                raise ScopeLimitError('LDAP object is outside directory scope')
            if self.pre_search_hook:
                self.pre_search_hook()
            self._consume_request()
            search_kwargs = {
                "search_base": dn,
                "search_filter": "(objectClass=*)",
                "search_scope": BASE,
                "attributes": attributes,
            }
            controls = _security_descriptor_controls(attributes)
            if controls:
                search_kwargs["controls"] = controls
            succeeded = self.connection.search(**search_kwargs)
            self._validate_search_result(succeeded)
            return [self._entry_to_dict(entry) for entry in self.connection.entries]
        return self._audited_query(query, dn, '(objectClass=*)', attributes, 0, 'BASE')

    def _consume_request(self):
        if self.assessment_scope:
            self.assessment_scope.consume(self.dc_ip, 'ldaps' if self.use_ssl or self.start_tls else 'ldap')

    def _audited_query(self, query, base, ldap_filter, attributes, limit, scope):
        import hashlib
        started = time.monotonic()
        record = {'base': base, 'query_id': hashlib.sha256(
            repr((base, ldap_filter, attributes, limit, scope)).encode()).hexdigest()[:24],
            'attributes': list(attributes or []), 'scope': scope, 'size_limit': limit}
        self._search_incomplete = False
        try:
            results = query()
            missing = {name: len(results) for name in attributes or []}
            for row in results:
                observed = {str(key).casefold() for key, value in row.items()
                            if value is not None and value != '' and value != [] and value != b''}
                for name in missing:
                    if name.casefold() in observed:
                        missing[name] -= 1
            record.update(
                status='incomplete' if self._search_incomplete else 'completed',
                returned_objects=len(results),
                unobserved_attributes=[name for name, count in missing.items() if count == len(results)],
                unobserved_attribute_counts=missing,
            )
            return results
        except Exception:
            record.update(status='failed', returned_objects=0,
                          unobserved_attributes=list(attributes or []))
            raise
        finally:
            record['duration_ms'] = round((time.monotonic() - started) * 1000, 1)
            result = getattr(self.connection, 'result', None)
            record['result_code'] = result.get('result') if isinstance(result, dict) else None
            self.merge_query_audit([record])

    def merge_query_audit(self, records):
        """Merge worker diagnostics with a bounded record list."""
        lock = self.__dict__.setdefault('_audit_lock', Lock())
        with lock:
            if not hasattr(self, 'query_audit'):
                self.query_audit = []
            self.query_failure_count = getattr(self, 'query_failure_count', 0) + sum(
                record.get('status') == 'failed' for record in records
            )
            remaining = max(0, 10000 - len(self.query_audit))
            self.query_audit.extend(records[:remaining])
            if len(records) > remaining:
                self.query_audit_overflow = True

    def _search_impl(self, search_base: Optional[str] = None,
               search_filter: str = '(objectClass=*)',
               attributes: Optional[list[str]] = None,
               size_limit: int = 0,
               progress_callback: Optional[callable] = None,
               use_cache: bool = True) -> list[dict[str, Any]]:
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
            cached_result = self.query_cache.get_query_result(
                search_filter,
                search_base,
                attributes=attributes,
                size_limit=size_limit,
                page_size=self.page_size,
                enable_paging=self.enable_paging,
            )
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
                    try:
                        results = self._paged_search(
                            search_base=search_base,
                            search_filter=search_filter,
                            attributes=attributes,
                            size_limit=size_limit,
                            progress_callback=progress_callback,
                            timeout=timeout
                        )
                    except LDAPSearchError as exc:
                        # A deadline keeps the pages already read. Protocol failures
                        # still raise so a broken page is not treated as the inventory.
                        if not exc.partial_results:
                            raise
                        self._search_incomplete = True
                        self.last_query_duration = time.time() - start_time
                        logger.warning("%s", exc)
                        return list(exc.partial_results)
                    self.last_query_duration = time.time() - start_time

                    # Cache result if enabled
                    if self.enable_cache and use_cache and self.query_cache:
                        self.query_cache.set_query_result(
                            search_filter,
                            results,
                            search_base,
                            attributes=attributes,
                            size_limit=size_limit,
                            page_size=self.page_size,
                            enable_paging=self.enable_paging,
                        )

                    return results
                else:
                    # Standard search for small result sets
                    if self.pre_search_hook:
                        self.pre_search_hook()
                    self._consume_request()
                    start_time = time.time()
                    search_kwargs = {
                        "search_base": search_base,
                        "search_filter": search_filter,
                        "attributes": attributes,
                        "size_limit": size_limit,
                    }
                    controls = _security_descriptor_controls(attributes)
                    if controls:
                        search_kwargs["controls"] = controls
                    search_succeeded = self.connection.search(**search_kwargs)
                    self._validate_search_result(
                        search_succeeded,
                        allow_size_limit=bool(size_limit),
                    )

                    results: list[dict[str, Any]] = []
                    for entry in self.connection.entries:
                        entry_dict = self._entry_to_dict(entry)
                        results.append(entry_dict)

                    self.last_query_duration = time.time() - start_time

                    # Cache result if enabled
                    if self.enable_cache and use_cache and self.query_cache:
                        self.query_cache.set_query_result(
                            search_filter,
                            results,
                            search_base,
                            attributes=attributes,
                            size_limit=size_limit,
                            page_size=self.page_size,
                            enable_paging=self.enable_paging,
                        )

                    if progress_callback:
                        progress_callback(len(results), len(results))

                    return results

            except ScopeLimitError:
                raise
            except LDAPConnectionError as e:
                # Re-raise connection errors immediately (no retry)
                logger.error(f"LDAP connection error: {str(e)}")
                raise
            except LDAPSearchError as e:
                # Re-raise search errors if not retryable
                error_msg = str(e).lower()
                if not self._is_retryable_error(error_msg) or attempt >= self.max_retries - 1:
                    logger.debug("LDAP search rejected: %s", e)
                    raise
                last_error = e
                wait_time = self.retry_delay * (attempt + 1)
                logger.warning(
                    "LDAP search failed (attempt %d/%d): %s. Retrying in %.1f seconds...",
                    attempt + 1,
                    self.max_retries,
                    e,
                    wait_time,
                )
                time.sleep(wait_time)
                continue
            except LDAPException as e:
                last_error = e
                error_msg = str(e).lower()

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

    def _validate_search_result(self, succeeded: bool, *, allow_size_limit: bool = False) -> None:
        """Raise a descriptive error when ldap3 reports an unsuccessful operation."""
        result = getattr(self.connection, "result", None)
        result = result if isinstance(result, dict) else {}
        result_code = result.get("result")
        try:
            numeric_result_code = int(result_code) if result_code is not None else None
        except (TypeError, ValueError):
            numeric_result_code = None

        # The LDAP result code is authoritative. Some ldap3 strategies return
        # False for an empty successful search while still reporting result=0.
        if numeric_result_code == 0:
            return
        if succeeded and numeric_result_code is None:
            return
        if allow_size_limit and numeric_result_code == 4:
            return

        description = result.get("description") or "unknown LDAP result"
        message = result.get("message") or "the server rejected the search"
        raise LDAPSearchError(
            f"LDAP search failed ({description}, result={result_code!r}): {message}"
        )

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

        # An unlimited inventory read cannot share the short connection timeout.
        # A 30 second cap drops a domain-sized paged result before the last page.
        if size_limit <= 0:
            return max(self.base_timeout, 300)

        # Estimate: ~0.1 seconds per 1000 results, with a five-minute cap.
        estimated_time = (size_limit / 1000) * 0.1
        timeout = max(self.base_timeout, int(estimated_time) + 10)
        return min(timeout, 300)

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
                     attributes: Optional[list[str]], size_limit: int,
                     progress_callback: Optional[callable] = None,
                     timeout: Optional[int] = None) -> list[dict[str, Any]]:
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
        results: list[dict[str, Any]] = []
        seen_entries = set()
        seen_cookies = set()
        processed_entry_count = 0
        cookie = None
        total_count = 0
        start_time = time.monotonic()

        if timeout is None:
            timeout = self._calculate_timeout(size_limit)

        try:
            # Use ldap3's paged search with manual cookie management
            while True:
                if self.pre_search_hook:
                    self.pre_search_hook()
                self._consume_request()
                # Check timeout
                elapsed = time.monotonic() - start_time
                if elapsed > timeout:
                    raise LDAPSearchError(
                        f"LDAP paged search timed out after {elapsed:.1f} seconds; "
                        f"{len(results)} partial entries retained",
                        partial_results=results,
                    )

                # Perform paged search
                search_kwargs = {
                    "search_base": search_base,
                    "search_filter": search_filter,
                    "attributes": attributes,
                    "paged_size": self.page_size,
                    "paged_cookie": cookie,
                }
                controls = _security_descriptor_controls(attributes)
                if controls:
                    search_kwargs["controls"] = controls
                search_succeeded = self.connection.search(**search_kwargs)
                self._validate_search_result(search_succeeded)

                # Process entries in current page
                # ldap3 accumulates entries, so we only process new ones
                page_count = 0
                # Some ldap3 strategies replace entries per page while others
                # expose accumulated entries. Deduplicate by DN to support both.
                all_entries = list(self.connection.entries) if hasattr(self.connection, 'entries') else []
                if len(all_entries) > processed_entry_count:
                    page_entries = all_entries[processed_entry_count:]
                    processed_entry_count = len(all_entries)
                else:
                    page_entries = all_entries
                for entry in page_entries:
                    entry_dict = self._entry_to_dict(entry)
                    entry_identity = entry_dict.get("dn") or repr(entry_dict)
                    if entry_identity in seen_entries:
                        continue
                    seen_entries.add(entry_identity)
                    results.append(entry_dict)
                    page_count += 1
                    total_count += 1

                    # Check size limit
                    if size_limit > 0 and total_count >= size_limit:
                        break

                if time.monotonic() - start_time > timeout:
                    raise LDAPSearchError(
                        f"LDAP paged search timed out; {len(results)} partial entries retained",
                        partial_results=results,
                    )

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
                        logger.debug("No cookie returned and no entries in page - ending search")
                    break

                if isinstance(next_cookie, bytes) and len(next_cookie) == 0:
                    logger.debug(f"Empty cookie returned after {total_count} entries - all results retrieved")
                    break

                if page_count == 0 or next_cookie in seen_cookies:
                    raise LDAPSearchError(
                        "LDAP paging did not advance; partial results discarded"
                    )
                seen_cookies.add(next_cookie)

                # Continue with next page
                cookie = next_cookie
                logger.debug(f"Continuing paged search with cookie (length: {len(cookie) if isinstance(cookie, bytes) else 'N/A'}) - total so far: {total_count}")

            # Update estimated result size for future queries
            if total_count > 0:
                self.estimated_result_size = total_count

            logger.info(f"Paged search completed: {total_count} total entries")
            return results

        except LDAPException as e:
            error_msg = f"LDAP paged search error: {str(e)}"
            raise LDAPSearchError(error_msg) from e

    def _get_paged_cookie(self) -> Optional[bytes]:
        """Prefer the current result's cookie, including its explicit end marker."""
        paged_oid = '1.2.840.113556.1.4.319'
        for container in (getattr(self.connection, 'result', None),
                          getattr(self.connection, 'response', None), self.connection):
            controls = container.get('controls') if isinstance(container, dict) else getattr(container, 'controls', None)
            if isinstance(controls, dict) and paged_oid in controls:
                return self._extract_cookie_from_control(controls[paged_oid])
            if isinstance(controls, list):
                for control in controls:
                    identifier = control.get('controlType') if isinstance(control, dict) else getattr(control, 'controlType', None)
                    if str(identifier) == paged_oid:
                        return self._extract_cookie_from_control(control)
        return None

    def _extract_cookie_from_control(self, control) -> Optional[bytes]:
        """Reject malformed controls instead of accepting an incomplete search."""
        if isinstance(control, dict):
            if 'value' in control:
                value = control['value']
            elif 'cookie' in control:
                value = control
            else:
                value = control.get('controlValue')
        elif hasattr(control, 'cookie'):
            value = control
        else:
            value = getattr(control, 'value', getattr(control, 'controlValue', None))
        cookie = value.get('cookie') if isinstance(value, dict) else getattr(value, 'cookie', value)
        if hasattr(cookie, 'asOctets'):
            cookie = cookie.asOctets()
        if not isinstance(cookie, (bytes, bytearray, memoryview)):
            raise LDAPSearchError('Invalid LDAP paging cookie; partial results discarded')
        return bytes(cookie)

    def _entry_to_dict(self, entry) -> dict[str, Any]:
        """
        Convert LDAP entry to dictionary.

        Args:
            entry: LDAP entry object

        Returns:
            dict: Dictionary representation of entry
        """
        entry_dict: dict[str, Any] = {}
        for attr in entry.entry_attributes:
            values = entry[attr].values
            entry_dict[attr] = values if len(values) > 1 else values[0] if values else None
        entry_dict['dn'] = str(entry.entry_dn)
        return entry_dict

    def disconnect(self) -> None:
        """Close LDAP connection and drop the bind secret from this object."""
        connection = self.connection
        self.password = ''
        if connection is not None:
            try:
                connection.password = None
            except Exception:
                logger.debug('Could not clear the LDAP client password', exc_info=True)
            try:
                connection.unbind()
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
