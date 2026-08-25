"""
Configuration Management Module
Centralized configuration for the application
"""

from dataclasses import dataclass
from typing import Optional
import logging
import math
import os

logger = logging.getLogger(__name__)


@dataclass
class LDAPConfig:
    """LDAP connection configuration."""
    default_timeout: int = 30
    max_retries: int = 3
    page_size: int = 5000  # Increased from 1000 to allow larger page sizes
    retry_delay: float = 2.0
    adaptive_timeout: bool = True
    enable_paging: bool = True


@dataclass
class RiskScoringConfig:
    """Risk scoring configuration."""
    base_scores: dict[str, int] = None

    def __post_init__(self):
        if self.base_scores is None:
            self.base_scores = {
                'user_password_never_expires': 30,
                'password_not_required': 95,
                'kerberos_preauth_disabled': 85,
                'user_with_spn': 40,
                'admin_count_set': 60,
                'inactive_privileged_account': 50,
                'disabled_domain_admin': 80,
                'disabled_enterprise_admin': 85,
                'unconstrained_delegation': 90,
                'unconstrained_delegation_user': 90,
                'constrained_delegation': 45,
                'computer_unconstrained_delegation': 90,
                'computer_broad_constrained_delegation': 55,
                'eol_operating_system': 70,
                'too_many_domain_admins': 75,
                'nested_admin_group': 65,
                'operators_group_members': 60,
                'duplicate_spn': 50,
                'privilege_escalation_path': 55,
                'delegation_privilege_escalation': 95,
                'spn_privilege_escalation': 70,
                'computer_delegation_privilege_path': 95,
                'acl_generic_all': 80,
                'acl_write_dacl': 85,
                'acl_write_owner': 85,
                'acl_generic_write': 60
            }


@dataclass
class StealthConfig:
    """Stealth mode configuration."""
    enabled: bool = False
    rate_limit: float = 0.5
    random_delay_min: float = 0.0
    random_delay_max: float = 0.0
    min_logging: bool = False


@dataclass
class AnalysisConfig:
    """Analysis configuration."""
    inactive_account_threshold_days: int = 90
    recently_created_threshold_days: int = 30
    recently_modified_threshold_days: int = 30
    eol_check_enabled: bool = True
    vulnerability_scanning_enabled: bool = True


@dataclass
class AppConfig:
    """Main application configuration."""
    ldap: LDAPConfig = None
    risk_scoring: RiskScoringConfig = None
    stealth: StealthConfig = None
    analysis: AnalysisConfig = None

    def __post_init__(self):
        if self.ldap is None:
            self.ldap = LDAPConfig()
        if self.risk_scoring is None:
            self.risk_scoring = RiskScoringConfig()
        if self.stealth is None:
            self.stealth = StealthConfig()
        if self.analysis is None:
            self.analysis = AnalysisConfig()

    @staticmethod
    def _env_int(name: str, current: int, minimum: int, maximum: int) -> int:
        """Parse a bounded integer environment variable, keeping the current value on error."""
        raw = os.getenv(name)
        if raw is None or raw == "":
            return current
        try:
            value = int(raw)
        except ValueError:
            logger.warning("Invalid %s value: %r, using default", name, raw)
            return current
        if value < minimum or value > maximum:
            logger.warning(
                "Invalid %s value: %r, expected %d-%d, using default",
                name, raw, minimum, maximum,
            )
            return current
        return value

    @staticmethod
    def _env_float(name: str, current: float, minimum: float) -> float:
        """Parse a finite, non-negative float environment variable."""
        raw = os.getenv(name)
        if raw is None or raw == "":
            return current
        try:
            value = float(raw)
        except ValueError:
            logger.warning("Invalid %s value: %r, using default", name, raw)
            return current
        if not math.isfinite(value) or value < minimum:
            logger.warning("Invalid %s value: %r, using default", name, raw)
            return current
        return value

    @classmethod
    def from_env(cls) -> 'AppConfig':
        """Load configuration from environment variables."""
        config = cls()

        config.ldap.default_timeout = cls._env_int(
            "LDAP_TIMEOUT", config.ldap.default_timeout, 1, 300
        )
        config.ldap.max_retries = cls._env_int(
            "LDAP_MAX_RETRIES", config.ldap.max_retries, 1, 20
        )
        config.ldap.page_size = cls._env_int(
            "LDAP_PAGE_SIZE", config.ldap.page_size, 1, 5000
        )

        if os.getenv('STEALTH_ENABLED'):
            config.stealth.enabled = os.getenv('STEALTH_ENABLED').lower() == 'true'
        config.stealth.rate_limit = cls._env_float(
            "RATE_LIMIT", config.stealth.rate_limit, 0.0
        )

        return config

    @classmethod
    def default(cls) -> 'AppConfig':
        """Get default configuration."""
        return cls()


# Global configuration instance
_config: Optional[AppConfig] = None


def get_config() -> AppConfig:
    """Get global configuration instance."""
    global _config
    if _config is None:
        _config = AppConfig.from_env()
    return _config


def set_config(config: AppConfig) -> None:
    """Set global configuration instance."""
    global _config
    _config = config
