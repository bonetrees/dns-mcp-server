"""
Configuration management for DNS OSINT MCP Server
Centralized settings for rate limiting, timeouts, resolvers, and default values
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class DNSServerConfig:
    """
    Main configuration class for DNS OSINT MCP Server
    Provides centralized management of all server settings
    """
    
    # Rate Limiting Configuration
    default_rate_limit: int = 30  # requests per second per resolver
    
    # Timeout Configuration
    default_timeout: float = 10.0  # seconds
    max_timeout: float = 60.0  # maximum allowed timeout
    min_timeout: float = 1.0   # minimum allowed timeout
    
    # Concurrency Configuration
    default_max_workers: int = 10
    max_concurrent_workers: int = 50  # safety limit
    dns_query_all_concurrency: int = 3  # concurrent queries to same resolver in query_all
    
    # Bulk Query Configuration
    default_bulk_delay: float = 0.1  # delay between queries in response analysis
    
    # OSINT Tool Configuration
    default_propagation_iterations: int = 10
    default_wildcard_test_count: int = 3
    max_wildcard_test_count: int = 10  # safety limit
    wildcard_subdomain_length: int = 32  # length of random subdomains
    
    # Response Analysis Configuration
    anomaly_threshold_multiplier: float = 2.0  # standard deviations for anomaly detection
    performance_thresholds: Dict[str, float] = field(default_factory=lambda: {
        "excellent": 0.1,
        "good": 0.3,
        "moderate": 0.5,
        "poor": 1.0
    })
    
    # Error Analysis Configuration
    high_failure_rate_threshold: float = 0.3  # 30% failure rate triggers warnings
    high_variance_threshold: float = 0.5  # response time variance threshold
    
    def validate_timeout(self, timeout: float) -> float:
        """Validate and clamp timeout to acceptable range"""
        return max(self.min_timeout, min(timeout, self.max_timeout))
    
    def validate_max_workers(self, workers: int) -> int:
        """Validate and clamp max workers to acceptable range"""
        return max(1, min(workers, self.max_concurrent_workers))
    
    def validate_wildcard_count(self, count: int) -> int:
        """Validate and clamp wildcard test count"""
        return max(1, min(count, self.max_wildcard_test_count))


# Resolver Configurations
RESOLVER_CONFIGS = {
    "public": ["8.8.8.8", "1.1.1.1", "9.9.9.9"],
    "google": ["8.8.8.8", "8.8.4.4"],
    "cloudflare": ["1.1.1.1", "1.0.0.1"],
    "quad9": ["9.9.9.9", "149.112.112.112"],
    "opendns": ["208.67.222.222", "208.67.220.220"]
}

# OSINT Propagation Resolvers
DEFAULT_PROPAGATION_RESOLVERS = {
    "google": "8.8.8.8",
    "cloudflare": "1.1.1.1", 
    "quad9": "9.9.9.9",
    "opendns": "208.67.222.222",
    "level3": "4.2.2.1",
    "verisign": "64.6.64.6"
}

# Supported DNS Record Types
SUPPORTED_RECORD_TYPES = [
    "A", "AAAA", "MX", "TXT", "NS", "SOA", 
    "CNAME", "CAA", "SRV", "PTR"
]

# CDN and Hosting Indicators for Wildcard Analysis
CDN_INDICATORS = [
    "cloudflare", "amazonaws", "cloudfront", "fastly", 
    "cdn", "akamai", "edgecast", "maxcdn", "keycdn"
]

# Global configuration instance
config = DNSServerConfig()


def validate_record_type(record_type: str) -> str:
    """
    Validate DNS record type
    
    Args:
        record_type: DNS record type to validate
        
    Returns:
        Validated record type in uppercase
        
    Raises:
        ValueError: If record type is not supported
    """
    record_type = record_type.upper()
    if record_type not in SUPPORTED_RECORD_TYPES:
        raise ValueError(
            f"Unsupported record type: {record_type}. "
            f"Supported types: {', '.join(SUPPORTED_RECORD_TYPES)}"
        )
    return record_type


def validate_resolver_type(resolver_type: str) -> str:
    """
    Validate resolver type
    
    Args:
        resolver_type: Resolver type to validate
        
    Returns:
        Validated resolver type
        
    Raises:
        ValueError: If resolver type is not supported
    """
    if resolver_type not in RESOLVER_CONFIGS and resolver_type != "system":
        raise ValueError(
            f"Unsupported resolver type: {resolver_type}. "
            f"Supported types: {', '.join(list(RESOLVER_CONFIGS.keys()) + ['system'])}"
        )
    return resolver_type


def get_performance_rating(avg_time: float) -> str:
    """
    Get performance rating based on average response time
    
    Args:
        avg_time: Average response time in seconds
        
    Returns:
        Performance rating string
    """
    thresholds = config.performance_thresholds
    
    if avg_time < thresholds["excellent"]:
        return "EXCELLENT"
    elif avg_time < thresholds["good"]:
        return "GOOD"
    elif avg_time < thresholds["moderate"]:
        return "MODERATE"
    elif avg_time < thresholds["poor"]:
        return "POOR"
    else:
        return "VERY_POOR"


def is_cdn_related(record: str) -> bool:
    """
    Check if a DNS record appears to be CDN/hosting related
    
    Args:
        record: DNS record string to check
        
    Returns:
        True if record appears to be CDN/hosting related
    """
    if record is None:
        return False
    
    record_lower = str(record).lower()
    return any(indicator in record_lower for indicator in CDN_INDICATORS)


# Configuration validation on import
def _validate_config():
    """Validate configuration on module import"""
    assert config.default_rate_limit > 0, "Rate limit must be positive"
    assert config.default_timeout > 0, "Timeout must be positive"
    assert config.default_max_workers > 0, "Max workers must be positive"
    assert 0 < config.high_failure_rate_threshold < 1, "Failure rate threshold must be between 0 and 1"
    
    # Validate resolver configurations
    for resolver_name, nameservers in RESOLVER_CONFIGS.items():
        assert isinstance(nameservers, list), f"Resolver {resolver_name} must have list of nameservers"
        assert len(nameservers) > 0, f"Resolver {resolver_name} must have at least one nameserver"


# Run validation on import
_validate_config()
