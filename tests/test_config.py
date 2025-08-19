"""
Tests for configuration management and validation
Testing centralized configuration, validation, and utility functions
"""

import pytest
from dns_mcp_server.config import (
    DNSServerConfig,
    config,
    validate_record_type,
    validate_resolver_type,
    get_performance_rating,
    is_cdn_related,
    RESOLVER_CONFIGS,
    DEFAULT_PROPAGATION_RESOLVERS,
    SUPPORTED_RECORD_TYPES,
    CDN_INDICATORS
)


class TestDNSServerConfig:
    """Test DNS server configuration class"""
    
    def test_default_configuration(self):
        """Test default configuration values"""
        assert config.default_rate_limit == 30
        assert config.default_timeout == 10.0
        assert config.default_max_workers == 10
        assert config.default_wildcard_test_count == 3
        assert config.wildcard_subdomain_length == 32
        assert config.anomaly_threshold_multiplier == 2.0
    
    def test_timeout_validation(self):
        """Test timeout validation and clamping"""
        # Test normal timeout
        assert config.validate_timeout(5.0) == 5.0
        
        # Test too low timeout
        assert config.validate_timeout(0.5) == config.min_timeout
        
        # Test too high timeout
        assert config.validate_timeout(100.0) == config.max_timeout
    
    def test_max_workers_validation(self):
        """Test max workers validation and clamping"""
        # Test normal workers
        assert config.validate_max_workers(5) == 5
        
        # Test too low workers
        assert config.validate_max_workers(0) == 1
        
        # Test too high workers
        assert config.validate_max_workers(100) == config.max_concurrent_workers
    
    def test_wildcard_count_validation(self):
        """Test wildcard test count validation"""
        # Test normal count
        assert config.validate_wildcard_count(5) == 5
        
        # Test too low count
        assert config.validate_wildcard_count(0) == 1
        
        # Test too high count
        assert config.validate_wildcard_count(20) == config.max_wildcard_test_count
    
    def test_performance_thresholds(self):
        """Test performance threshold configuration"""
        thresholds = config.performance_thresholds
        assert "excellent" in thresholds
        assert "good" in thresholds
        assert "moderate" in thresholds
        assert "poor" in thresholds
        
        # Thresholds should be in ascending order
        assert thresholds["excellent"] < thresholds["good"]
        assert thresholds["good"] < thresholds["moderate"]
        assert thresholds["moderate"] < thresholds["poor"]


class TestValidationFunctions:
    """Test configuration validation functions"""
    
    def test_validate_record_type_valid(self):
        """Test validation with valid record types"""
        for record_type in SUPPORTED_RECORD_TYPES:
            assert validate_record_type(record_type) == record_type
            assert validate_record_type(record_type.lower()) == record_type
    
    def test_validate_record_type_invalid(self):
        """Test validation with invalid record types"""
        with pytest.raises(ValueError) as exc_info:
            validate_record_type("INVALID")
        assert "Unsupported record type" in str(exc_info.value)
        assert "INVALID" in str(exc_info.value)
    
    def test_validate_resolver_type_valid(self):
        """Test validation with valid resolver types"""
        for resolver_type in RESOLVER_CONFIGS.keys():
            assert validate_resolver_type(resolver_type) == resolver_type
        
        # Test system resolver
        assert validate_resolver_type("system") == "system"
    
    def test_validate_resolver_type_invalid(self):
        """Test validation with invalid resolver types"""
        with pytest.raises(ValueError) as exc_info:
            validate_resolver_type("invalid_resolver")
        assert "Unsupported resolver type" in str(exc_info.value)
    
    def test_get_performance_rating(self):
        """Test performance rating classification"""
        # Test each rating level
        assert get_performance_rating(0.05) == "EXCELLENT"
        assert get_performance_rating(0.2) == "GOOD"
        assert get_performance_rating(0.4) == "MODERATE"
        assert get_performance_rating(0.8) == "POOR"
        assert get_performance_rating(2.0) == "VERY_POOR"
        
        # Test edge cases
        assert get_performance_rating(0.1) == "GOOD"  # Boundary case
        assert get_performance_rating(1.0) == "VERY_POOR"  # Boundary case
    
    def test_is_cdn_related(self):
        """Test CDN/hosting detection"""
        # Test CDN-related records
        cdn_records = [
            "cloudflare.com",
            "amazonaws.com", 
            "d123.cloudfront.net",
            "fastly.map.fastly.net",
            "cdn.example.com"
        ]
        
        for record in cdn_records:
            assert is_cdn_related(record) is True
        
        # Test non-CDN records
        non_cdn_records = [
            "example.com",
            "192.168.1.1",
            "mail.company.com"
        ]
        
        for record in non_cdn_records:
            assert is_cdn_related(record) is False


class TestResolverConfigurations:
    """Test resolver configuration data"""
    
    def test_resolver_configs_structure(self):
        """Test resolver configurations structure"""
        for resolver_name, nameservers in RESOLVER_CONFIGS.items():
            assert isinstance(nameservers, list)
            assert len(nameservers) > 0
            
            # All nameservers should be strings (IP addresses)
            for ns in nameservers:
                assert isinstance(ns, str)
                assert len(ns) > 0
    
    def test_propagation_resolvers_structure(self):
        """Test propagation resolver configurations"""
        assert len(DEFAULT_PROPAGATION_RESOLVERS) >= 5  # Should have good coverage
        
        for resolver_name, ip in DEFAULT_PROPAGATION_RESOLVERS.items():
            assert isinstance(resolver_name, str)
            assert isinstance(ip, str)
            assert len(ip) > 0
    
    def test_major_dns_providers_included(self):
        """Test that major DNS providers are included"""
        expected_providers = ["google", "cloudflare", "quad9", "opendns"]
        
        for provider in expected_providers:
            assert provider in RESOLVER_CONFIGS
            assert provider in DEFAULT_PROPAGATION_RESOLVERS


class TestSupportedRecordTypes:
    """Test supported DNS record types"""
    
    def test_record_types_completeness(self):
        """Test that all common record types are supported"""
        common_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]
        
        for record_type in common_types:
            assert record_type in SUPPORTED_RECORD_TYPES
    
    def test_record_types_are_uppercase(self):
        """Test that all record types are uppercase"""
        for record_type in SUPPORTED_RECORD_TYPES:
            assert record_type == record_type.upper()


class TestCDNIndicators:
    """Test CDN indicator configurations"""
    
    def test_cdn_indicators_coverage(self):
        """Test CDN indicators include major providers"""
        major_cdns = ["cloudflare", "amazonaws", "cloudfront", "fastly"]
        
        for cdn in major_cdns:
            assert cdn in CDN_INDICATORS
    
    def test_cdn_indicators_lowercase(self):
        """Test that CDN indicators are lowercase for case-insensitive matching"""
        for indicator in CDN_INDICATORS:
            assert indicator == indicator.lower()


class TestConfigurationValidation:
    """Test configuration validation on module import"""
    
    def test_config_validation_success(self):
        """Test that current configuration passes validation"""
        # If we get here, the module imported successfully
        # which means _validate_config() passed
        assert config.default_rate_limit > 0
        assert config.default_timeout > 0
        assert config.default_max_workers > 0
        assert 0 < config.high_failure_rate_threshold < 1
    
    def test_invalid_config_creation(self):
        """Test that invalid configuration would be caught"""
        # Test with invalid rate limit
        invalid_config = DNSServerConfig(default_rate_limit=0)
        
        # This should work for creation, but would fail validation
        assert invalid_config.default_rate_limit == 0


class TestEdgeCases:
    """Test edge cases and boundary conditions"""
    
    def test_zero_timeout_validation(self):
        """Test zero timeout handling"""
        assert config.validate_timeout(0) == config.min_timeout
    
    def test_negative_timeout_validation(self):
        """Test negative timeout handling"""
        assert config.validate_timeout(-1.0) == config.min_timeout
    
    def test_negative_workers_validation(self):
        """Test negative workers handling"""
        assert config.validate_max_workers(-5) == 1
    
    def test_empty_string_cdn_check(self):
        """Test CDN check with empty string"""
        assert is_cdn_related("") is False
    
    def test_none_cdn_check(self):
        """Test CDN check with None"""
        # Should handle None gracefully
        assert is_cdn_related(None) is False
    
    def test_numeric_cdn_check(self):
        """Test CDN check with numeric input"""
        assert is_cdn_related(12345) is False


class TestConfigurationIntegration:
    """Test configuration integration with other modules"""
    
    def test_config_import_in_modules(self):
        """Test that configuration can be imported by other modules"""
        from dns_mcp_server.resolvers import RESOLVER_CONFIGS as resolver_configs
        from dns_mcp_server.osint_tools import DEFAULT_PROPAGATION_RESOLVERS as osint_resolvers
        
        # These should be the same as our centralized config
        assert resolver_configs == RESOLVER_CONFIGS
        assert osint_resolvers == DEFAULT_PROPAGATION_RESOLVERS
    
    def test_config_consistency(self):
        """Test that configuration values are consistent across modules"""
        # All resolvers used in propagation should exist in main config
        for resolver_name in DEFAULT_PROPAGATION_RESOLVERS.keys():
            if resolver_name not in ["level3", "verisign"]:  # These are propagation-only
                assert resolver_name in RESOLVER_CONFIGS


# Test configuration
pytestmark = pytest.mark.asyncio
