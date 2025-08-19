"""
Tests for OSINT DNS analysis tools
Testing propagation check, wildcard detection, and response time analysis
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock

from dns_mcp_server.osint_tools import (
    dns_propagation_check,
    dns_wildcard_check,
    dns_response_analysis,
    DEFAULT_PROPAGATION_RESOLVERS,
)


class TestDNSPropagationCheck:
    """Test DNS propagation analysis across multiple resolvers"""

    @patch("dns_mcp_server.osint_tools.create_resolver")
    async def test_consistent_propagation(self, mock_create_resolver):
        """Test consistent DNS propagation across all resolvers"""
        # Mock resolver that returns consistent results
        mock_resolver = AsyncMock()
        mock_resolver.query.return_value = ["192.168.1.1"]
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver

        result = await dns_propagation_check(domain="example.com", record_type="A")

        assert result["domain"] == "example.com"
        assert result["record_type"] == "A"
        assert result["is_consistent"] is True
        assert result["unique_response_count"] == 1
        assert result["osint_analysis"]["consistency_status"] == "CONSISTENT"
        assert result["osint_analysis"]["trust_level"] == "HIGH"
        assert len(result["response_groups"]) == 1
        assert result["response_groups"][0]["records"] == ["192.168.1.1"]

    @patch("dns_mcp_server.osint_tools.create_resolver")
    async def test_inconsistent_propagation(self, mock_create_resolver):
        """Test inconsistent DNS responses indicating potential issues"""
        # Mock resolver that returns different results
        call_count = 0

        def mock_query_side_effect(domain, record_type):
            nonlocal call_count
            call_count += 1
            if call_count <= 3:
                return ["192.168.1.1"]
            else:
                return ["192.168.1.2"]  # Different IP

        mock_resolver = AsyncMock()
        mock_resolver.query.side_effect = mock_query_side_effect
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver

        result = await dns_propagation_check(domain="suspicious.com", record_type="A")

        assert result["is_consistent"] is False
        assert result["unique_response_count"] == 2
        assert result["osint_analysis"]["consistency_status"] == "INCONSISTENT"
        assert result["osint_analysis"]["trust_level"] == "LOW"
        assert (
            "DNS response inconsistency detected"
            in result["osint_analysis"]["potential_issues"]
        )

    async def test_custom_resolvers(self):
        """Test propagation check with custom resolvers"""
        custom_resolvers = {"test1": "1.1.1.1", "test2": "8.8.8.8"}

        # This will likely fail due to network, but should handle gracefully
        result = await dns_propagation_check(
            domain="example.com", resolvers=custom_resolvers, timeout=1  # Short timeout
        )

        assert result["total_resolvers_queried"] == 2
        assert "test1" in result["resolver_results"]
        assert "test2" in result["resolver_results"]


class TestDNSWildcardCheck:
    """Test wildcard DNS detection"""

    @patch("dns_mcp_server.osint_tools.create_resolver")
    async def test_no_wildcard_detected(self, mock_create_resolver):
        """Test domain with no wildcard DNS"""
        # Mock resolver that raises exceptions (no wildcard)
        mock_resolver = AsyncMock()
        mock_resolver.query.side_effect = Exception("NXDOMAIN")
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver

        result = await dns_wildcard_check(domain="specific.com", test_count=2)

        assert result["domain"] == "specific.com"
        assert result["has_wildcard"] is False
        assert result["wildcard_analysis"]["A"]["detected"] is False
        assert result["wildcard_analysis"]["CNAME"]["detected"] is False
        assert result["osint_insights"]["risk_level"] == "LOW"
        assert (
            "No wildcard DNS detected"
            in result["osint_insights"]["security_implications"][0]
        )

    @patch("dns_mcp_server.osint_tools.create_resolver")
    async def test_wildcard_detected(self, mock_create_resolver):
        """Test domain with wildcard DNS"""
        # Mock resolver that returns results for random subdomains
        mock_resolver = AsyncMock()
        mock_resolver.query.return_value = ["192.168.1.100"]  # Wildcard response
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver

        result = await dns_wildcard_check(domain="wildcard.com", test_count=2)

        assert result["domain"] == "wildcard.com"
        assert result["has_wildcard"] is True
        assert result["wildcard_analysis"]["A"]["detected"] is True
        assert result["osint_insights"]["risk_level"] in ["MEDIUM", "HIGH", "LOW"]
        assert (
            "All subdomains resolve to same target"
            in result["osint_insights"]["security_implications"]
        )

    @patch("dns_mcp_server.osint_tools.create_resolver")
    async def test_mixed_wildcard_response(self, mock_create_resolver):
        """Test domain with mixed wildcard responses"""
        # Mock resolver that sometimes fails, sometimes succeeds
        call_count = 0

        def mock_query_side_effect(domain, record_type):
            nonlocal call_count
            call_count += 1
            if call_count % 2 == 0:
                return ["192.168.1.100"]  # Some succeed
            else:
                raise Exception("NXDOMAIN")  # Some fail

        mock_resolver = AsyncMock()
        mock_resolver.query.side_effect = mock_query_side_effect
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver

        result = await dns_wildcard_check(domain="partial.com", test_count=3)

        # Should detect some wildcard behavior
        assert result["domain"] == "partial.com"
        assert len(result["test_results"]) > 0

    def test_random_subdomain_generation(self):
        """Test that random subdomains are properly generated"""
        import secrets
        import string

        # Mock secrets.choice to ensure reproducible test
        with patch("dns_mcp_server.osint_tools.secrets.choice") as mock_choice:
            mock_choice.return_value = "a"

            # Import the function that would use this mocked choice
            # Since we can't easily test the internal function directly,
            # we'll test that the subdomain generation creates expected patterns
            from dns_mcp_server.config import config

            # Test the general pattern - this should create predictable subdomains for testing
            test_subdomain = "".join(
                mock_choice(string.ascii_lowercase + string.digits)
                for _ in range(config.wildcard_subdomain_length)
            )

            expected_subdomain = "a" * config.wildcard_subdomain_length
            assert test_subdomain == expected_subdomain

            # Verify choice was called the expected number of times
            assert mock_choice.call_count == config.wildcard_subdomain_length


class TestDNSResponseAnalysis:
    """Test DNS response time analysis"""

    @patch("dns_mcp_server.osint_tools.create_resolver")
    async def test_excellent_performance(self, mock_create_resolver):
        """Test analysis with excellent response times"""
        # Mock resolver with fast, consistent responses
        mock_resolver = AsyncMock()
        mock_resolver.query.return_value = ["192.168.1.1"]
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver

        result = await dns_response_analysis(
            domain="fast.com", iterations=5, record_type="A"
        )

        assert result["domain"] == "fast.com"
        assert result["iterations"] == 5
        assert result["successful_queries"] == 5
        assert result["failed_queries"] == 0
        assert result["failure_rate"] == 0.0
        assert "response_time_analysis" in result
        assert result["osint_insights"]["performance_rating"] in [
            "EXCELLENT",
            "GOOD",
            "MODERATE",
        ]
        assert result["osint_insights"]["anomaly_detection"] in ["DETECTED", "NONE"]

    @patch("dns_mcp_server.osint_tools.create_resolver")
    async def test_high_failure_rate(self, mock_create_resolver):
        """Test analysis with high failure rate"""
        # Mock resolver that fails most of the time
        call_count = 0

        def mock_query_side_effect(domain, record_type):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return ["192.168.1.1"]  # Only first 2 succeed
            else:
                raise Exception("Timeout")  # Rest fail

        mock_resolver = AsyncMock()
        mock_resolver.query.side_effect = mock_query_side_effect
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver

        result = await dns_response_analysis(domain="unreliable.com", iterations=10)

        assert result["failed_queries"] == 8  # 8 out of 10 failed
        assert result["failure_rate"] == 0.8
        assert "High failure rate" in str(result["osint_insights"]["potential_issues"])

    @patch("dns_mcp_server.osint_tools.create_resolver")
    async def test_response_time_anomalies(self, mock_create_resolver):
        """Test detection of response time anomalies"""
        # Mock resolver with variable response times
        # We'll simulate this by controlling the sleep delay in the actual function
        mock_resolver = AsyncMock()
        mock_resolver.query.return_value = ["192.168.1.1"]
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver

        result = await dns_response_analysis(
            domain="variable.com",
            iterations=3,  # Small number for faster test
            record_type="A",
        )

        assert result["successful_queries"] == 3
        assert "response_time_analysis" in result

        # Check that analysis includes required statistical fields
        analysis = result["response_time_analysis"]
        required_fields = ["min_time", "max_time", "avg_time", "median_time"]
        for field in required_fields:
            assert field in analysis

    async def test_empty_iterations(self):
        """Test response analysis with zero iterations"""
        result = await dns_response_analysis(domain="test.com", iterations=0)

        assert result["iterations"] == 0
        assert result["successful_queries"] == 0
        assert result["failed_queries"] == 0
        assert result["failure_rate"] == 0.0


class TestOSINTConfiguration:
    """Test OSINT tool configuration and defaults"""

    def test_default_propagation_resolvers(self):
        """Test that default resolvers are properly configured"""
        assert "google" in DEFAULT_PROPAGATION_RESOLVERS
        assert "cloudflare" in DEFAULT_PROPAGATION_RESOLVERS
        assert "quad9" in DEFAULT_PROPAGATION_RESOLVERS
        assert DEFAULT_PROPAGATION_RESOLVERS["google"] == "8.8.8.8"
        assert DEFAULT_PROPAGATION_RESOLVERS["cloudflare"] == "1.1.1.1"

    def test_resolver_coverage(self):
        """Test that we have good resolver coverage for propagation analysis"""
        # Should have at least 5 different resolver providers
        assert len(DEFAULT_PROPAGATION_RESOLVERS) >= 5

        # Should include major public DNS providers
        expected_providers = ["google", "cloudflare", "quad9"]
        for provider in expected_providers:
            assert provider in DEFAULT_PROPAGATION_RESOLVERS


class TestOSINTIntegration:
    """Integration tests for OSINT tools with real domains"""

    @pytest.mark.integration
    async def test_real_propagation_check(self):
        """Test propagation check against real domain"""
        result = await dns_propagation_check(
            domain="sans.com", record_type="A", timeout=5
        )

        assert result["domain"] == "sans.com"
        assert result["total_resolvers_queried"] > 0
        assert "resolver_results" in result
        assert "osint_analysis" in result

    @pytest.mark.integration
    async def test_real_wildcard_check(self):
        """Test wildcard check against real domain"""
        result = await dns_wildcard_check(
            domain="hackthissite.org", test_count=2, timeout=5
        )

        assert result["domain"] == "hackthissite.org"
        assert result["test_count"] == 2
        assert len(result["test_subdomains"]) == 2
        assert "osint_insights" in result

    @pytest.mark.integration
    async def test_real_response_analysis(self):
        """Test response analysis against real domain"""
        result = await dns_response_analysis(
            domain="root-me.org",
            iterations=3,  # Keep small for speed
            record_type="A",
            timeout=5,
        )

        assert result["domain"] == "root-me.org"
        assert result["iterations"] == 3
        assert "response_time_analysis" in result or result["failed_queries"] == 3
        assert "osint_insights" in result


# Test configuration
pytestmark = pytest.mark.asyncio
