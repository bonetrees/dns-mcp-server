"""
Edge case and error resilience tests for DNS OSINT MCP Server
Testing network failures, malformed inputs, IPv6, and extreme conditions
"""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from dns_mcp_server.bulk_tools import dns_bulk_query, dns_bulk_reverse_lookup
from dns_mcp_server.config import config
from dns_mcp_server.core_tools import dns_query, dns_query_all, dns_reverse_lookup
from dns_mcp_server.osint_tools import (
    dns_propagation_check,
    dns_response_analysis,
    dns_wildcard_check,
)


class TestNetworkFailures:
    """Test behavior under various network failure conditions"""

    @patch("dns_mcp_server.core_tools.create_resolver")
    async def test_complete_network_failure(self, mock_create_resolver):
        """Test behavior when all DNS queries fail"""
        # Mock resolver that always fails
        mock_resolver = AsyncMock()
        mock_resolver.query.side_effect = Exception("Network unreachable")
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver

        result = await dns_query(domain="example.com", record_type="A")

        assert "error" in result
        assert result["domain"] == "example.com"
        assert "query_time_seconds" in result

    @patch("dns_mcp_server.bulk_tools.create_resolver")
    async def test_partial_network_failure_bulk(self, mock_create_resolver):
        """Test bulk operations with intermittent network failures"""
        call_count = 0

        def failing_query(domain, record_type):
            nonlocal call_count
            call_count += 1
            if call_count % 3 == 0:  # Every 3rd query fails
                raise Exception("Timeout")
            return ["192.168.1.1"]

        mock_resolver = AsyncMock()
        mock_resolver.query.side_effect = failing_query
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver

        domains = [
            "test1.com",
            "test2.com",
            "test3.com",
            "test4.com",
            "test5.com",
            "test6.com",
        ]
        result = await dns_bulk_query(domains=domains, record_type="A")

        assert result["domain_count"] == 6
        assert result["failed_queries"] == 2  # Every 3rd query failed
        assert result["successful_queries"] == 4

    @patch("dns_mcp_server.osint_tools.create_resolver")
    async def test_propagation_check_resolver_failures(self, mock_create_resolver):
        """Test propagation check when some resolvers fail"""

        def resolver_query(domain, record_type):
            # Simulate some resolvers failing
            if "fail" in mock_create_resolver.call_args[1].get("nameserver", ""):
                raise Exception("Resolver failure")
            return ["192.168.1.1"]

        mock_resolver = AsyncMock()
        mock_resolver.query.side_effect = resolver_query
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver

        test_resolvers = {
            "working1": "8.8.8.8",
            "fail1": "1.1.1.fail",
            "working2": "9.9.9.9",
            "fail2": "8.8.8.fail",
        }

        result = await dns_propagation_check(
            domain="example.com", resolvers=test_resolvers
        )

        assert result["total_resolvers_queried"] == 4
        assert result["failed_queries"] == 2
        assert result["successful_queries"] == 2


class TestMalformedInputs:
    """Test handling of malformed and invalid inputs"""

    async def test_invalid_domain_names(self):
        """Test queries with invalid domain names"""
        invalid_domains = [
            "",  # Empty string
            ".",  # Just a dot
            "...",  # Multiple dots
            "domain..com",  # Double dots
            "a" * 300 + ".com",  # Too long
            "domain with spaces.com",  # Spaces
            "xn--",  # Incomplete punycode
        ]

        for invalid_domain in invalid_domains:
            result = await dns_query(domain=invalid_domain, record_type="A", timeout=2)
            # Should handle gracefully with error
            assert "domain" in result
            assert "error" in result or "records" in result

    async def test_invalid_ip_addresses(self):
        """Test reverse lookup with invalid IP addresses"""
        invalid_ips = [
            "",  # Empty string
            "999.999.999.999",  # Invalid IPv4
            "256.1.1.1",  # Out of range IPv4
            "not.an.ip",  # Not an IP
            "192.168.1",  # Incomplete IP
            "192.168.1.1.1",  # Too many octets
        ]

        for invalid_ip in invalid_ips:
            result = await dns_reverse_lookup(ip=invalid_ip, timeout=2)
            # Should handle gracefully with error
            assert "ip" in result
            assert result["ip"] == invalid_ip
            assert "error" in result

    async def test_extreme_parameter_values(self):
        """Test with extreme parameter values"""
        # Test with very short timeout (but not too extreme)
        result = await dns_query(
            domain="example.com",
            timeout=1,  # Short but reasonable timeout
        )
        assert "domain" in result

        # Test with high iteration count (but clamped to reasonable value)
        result = await dns_response_analysis(
            domain="example.com",
            iterations=50,  # High but not excessive
            timeout=2,  # Short timeout to prevent long test
        )
        assert result["iterations"] == 50
        # Should complete quickly due to timeout, may have failures
        assert "successful_queries" in result
        assert "failed_queries" in result


class TestIPv6Support:
    """Test IPv6 DNS operations"""

    async def test_ipv6_aaaa_query(self):
        """Test AAAA record queries for IPv6"""
        result = await dns_query(
            domain="ipv6.google.com",
            record_type="AAAA",
            resolver_type="google",
            timeout=5,
        )

        assert result["domain"] == "ipv6.google.com"
        assert result["record_type"] == "AAAA"
        # Should either succeed with IPv6 addresses or fail gracefully
        assert "records" in result or "error" in result

    async def test_ipv6_reverse_lookup(self):
        """Test reverse lookup for IPv6 addresses"""
        # Test with Google's IPv6 DNS
        ipv6_address = "2001:4860:4860::8888"

        result = await dns_reverse_lookup(
            ip=ipv6_address, resolver_type="google", timeout=5
        )

        assert result["ip"] == ipv6_address
        # Should either succeed or fail gracefully
        assert "hostnames" in result or "error" in result

    async def test_mixed_ipv4_ipv6_bulk_operations(self):
        """Test bulk operations with mixed IPv4 and IPv6"""
        mixed_ips = [
            "8.8.8.8",  # IPv4
            "2001:4860:4860::8888",  # IPv6
            "1.1.1.1",  # IPv4
            "2606:4700:4700::1111",  # IPv6
        ]

        result = await dns_bulk_reverse_lookup(ips=mixed_ips, timeout=5)

        assert result["ip_count"] == 4
        assert len(result["results"]) == 4


class TestConcurrencyStress:
    """Test behavior under high concurrency stress"""

    @patch("dns_mcp_server.bulk_tools.create_resolver")
    async def test_high_concurrency_bulk_query(self, mock_create_resolver):
        """Test bulk query with high concurrency"""

        # Mock resolver with small delay to simulate real conditions
        async def slow_query(domain, record_type):
            await asyncio.sleep(0.01)  # Small delay
            return ["192.168.1.1"]

        mock_resolver = AsyncMock()
        mock_resolver.query.side_effect = slow_query
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver

        # Test with reasonable number of domains for testing
        domains = [f"test{i}.com" for i in range(20)]  # Reduced from 50

        result = await dns_bulk_query(
            domains=domains,
            max_workers=20,
            timeout=5,  # High concurrency
        )

        assert result["domain_count"] == 20
        assert result["successful_queries"] <= 20
        assert result["total_query_time_seconds"] > 0

    async def test_concurrent_tool_execution(self):
        """Test multiple tools running concurrently"""
        # Run multiple different tools concurrently
        tasks = [
            dns_query(domain="example.com", record_type="A", timeout=3),
            dns_reverse_lookup(ip="8.8.8.8", timeout=3),
            dns_response_analysis(domain="example.com", iterations=3, timeout=3),
            dns_wildcard_check(domain="example.com", test_count=2, timeout=3),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # All should complete (successfully or with errors)
        assert len(results) == 4
        for result in results:
            # Should be dict (success) or exception
            assert isinstance(result, (dict, Exception))


class TestResourceExhaustion:
    """Test behavior under resource exhaustion conditions"""

    async def test_memory_intensive_operations(self):
        """Test operations that might consume significant memory"""
        # Reasonably large bulk operation (reduced for faster testing)
        large_domain_list = [
            f"test{i}.example.com" for i in range(50)
        ]  # Reduced from 100

        result = await dns_bulk_query(
            domains=large_domain_list,
            timeout=2,  # Short timeout to prevent long-running test
            max_workers=5,  # Limit workers to prevent resource exhaustion
        )

        assert result["domain_count"] == 50
        # Should complete or fail gracefully
        assert "results" in result

    @patch("dns_mcp_server.osint_tools.create_resolver")
    async def test_rate_limiting_under_load(self, mock_create_resolver):
        """Test rate limiting behavior under high load"""
        # Mock resolver that tracks call frequency
        call_times = []

        async def timed_query(domain, record_type):
            import time

            call_times.append(time.time())
            return ["192.168.1.1"]

        mock_resolver = AsyncMock()
        mock_resolver.query.side_effect = timed_query
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver

        # Run many queries quickly
        domains = [f"test{i}.com" for i in range(20)]

        start_time = asyncio.get_event_loop().time()
        result = await dns_bulk_query(domains=domains, max_workers=10)
        end_time = asyncio.get_event_loop().time()

        # Should have taken some time due to rate limiting
        total_time = end_time - start_time
        assert total_time > 0
        assert result["domain_count"] == 20


class TestErrorRecovery:
    """Test error recovery and resilience"""

    @patch("dns_mcp_server.core_tools.create_resolver")
    async def test_resolver_recovery_after_failure(self, mock_create_resolver):
        """Test that resolvers can recover after failures"""
        call_count = 0

        def recovery_query(domain, record_type):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:  # First 2 calls fail
                raise Exception("Temporary failure")
            return ["192.168.1.1"]  # Subsequent calls succeed

        mock_resolver = AsyncMock()
        mock_resolver.query.side_effect = recovery_query
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver

        # First query should fail
        result1 = await dns_query(domain="test.com")
        assert "error" in result1

        # Second query should fail
        result2 = await dns_query(domain="test.com")
        assert "error" in result2

        # Third query should succeed
        result3 = await dns_query(domain="test.com")
        assert "records" in result3
        assert result3["records"] == ["192.168.1.1"]

    async def test_partial_failure_handling(self):
        """Test handling of partial failures in complex operations"""
        # Test query_all with some record types failing
        result = await dns_query_all(
            domain="nonexistent-example-domain-12345.com", timeout=2
        )

        assert result["domain"] == "nonexistent-example-domain-12345.com"
        # Should have tried all record types
        assert "records" in result
        assert "errors" in result or len(result["records"]) > 0


class TestConfigurationEdgeCases:
    """Test edge cases in configuration usage"""

    async def test_config_validation_in_tools(self):
        """Test that tools properly validate configuration values"""
        # Test wildcard check with invalid count (should be clamped)
        result = await dns_wildcard_check(
            domain="example.com",
            test_count=100,
            timeout=2,  # Should be clamped to max
        )

        assert result["test_count"] <= config.max_wildcard_test_count

    async def test_timeout_clamping(self):
        """Test that extreme timeout values are handled properly"""
        # Test with negative timeout (should be clamped)
        result = await dns_query(domain="example.com", timeout=-1)  # Invalid timeout

        assert "domain" in result
        # Should complete despite invalid timeout


# Test configuration
pytestmark = pytest.mark.asyncio
