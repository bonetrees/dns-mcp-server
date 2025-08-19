"""
Tests for async DNS functionality
Testing the new async core tools and bulk operations
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from dns_mcp_server.bulk_tools import dns_bulk_query
from dns_mcp_server.core_tools import dns_query, dns_query_all
from dns_mcp_server.rate_limiter import DNSRateLimiter
from dns_mcp_server.resolvers import create_resolver


class TestAsyncDNSResolver:
    """Test the AsyncDNSResolver class"""

    def test_resolver_creation(self):
        """Test resolver creation with different configurations"""
        # System resolver
        resolver = create_resolver()
        assert resolver.resolver_type == "system"
        assert resolver.resolver_id == "system"

        # Google resolver
        resolver = create_resolver(resolver_type="google")
        assert resolver.resolver_type == "google"
        assert resolver.resolver_id == "google"

        # Custom resolver
        resolver = create_resolver(nameserver="8.8.8.8")
        assert "custom" in resolver.resolver_id

    @patch("aiodns.DNSResolver.query")
    async def test_successful_query(self, mock_query):
        """Test successful DNS query"""
        # Mock aiodns response with proper structure for A records
        mock_record = Mock()
        mock_record.host = "192.168.1.1"  # A records have .host attribute
        mock_record.__str__ = Mock(return_value="192.168.1.1")

        # Make the mock query return an awaitable
        async def async_mock_result():
            return [mock_record]

        mock_query.return_value = async_mock_result()

        resolver = create_resolver()
        result = await resolver.query("example.com", "A")

        assert result == ["192.168.1.1"]
        mock_query.assert_called_once_with("example.com", "A")

    @patch("aiodns.DNSResolver.query")
    async def test_query_exception_handling(self, mock_query):
        """Test DNS query exception handling"""
        mock_query.side_effect = Exception("DNS error")

        resolver = create_resolver()

        with pytest.raises(Exception) as exc_info:
            await resolver.query("nonexistent.com", "A")

        assert "DNS error" in str(exc_info.value)


class TestRateLimiter:
    """Test the DNS rate limiter"""

    def test_rate_limiter_creation(self):
        """Test rate limiter initialization"""
        limiter = DNSRateLimiter(rate_limit=10)
        assert limiter.rate_limit == 10
        assert len(limiter._throttlers) == 0

    def test_throttler_creation(self):
        """Test throttler creation per resolver"""
        limiter = DNSRateLimiter(rate_limit=30)

        throttler1 = limiter.get_throttler("google")
        throttler2 = limiter.get_throttler("cloudflare")
        throttler3 = limiter.get_throttler("google")  # Should return same instance

        assert throttler1 is not throttler2
        assert throttler1 is throttler3
        assert len(limiter._throttlers) == 2

    async def test_rate_limit_acquire(self):
        """Test rate limit token acquisition"""
        limiter = DNSRateLimiter(rate_limit=100)  # High rate for testing

        # Should not raise exception
        await limiter.acquire("test_resolver")
        await limiter.acquire("test_resolver")

    def test_get_stats(self):
        """Test rate limiter statistics"""
        limiter = DNSRateLimiter(rate_limit=25)
        limiter.get_throttler("google")
        limiter.get_throttler("cloudflare")

        stats = limiter.get_stats()
        assert "google" in stats
        assert "cloudflare" in stats
        assert stats["google"]["rate_limit"] == 25


class TestAsyncDNSTools:
    """Test async DNS tools"""

    @patch("dns_mcp_server.core_tools.create_resolver")
    async def test_dns_query_success(self, mock_create_resolver):
        """Test successful dns_query"""
        # Mock resolver
        mock_resolver = AsyncMock()
        mock_resolver.query.return_value = ["192.168.1.1"]
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver

        result = await dns_query(
            domain="example.com", record_type="A", resolver_type="google"
        )

        assert result["domain"] == "example.com"
        assert result["record_type"] == "A"
        assert result["records"] == ["192.168.1.1"]
        assert result["record_count"] == 1
        assert "query_time_seconds" in result
        assert "error" not in result

    @patch("dns_mcp_server.core_tools.create_resolver")
    async def test_dns_query_error(self, mock_create_resolver):
        """Test dns_query with DNS error"""
        # Mock resolver that raises exception
        mock_resolver = AsyncMock()
        mock_resolver.query.side_effect = Exception("NXDOMAIN")
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver

        result = await dns_query(domain="nonexistent.example.com", record_type="A")

        assert result["domain"] == "nonexistent.example.com"
        assert "error" in result
        assert "records" not in result

    @patch("dns_mcp_server.core_tools.create_resolver")
    async def test_dns_query_all_concurrent(self, mock_create_resolver):
        """Test dns_query_all concurrent execution"""
        # Mock resolver
        mock_resolver = AsyncMock()

        # Mock different responses for different record types
        async def mock_query(domain, record_type):
            if record_type == "A":
                return ["192.168.1.1"]
            elif record_type == "MX":
                return ["10 mail.example.com"]
            else:
                raise Exception("No records")

        mock_resolver.query.side_effect = mock_query
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver

        result = await dns_query_all(domain="example.com")

        assert result["domain"] == "example.com"
        assert "A" in result["records"]
        assert "MX" in result["records"]
        assert result["record_types_found"] == 2
        assert "errors" in result  # Should have errors for unsupported types
        assert "total_query_time_seconds" in result


class TestBulkOperations:
    """Test bulk DNS operations"""

    @patch("dns_mcp_server.bulk_tools.create_resolver")
    async def test_bulk_query_success(self, mock_create_resolver):
        """Test successful bulk DNS query"""
        # Mock resolver
        mock_resolver = AsyncMock()
        mock_resolver.query.return_value = ["192.168.1.1"]
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver

        domains = ["example1.com", "example2.com", "example3.com"]
        result = await dns_bulk_query(domains=domains, record_type="A", max_workers=2)

        assert result["bulk_query"] is True
        assert result["domain_count"] == 3
        assert result["successful_queries"] == 3
        assert result["failed_queries"] == 0
        assert len(result["results"]) == 3

        # Check individual results
        for domain_result in result["results"]:
            assert domain_result["record_type"] == "A"
            assert domain_result["records"] == ["192.168.1.1"]
            assert "error" not in domain_result

    async def test_bulk_query_empty_list(self):
        """Test bulk query with empty domain list"""
        result = await dns_bulk_query(domains=[])

        assert result["domain_count"] == 0
        assert result["successful_queries"] == 0
        assert result["failed_queries"] == 0
        assert result["results"] == []

    @patch("dns_mcp_server.bulk_tools.create_resolver")
    async def test_bulk_query_mixed_results(self, mock_create_resolver):
        """Test bulk query with mixed success/failure"""
        # Mock resolver with mixed responses
        mock_resolver = AsyncMock()

        async def mock_query(domain, record_type):
            if "fail" in domain:
                raise Exception("NXDOMAIN")
            return ["192.168.1.1"]

        mock_resolver.query.side_effect = mock_query
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver

        domains = ["success.com", "fail.com", "success2.com"]
        result = await dns_bulk_query(domains=domains)

        assert result["domain_count"] == 3
        assert result["successful_queries"] == 2
        assert result["failed_queries"] == 1

        # Check that we have both successful and failed results
        errors = [r for r in result["results"] if "error" in r]
        successes = [r for r in result["results"] if "error" not in r]

        assert len(errors) == 1
        assert len(successes) == 2


class TestIntegration:
    """Integration tests with real domains (limited to avoid hitting rate limits)"""

    @pytest.mark.integration
    async def test_real_domain_query(self):
        """Test query against a real domain"""
        # Use a reliable domain for testing
        result = await dns_query(
            domain="sans.com", record_type="A", resolver_type="google", timeout=5
        )

        # Should succeed or have a meaningful error
        assert result["domain"] == "sans.com"
        assert "query_time_seconds" in result
        # Either records or error should be present
        assert ("records" in result) or ("error" in result)

        if "records" in result:
            assert isinstance(result["records"], list)
            assert result["record_count"] >= 0

    @pytest.mark.integration
    async def test_real_bulk_query(self):
        """Test bulk query against real domains"""
        domains = ["sans.com", "hackthissite.org"]

        result = await dns_bulk_query(
            domains=domains,
            record_type="A",
            resolver_type="cloudflare",
            timeout=5,
            max_workers=2,
        )

        assert result["domain_count"] == 2
        assert len(result["results"]) == 2
        assert result["total_query_time_seconds"] > 0


# Test configuration
pytestmark = pytest.mark.asyncio
