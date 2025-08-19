"""
Test suite for DNS MCP Server (Legacy compatibility tests)
Tests to ensure our new async architecture maintains compatibility
"""


import pytest

from dns_mcp_server.formatters import format_error_response
from dns_mcp_server.resolvers import RESOLVER_CONFIGS, create_resolver


class TestResolverConfigurations:
    """Test resolver configuration compatibility"""

    def test_resolver_configs_exist(self):
        """Test that all expected resolver configs exist"""
        expected_resolvers = ["public", "google", "cloudflare", "quad9", "opendns"]

        for resolver_type in expected_resolvers:
            assert resolver_type in RESOLVER_CONFIGS
            assert isinstance(RESOLVER_CONFIGS[resolver_type], list)
            assert len(RESOLVER_CONFIGS[resolver_type]) > 0

    def test_google_resolver_config(self):
        """Test Google resolver configuration"""
        expected_nameservers = ["8.8.8.8", "8.8.4.4"]
        assert RESOLVER_CONFIGS["google"] == expected_nameservers

    def test_cloudflare_resolver_config(self):
        """Test Cloudflare resolver configuration"""
        expected_nameservers = ["1.1.1.1", "1.0.0.1"]
        assert RESOLVER_CONFIGS["cloudflare"] == expected_nameservers

    def test_public_resolver_config(self):
        """Test public resolver configuration"""
        expected_nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        assert RESOLVER_CONFIGS["public"] == expected_nameservers


class TestAsyncResolverCreation:
    """Test async resolver creation"""

    def test_system_resolver_creation(self):
        """Test system resolver creation"""
        resolver = create_resolver(resolver_type="system")
        assert resolver.resolver_type == "system"
        assert resolver.resolver_id == "system"

    def test_custom_nameserver_resolver(self):
        """Test custom nameserver resolver creation"""
        resolver = create_resolver(nameserver="8.8.8.8")
        assert "custom" in resolver.resolver_id

    def test_google_resolver_creation(self):
        """Test Google resolver creation"""
        resolver = create_resolver(resolver_type="google")
        assert resolver.resolver_type == "google"
        assert resolver.resolver_id == "google"
        assert resolver.resolver.nameservers == RESOLVER_CONFIGS["google"]

    def test_timeout_configuration(self):
        """Test timeout configuration"""
        timeout = 30.0
        resolver = create_resolver(timeout=timeout)
        assert resolver.timeout == timeout
        # Note: aiodns.DNSResolver.timeout may not be directly accessible


class TestErrorFormatting:
    """Test error response formatting"""

    def test_nxdomain_error_formatting(self):
        """Test NXDOMAIN error formatting"""
        error = Exception("NXDOMAIN")
        context = {"domain": "nonexistent.com"}

        result = format_error_response(error, context)

        assert result["error"] == "domain_not_found"
        assert result["type"] == "NXDOMAIN"
        assert result["domain"] == "nonexistent.com"
        assert "osint_insights" in result
        assert "possible_scenarios" in result["osint_insights"]

    def test_no_answer_error_formatting(self):
        """Test NoAnswer error formatting"""
        error = Exception("No answer")
        context = {"domain": "example.com", "record_type": "AAAA"}

        result = format_error_response(error, context)

        assert result["error"] == "no_records"
        assert result["type"] == "NoAnswer"
        assert "osint_insights" in result

    def test_timeout_error_formatting(self):
        """Test timeout error formatting"""
        error = Exception("timeout")

        result = format_error_response(error)

        assert result["error"] == "timeout"
        assert result["type"] == "Timeout"
        assert "osint_insights" in result

    def test_generic_error_formatting(self):
        """Test generic error formatting"""
        error = ValueError("Invalid input")

        result = format_error_response(error)

        assert result["error"] == "unknown"
        assert result["type"] == "ValueError"
        assert result["details"] == "Invalid input"
        assert "timestamp" in result


class TestRecordFormatting:
    """Test DNS record formatting (moved to resolver)"""

    def test_mx_record_formatting(self):
        """Test MX record formatting via resolver"""
        resolver = create_resolver()

        # Test MX record with aiodns structure (priority/host)
        class MockMXRecord:
            def __init__(self, priority, host):
                self.priority = priority
                self.host = host

        mx_record = MockMXRecord(10, "mail.example.com")
        formatted = resolver._format_record("MX", mx_record)
        assert formatted == "10 mail.example.com"

        # Test MX record with RFC standard structure (preference/exchange)
        class MockRFCMXRecord:
            def __init__(self, preference, exchange):
                self.preference = preference
                self.exchange = exchange

        rfc_mx_record = MockRFCMXRecord(20, "backup.example.com")
        formatted_rfc = resolver._format_record("MX", rfc_mx_record)
        assert formatted_rfc == "20 backup.example.com"

        # Test MX record fallback (no recognized attributes)
        class MockSimpleMXRecord:
            def __str__(self):
                return "30 fallback.example.com"

        simple_mx_record = MockSimpleMXRecord()
        formatted_simple = resolver._format_record("MX", simple_mx_record)
        assert formatted_simple == "30 fallback.example.com"

    def test_txt_record_formatting(self):
        """Test TXT record formatting via resolver"""
        resolver = create_resolver()

        # Mock TXT record with text attribute (matches aiodns structure)
        class MockTXTRecord:
            def __init__(self, text):
                self.text = text

        txt_record = MockTXTRecord("v=spf1 include:_spf.example.com ~all")
        formatted = resolver._format_record("TXT", txt_record)
        assert formatted == "v=spf1 include:_spf.example.com ~all"

        # Test TXT record with bytes text (can happen in real scenarios)
        txt_record_bytes = MockTXTRecord(b"v=spf1 include:_spf.example.com ~all")
        formatted_bytes = resolver._format_record("TXT", txt_record_bytes)
        assert formatted_bytes == "v=spf1 include:_spf.example.com ~all"

        # Test TXT record fallback (no text attribute)
        class MockSimpleTXTRecord:
            def __str__(self):
                return "v=spf1 fallback test"

        simple_txt_record = MockSimpleTXTRecord()
        formatted_simple = resolver._format_record("TXT", simple_txt_record)
        assert formatted_simple == "v=spf1 fallback test"

    def test_a_record_formatting(self):
        """Test A record formatting via resolver"""
        resolver = create_resolver()

        # Mock A record
        class MockARecord:
            def __str__(self):
                return "192.168.1.1"

        a_record = MockARecord()
        formatted = resolver._format_record("A", a_record)
        assert formatted == "192.168.1.1"


# Integration tests (require network access)
class TestAsyncIntegration:
    """Integration tests for async functionality"""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_async_dns_query_integration(self):
        """Test actual async DNS query (requires network)"""
        from dns_mcp_server.core_tools import dns_query

        # Test with a well-known domain
        result = await dns_query(
            domain="sans.com", record_type="A", resolver_type="google"
        )

        assert "domain" in result
        assert result["domain"] == "sans.com"
        assert result["record_type"] == "A"
        assert "records" in result or "error" in result
        assert "query_time_seconds" in result

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_async_reverse_lookup_integration(self):
        """Test actual async reverse DNS lookup (requires network)"""
        from dns_mcp_server.core_tools import dns_reverse_lookup

        # Test with Google's public DNS
        result = await dns_reverse_lookup(ip="8.8.8.8", resolver_type="cloudflare")

        assert "ip" in result
        assert result["ip"] == "8.8.8.8"
        assert "hostnames" in result or "error" in result
        assert "query_time_seconds" in result

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_async_query_all_integration(self):
        """Test comprehensive async DNS query (requires network)"""
        from dns_mcp_server.core_tools import dns_query_all

        # Test with a well-known domain
        result = await dns_query_all(domain="hackthissite.org", resolver_type="quad9")

        assert "domain" in result
        assert result["domain"] == "hackthissite.org"
        assert "records" in result
        assert "record_types_found" in result
        assert isinstance(result["records"], dict)
        assert "total_query_time_seconds" in result

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_async_bulk_query_integration(self):
        """Test async bulk query (requires network)"""
        from dns_mcp_server.bulk_tools import dns_bulk_query

        domains = ["sans.com", "hackthissite.org"]
        result = await dns_bulk_query(
            domains=domains, record_type="A", resolver_type="cloudflare", max_workers=2
        )

        assert result["bulk_query"] is True
        assert result["domain_count"] == 2
        assert len(result["results"]) == 2
        assert result["total_query_time_seconds"] > 0
        assert "successful_queries" in result
        assert "failed_queries" in result


# Configuration for pytest
pytestmark = pytest.mark.asyncio
