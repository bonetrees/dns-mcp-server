"""
Test suite for DNS MCP Server
"""

import dns.resolver
import pytest

from dns_mcp_server.server import format_record_data, setup_resolver


class TestSetupResolver:
    """Test resolver configuration"""

    def test_system_resolver(self):
        """Test system resolver configuration"""
        resolver = setup_resolver(resolver_type="system")
        assert isinstance(resolver, dns.resolver.Resolver)
        assert resolver.timeout == 10

    def test_custom_nameserver(self):
        """Test custom nameserver configuration"""
        resolver = setup_resolver(nameserver="8.8.8.8")
        assert resolver.nameservers == ["8.8.8.8"]

    def test_public_resolver(self):
        """Test public resolver configuration"""
        resolver = setup_resolver(resolver_type="public")
        expected_nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        assert resolver.nameservers == expected_nameservers

    def test_google_resolver(self):
        """Test Google resolver configuration"""
        resolver = setup_resolver(resolver_type="google")
        expected_nameservers = ["8.8.8.8", "8.8.4.4"]
        assert resolver.nameservers == expected_nameservers

    def test_cloudflare_resolver(self):
        """Test Cloudflare resolver configuration"""
        resolver = setup_resolver(resolver_type="cloudflare")
        expected_nameservers = ["1.1.1.1", "1.0.0.1"]
        assert resolver.nameservers == expected_nameservers

    def test_custom_timeout(self):
        """Test custom timeout configuration"""
        resolver = setup_resolver(timeout=30)
        assert resolver.timeout == 30
        assert resolver.lifetime == 60  # 2x timeout


class TestFormatRecordData:
    """Test record formatting"""

    def test_mx_record_formatting(self):
        """Test MX record formatting"""

        # Mock MX record data
        class MockMXRecord:
            def __init__(self, preference, exchange):
                self.preference = preference
                self.exchange = exchange

        mx_record = MockMXRecord(10, "mail.example.com")
        formatted = format_record_data("MX", mx_record)
        assert formatted == "10 mail.example.com"

    def test_txt_record_formatting(self):
        """Test TXT record formatting"""

        # Mock TXT record data
        class MockTXTRecord:
            def __init__(self, strings):
                self.strings = strings

        txt_record = MockTXTRecord([b"v=spf1 include:_spf.example.com ~all"])
        formatted = format_record_data("TXT", txt_record)
        assert formatted == "v=spf1 include:_spf.example.com ~all"

    def test_a_record_formatting(self):
        """Test A record formatting"""

        # Mock A record data
        class MockARecord:
            def __str__(self):
                return "192.168.1.1"

        a_record = MockARecord()
        formatted = format_record_data("A", a_record)
        assert formatted == "192.168.1.1"


# Integration tests (require network access)
class TestIntegration:
    """Integration tests requiring network access"""

    @pytest.mark.integration
    def test_dns_query_integration(self):
        """Test actual DNS query (requires network)"""
        from dns_mcp_server.server import dns_query

        # Test with a well-known domain
        result = dns_query(domain="google.com", record_type="A")

        assert "domain" in result
        assert result["domain"] == "google.com"
        assert result["record_type"] == "A"
        assert "records" in result or "error" in result

    @pytest.mark.integration
    def test_dns_reverse_lookup_integration(self):
        """Test actual reverse DNS lookup (requires network)"""
        from dns_mcp_server.server import dns_reverse_lookup

        # Test with Google's public DNS
        result = dns_reverse_lookup(ip="8.8.8.8")

        assert "ip" in result
        assert result["ip"] == "8.8.8.8"
        assert "hostnames" in result or "error" in result

    @pytest.mark.integration
    def test_dns_query_all_integration(self):
        """Test comprehensive DNS query (requires network)"""
        from dns_mcp_server.server import dns_query_all

        # Test with a well-known domain
        result = dns_query_all(domain="google.com")

        assert "domain" in result
        assert result["domain"] == "google.com"
        assert "records" in result
        assert "record_types_found" in result
        assert isinstance(result["records"], dict)
