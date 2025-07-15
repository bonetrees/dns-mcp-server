#!/usr/bin/env python3
"""
Example usage of the DNS OSINT MCP Server
Demonstrates various DNS reconnaissance capabilities
"""

from dns_mcp_server.server import (
    dns_bulk_query,
    dns_query,
    dns_query_all,
    dns_reverse_lookup,
)


def main():
    """Demonstrate DNS OSINT capabilities"""

    print("🔍 DNS OSINT MCP Server - Example Usage")
    print("=" * 50)

    # Example 1: Basic A record lookup
    print("\n1. Basic A Record Lookup")
    print("-" * 30)
    result = dns_query(domain="google.com", record_type="A", resolver_type="cloudflare")
    print(f"Domain: {result['domain']}")
    print(f"Records: {result.get('records', result.get('error'))}")

    # Example 2: MX record lookup with different resolver
    print("\n2. MX Record Lookup")
    print("-" * 30)
    result = dns_query(domain="google.com", record_type="MX", resolver_type="quad9")
    print(f"Domain: {result['domain']}")
    print(f"Mail servers: {result.get('records', result.get('error'))}")

    # Example 3: Reverse DNS lookup
    print("\n3. Reverse DNS Lookup")
    print("-" * 30)
    result = dns_reverse_lookup(ip="8.8.8.8", resolver_type="public")
    print(f"IP: {result['ip']}")
    print(f"Hostnames: {result.get('hostnames', result.get('error'))}")

    # Example 4: Bulk domain analysis
    print("\n4. Bulk Domain Analysis")
    print("-" * 30)
    suspicious_domains = ["google.com", "facebook.com", "twitter.com"]
    result = dns_bulk_query(
        domains=suspicious_domains, record_type="A", resolver_type="google"
    )
    print(
        f"Analyzed {result['domain_count']} domains in {result['total_query_time_seconds']}s"
    )
    for domain_result in result["results"]:
        print(
            f"  {domain_result['domain']}: {domain_result.get('records', domain_result.get('error'))}"
        )

    # Example 5: Comprehensive domain profiling
    print("\n5. Comprehensive Domain Profiling")
    print("-" * 30)
    result = dns_query_all(domain="google.com", resolver_type="cloudflare")
    print(f"Domain: {result['domain']}")
    print(f"Record types found: {result['record_types_found']}")
    print(f"Total records: {result['total_records']}")
    print(f"Query time: {result['total_query_time_seconds']}s")

    print("\nDNS Records Found:")
    for record_type, records in result["records"].items():
        print(f"  {record_type}: {records}")

    if "errors" in result:
        print("\nErrors encountered:")
        for record_type, error in result["errors"].items():
            print(f"  {record_type}: {error['error']}")

    # Example 6: Resolver comparison for threat analysis
    print("\n6. Resolver Comparison Analysis")
    print("-" * 30)
    domain = "example.com"
    resolvers = ["system", "google", "cloudflare", "quad9"]

    print(f"Comparing DNS responses for {domain} across resolvers:")
    for resolver in resolvers:
        result = dns_query(domain=domain, record_type="A", resolver_type=resolver)
        records = result.get("records", ["ERROR"])
        print(f"  {resolver:>10}: {records}")

    print("\n✅ DNS OSINT examples completed!")
    print("\nThis demonstrates the power of the DNS MCP Server for:")
    print("• Threat actor infrastructure mapping")
    print("• Domain reputation analysis")
    print("• DNS manipulation detection")
    print("• Comprehensive reconnaissance")


if __name__ == "__main__":
    main()
