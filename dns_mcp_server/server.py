#!/usr/bin/env python3
"""
DNS OSINT MCP Server
Comprehensive DNS reconnaissance tools for threat intelligence and OSINT investigations
"""

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Union

import dns.exception
import dns.resolver
import dns.reversename
from fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("DNS OSINT Server")


def setup_resolver(
    nameserver: Optional[str] = None, resolver_type: str = "system", timeout: int = 10
) -> dns.resolver.Resolver:
    """
    Centralized resolver configuration for all DNS functions

    Args:
        nameserver: Custom nameserver IP (overrides resolver_type)
        resolver_type: Predefined resolver type
        timeout: Query timeout in seconds

    Returns:
        Configured DNS resolver
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2  # Overall query lifetime

    if nameserver:
        # Custom nameserver overrides resolver_type
        resolver.nameservers = [nameserver]
    elif resolver_type == "public":
        resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    elif resolver_type == "google":
        resolver.nameservers = ["8.8.8.8", "8.8.4.4"]
    elif resolver_type == "cloudflare":
        resolver.nameservers = ["1.1.1.1", "1.0.0.1"]
    elif resolver_type == "quad9":
        resolver.nameservers = ["9.9.9.9", "149.112.112.112"]
    elif resolver_type == "opendns":
        resolver.nameservers = ["208.67.222.222", "208.67.220.220"]
    # "system" uses default resolvers

    return resolver


def format_record_data(record_type: str, rdata) -> str:
    """
    Format DNS record data based on record type

    Args:
        record_type: DNS record type
        rdata: Raw DNS record data

    Returns:
        Formatted record string
    """
    if record_type == "MX":
        return f"{rdata.preference} {rdata.exchange}"
    elif record_type == "SOA":
        return f"{rdata.mname} {rdata.rname} {rdata.serial} {rdata.refresh} {rdata.retry} {rdata.expire} {rdata.minimum}"
    elif record_type == "TXT":
        return "".join(
            [s.decode() if isinstance(s, bytes) else s for s in rdata.strings]
        )
    elif record_type == "SRV":
        return f"{rdata.priority} {rdata.weight} {rdata.port} {rdata.target}"
    elif record_type == "CAA":
        return f"{rdata.flags} {rdata.tag} {rdata.value}"
    else:
        return str(rdata)


def handle_dns_exceptions(func):
    """
    Decorator to handle DNS exceptions consistently across all functions
    """

    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except dns.resolver.NXDOMAIN:
            return {"error": "domain_not_found", "type": "NXDOMAIN"}
        except dns.resolver.NoAnswer:
            return {"error": "no_records", "type": "NoAnswer"}
        except dns.resolver.Timeout:
            return {"error": "timeout", "type": "Timeout"}
        except dns.resolver.LifetimeTimeout:
            return {"error": "lifetime_timeout", "type": "LifetimeTimeout"}
        except dns.resolver.NoNameservers:
            return {"error": "no_nameservers", "type": "NoNameservers"}
        except dns.exception.DNSException as e:
            return {"error": "dns_error", "type": "DNSException", "details": str(e)}
        except Exception as e:
            return {"error": "unexpected", "type": type(e).__name__, "details": str(e)}

    return wrapper


@handle_dns_exceptions
def query_single_record(
    domain: str, record_type: str, resolver: dns.resolver.Resolver
) -> Union[Dict, List[str]]:
    """
    Query a single DNS record type

    Args:
        domain: Domain to query
        record_type: DNS record type
        resolver: Configured DNS resolver

    Returns:
        List of record strings or error dict
    """
    result = resolver.resolve(domain, record_type)

    records = []
    for rdata in result:
        formatted_record = format_record_data(record_type, rdata)
        records.append(formatted_record)

    return records


@mcp.tool()
def dns_query(
    domain: str,
    record_type: str = "A",
    nameserver: Optional[str] = None,
    resolver_type: str = "system",
    timeout: int = 10,
) -> Dict:
    """
    Query DNS records for a specific domain and record type

    Args:
        domain: Domain name to query
        record_type: DNS record type (A, AAAA, MX, TXT, NS, SOA, CNAME, CAA, SRV, PTR)
        nameserver: Custom nameserver IP (optional)
        resolver_type: Predefined resolver type (system, public, google, cloudflare, quad9, opendns)
        timeout: Query timeout in seconds

    Returns:
        Dictionary with query results or error information
    """
    resolver = setup_resolver(nameserver, resolver_type, timeout)

    start_time = time.time()
    result = query_single_record(domain, record_type.upper(), resolver)
    query_time = time.time() - start_time

    response = {
        "domain": domain,
        "record_type": record_type.upper(),
        "nameserver": nameserver or resolver_type,
        "query_time_seconds": round(query_time, 3),
    }

    if isinstance(result, dict) and "error" in result:
        response["error"] = result
    else:
        response["records"] = result
        response["record_count"] = len(result)

    return response


@mcp.tool()
def dns_reverse_lookup(
    ip: str,
    nameserver: Optional[str] = None,
    resolver_type: str = "system",
    timeout: int = 10,
) -> Dict:
    """
    Perform reverse DNS lookup (PTR) for an IP address

    Args:
        ip: IP address to reverse lookup
        nameserver: Custom nameserver IP (optional)
        resolver_type: Predefined resolver type (system, public, google, cloudflare, quad9, opendns)
        timeout: Query timeout in seconds

    Returns:
        Dictionary with reverse lookup results or error information
    """
    resolver = setup_resolver(nameserver, resolver_type, timeout)

    try:
        start_time = time.time()
        reverse_name = dns.reversename.from_address(ip)
        result = query_single_record(str(reverse_name), "PTR", resolver)
        query_time = time.time() - start_time

        response = {
            "ip": ip,
            "nameserver": nameserver or resolver_type,
            "query_time_seconds": round(query_time, 3),
        }

        if isinstance(result, dict) and "error" in result:
            response["error"] = result
        else:
            response["hostnames"] = result
            response["hostname_count"] = len(result)

        return response

    except Exception as e:
        return {
            "ip": ip,
            "nameserver": nameserver or resolver_type,
            "error": {
                "error": "invalid_ip",
                "type": type(e).__name__,
                "details": str(e),
            },
        }


@mcp.tool()
def dns_bulk_query(
    domains: List[str],
    record_type: str = "A",
    nameserver: Optional[str] = None,
    resolver_type: str = "system",
    timeout: int = 10,
) -> Dict:
    """
    Perform bulk DNS queries for multiple domains

    Args:
        domains: List of domains to query
        record_type: DNS record type for all queries
        nameserver: Custom nameserver IP (optional)
        resolver_type: Predefined resolver type (system, public, google, cloudflare, quad9, opendns)
        timeout: Query timeout in seconds

    Returns:
        Dictionary with bulk query results
    """
    resolver = setup_resolver(nameserver, resolver_type, timeout)

    results = []
    start_time = time.time()

    for domain in domains:
        domain_result = query_single_record(domain, record_type.upper(), resolver)

        domain_response = {"domain": domain, "record_type": record_type.upper()}

        if isinstance(domain_result, dict) and "error" in domain_result:
            domain_response["error"] = domain_result
        else:
            domain_response["records"] = domain_result
            domain_response["record_count"] = len(domain_result)

        results.append(domain_response)

    total_time = time.time() - start_time

    return {
        "bulk_query": True,
        "record_type": record_type.upper(),
        "nameserver": nameserver or resolver_type,
        "domain_count": len(domains),
        "total_query_time_seconds": round(total_time, 3),
        "results": results,
    }


@mcp.tool()
def dns_query_all(
    domain: str,
    nameserver: Optional[str] = None,
    resolver_type: str = "system",
    timeout: int = 10,
) -> Dict:
    """
    Query all DNS record types concurrently for comprehensive domain profiling

    Args:
        domain: Domain name to query
        nameserver: Custom nameserver IP (optional)
        resolver_type: Predefined resolver type (system, public, google, cloudflare, quad9, opendns)
        timeout: Query timeout in seconds

    Returns:
        Dictionary with comprehensive DNS profile
    """

    def query_with_new_resolver(
        domain: str, record_type: str
    ) -> Union[Dict, List[str]]:
        """
        Create a new resolver for each thread to avoid race conditions

        Args:
            domain: Domain to query
            record_type: DNS record type

        Returns:
            Query result or error dict
        """
        thread_resolver = setup_resolver(nameserver, resolver_type, timeout)
        return query_single_record(domain, record_type, thread_resolver)

    # Record types to query
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "CAA", "SRV"]

    start_time = time.time()

    # Create tasks for concurrent execution with thread-safe resolvers
    with ThreadPoolExecutor(max_workers=len(record_types)) as executor:
        # Submit all queries - each thread gets its own resolver
        future_to_record = {
            executor.submit(query_with_new_resolver, domain, record_type): record_type
            for record_type in record_types
        }

        # Collect results
        records = {}
        errors = {}

        for future in future_to_record:
            record_type = future_to_record[future]
            try:
                result = future.result()

                if isinstance(result, dict) and "error" in result:
                    errors[record_type] = result
                else:
                    records[record_type] = result

            except Exception as e:
                errors[record_type] = {
                    "error": "query_failed",
                    "type": type(e).__name__,
                    "details": str(e),
                }

    total_time = time.time() - start_time

    response = {
        "domain": domain,
        "nameserver": nameserver or resolver_type,
        "total_query_time_seconds": round(total_time, 3),
        "records": records,
        "record_types_found": len(records),
        "total_records": sum(len(record_list) for record_list in records.values()),
    }

    if errors:
        response["errors"] = errors

    return response


def main():
    """Main entry point for the DNS MCP server"""
    mcp.run()


if __name__ == "__main__":
    main()
