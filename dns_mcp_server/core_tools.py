"""
Core async DNS tools
Basic DNS query and reverse lookup functionality with async support
"""

import asyncio
import time

import dns.reversename

from .config import config
from .formatters import format_dns_response, format_error_response
from .resolvers import create_resolver
from .server import mcp


@mcp.tool()
async def dns_query(
    domain: str,
    record_type: str = "A",
    nameserver: str | None = None,
    resolver_type: str = "system",
    timeout: int = 10,
) -> dict:
    """
    Async DNS query for specific domain and record type

    Args:
        domain: Domain name to query
        record_type: DNS record type (A, AAAA, MX, TXT, NS, SOA, CNAME, CAA, SRV, PTR)
        nameserver: Custom nameserver IP (optional)
        resolver_type: Predefined resolver type (system, public, google, cloudflare, quad9, opendns)
        timeout: Query timeout in seconds

    Returns:
        Dictionary with query results or error information
    """
    resolver = create_resolver(
        nameserver=nameserver, resolver_type=resolver_type, timeout=float(timeout)
    )

    start_time = time.time()
    records = []
    error = None

    try:
        records = await resolver.query(domain, record_type.upper())
    except Exception as e:
        error = e

    query_time = time.time() - start_time

    resolver_info = {
        "resolver_id": resolver.resolver_id,
        "resolver_type": resolver_type,
        "nameserver": nameserver,
    }

    return format_dns_response(
        domain=domain,
        record_type=record_type,
        records=records,
        query_time=query_time,
        resolver_info=resolver_info,
        error=error,
    )


@mcp.tool()
async def dns_reverse_lookup(
    ip: str,
    nameserver: str | None = None,
    resolver_type: str = "system",
    timeout: int = 10,
) -> dict:
    """
    Async reverse DNS lookup (PTR) for an IP address

    Args:
        ip: IP address to reverse lookup
        nameserver: Custom nameserver IP (optional)
        resolver_type: Predefined resolver type (system, public, google, cloudflare, quad9, opendns)
        timeout: Query timeout in seconds

    Returns:
        Dictionary with reverse lookup results or error information
    """
    try:
        # Generate reverse DNS name
        reverse_name = dns.reversename.from_address(ip)
        reverse_domain = str(reverse_name)

        resolver = create_resolver(
            nameserver=nameserver, resolver_type=resolver_type, timeout=float(timeout)
        )

        start_time = time.time()
        hostnames = []
        error = None

        try:
            hostnames = await resolver.query(reverse_domain, "PTR")
        except Exception as e:
            error = e

        query_time = time.time() - start_time

        response = {
            "ip": ip,
            "reverse_domain": reverse_domain,
            "nameserver": nameserver or resolver_type,
            "query_time_seconds": round(query_time, 3),
        }

        if error:
            response["error"] = format_error_response(
                error,
                context={
                    "ip": ip,
                    "reverse_domain": reverse_domain,
                    "resolver": resolver.resolver_id,
                },
            )
        else:
            response.update({"hostnames": hostnames, "hostname_count": len(hostnames)})

        return response

    except Exception as e:
        # Handle invalid IP address or other errors
        return {
            "ip": ip,
            "nameserver": nameserver or resolver_type,
            "error": format_error_response(
                e, context={"ip": ip, "operation": "reverse_lookup"}
            ),
        }


@mcp.tool()
async def dns_query_all(
    domain: str,
    nameserver: str | None = None,
    resolver_type: str = "system",
    timeout: int = 10,
) -> dict:
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
    # Record types to query concurrently
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "CAA", "SRV"]

    resolver = create_resolver(
        nameserver=nameserver, resolver_type=resolver_type, timeout=float(timeout)
    )

    start_time = time.time()

    # Execute all queries concurrently with limited concurrency to avoid overwhelming resolver
    semaphore = asyncio.Semaphore(
        config.dns_query_all_concurrency
    )  # Configurable concurrency limit

    # Create tasks for concurrent execution with semaphore
    async def query_record_type(record_type: str):
        """Query single record type with error handling and rate limiting"""
        async with semaphore:
            try:
                records = await resolver.query(domain, record_type)
                return record_type, records, None
            except Exception as e:
                return record_type, [], e

    # Execute queries with controlled concurrency
    tasks = [query_record_type(rt) for rt in record_types]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    total_time = time.time() - start_time

    # Process results
    records = {}
    errors = {}

    for result in results:
        if isinstance(result, Exception):
            # Task itself failed (shouldn't happen with our error handling)
            continue

        record_type, record_list, error = result

        if error:
            errors[record_type] = format_error_response(
                error,
                context={
                    "domain": domain,
                    "record_type": record_type,
                    "resolver": resolver.resolver_id,
                },
            )
        else:
            if record_list:  # Only include non-empty results
                records[record_type] = record_list

    response = {
        "domain": domain,
        "nameserver": nameserver or resolver_type,
        "resolver_id": resolver.resolver_id,
        "total_query_time_seconds": round(total_time, 3),
        "records": records,
        "record_types_found": len(records),
        "total_records": sum(len(record_list) for record_list in records.values()),
    }

    if errors:
        response["errors"] = errors

    return response
