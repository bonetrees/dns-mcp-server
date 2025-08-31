"""
Async bulk DNS operations
High-performance concurrent DNS queries with rate limiting
"""

import asyncio
import time

import dns.reversename

from .formatters import format_bulk_response, format_error_response
from .param_utils import ensure_int
from .resolvers import create_resolver
from .server import mcp


@mcp.tool()
async def dns_bulk_query(
    domains: list[str],
    record_type: str = "A",
    nameserver: str | None = None,
    resolver_type: str = "system",
    timeout: int = 10,
    max_workers: int = 10,
) -> dict:
    """
    Perform concurrent bulk DNS queries for multiple domains

    Args:
        domains: List of domains to query
        record_type: DNS record type for all queries
        nameserver: Custom nameserver IP (optional)
        resolver_type: Predefined resolver type (system, public, google, cloudflare, quad9, opendns)
        timeout: Query timeout in seconds
        max_workers: Maximum concurrent queries (default: 10)

    Returns:
        Dictionary with bulk query results
    """
    if not domains:
        return {
            "bulk_query": True,
            "record_type": record_type.upper(),
            "domain_count": 0,
            "successful_queries": 0,
            "failed_queries": 0,
            "total_query_time_seconds": 0.0,
            "average_query_time_seconds": 0.0,
            "results": [],
        }

    # Ensure max_workers is an integer (handles FastMCP type conversion issues)
    max_workers = ensure_int(max_workers) or 10
    
    # Limit concurrent workers to prevent overwhelming resolvers
    actual_workers = min(max_workers, len(domains))

    resolver = create_resolver(
        nameserver=nameserver, resolver_type=resolver_type, timeout=float(timeout)
    )

    start_time = time.time()

    async def query_single_domain(domain: str) -> dict:
        """Query single domain with comprehensive error handling"""
        domain_start = time.time()

        try:
            records = await resolver.query(domain, record_type.upper())
            query_time = time.time() - domain_start

            return {
                "domain": domain,
                "record_type": record_type.upper(),
                "records": records,
                "record_count": len(records),
                "query_time_seconds": round(query_time, 3),
            }

        except Exception as e:
            query_time = time.time() - domain_start

            return {
                "domain": domain,
                "record_type": record_type.upper(),
                "query_time_seconds": round(query_time, 3),
                "error": format_error_response(
                    e,
                    context={
                        "domain": domain,
                        "record_type": record_type,
                        "resolver": resolver.resolver_id,
                    },
                ),
            }

    # Execute concurrent queries with semaphore for rate limiting
    semaphore = asyncio.Semaphore(actual_workers)

    async def rate_limited_query(domain: str):
        """Execute query with semaphore rate limiting"""
        async with semaphore:
            return await query_single_domain(domain)

    # Create and execute all tasks
    tasks = [rate_limited_query(domain) for domain in domains]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Handle any task-level exceptions
    processed_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            # Task-level failure
            processed_results.append(
                {
                    "domain": domains[i],
                    "record_type": record_type.upper(),
                    "query_time_seconds": 0.0,
                    "error": format_error_response(
                        result,
                        context={
                            "domain": domains[i],
                            "record_type": record_type,
                            "operation": "bulk_query",
                        },
                    ),
                }
            )
        else:
            processed_results.append(result)

    total_time = time.time() - start_time

    resolver_info = {
        "resolver_id": resolver.resolver_id,
        "resolver_type": resolver_type,
        "nameserver": nameserver,
    }

    return format_bulk_response(
        domains=domains,
        record_type=record_type,
        results=processed_results,
        total_time=total_time,
        resolver_info=resolver_info,
    )


@mcp.tool()
async def dns_bulk_reverse_lookup(
    ips: list[str],
    nameserver: str | None = None,
    resolver_type: str = "system",
    timeout: int = 10,
    max_workers: int = 10,
) -> dict:
    """
    Perform concurrent bulk reverse DNS lookups for multiple IP addresses

    Args:
        ips: List of IP addresses to reverse lookup
        nameserver: Custom nameserver IP (optional)
        resolver_type: Predefined resolver type (system, public, google, cloudflare, quad9, opendns)
        timeout: Query timeout in seconds
        max_workers: Maximum concurrent queries (default: 10)

    Returns:
        Dictionary with bulk reverse lookup results
    """
    if not ips:
        return {
            "bulk_reverse_lookup": True,
            "ip_count": 0,
            "successful_queries": 0,
            "failed_queries": 0,
            "total_query_time_seconds": 0.0,
            "average_query_time_seconds": 0.0,
            "results": [],
        }

    # Ensure max_workers is an integer (handles FastMCP type conversion issues)
    max_workers = ensure_int(max_workers) or 10
    
    # Limit concurrent workers
    actual_workers = min(max_workers, len(ips))

    start_time = time.time()

    async def reverse_lookup_single_ip(ip: str) -> dict:
        """Reverse lookup single IP with error handling"""
        try:
            # Generate reverse DNS name
            reverse_name = dns.reversename.from_address(ip)
            reverse_domain = str(reverse_name)

            resolver = create_resolver(
                nameserver=nameserver,
                resolver_type=resolver_type,
                timeout=float(timeout),
            )

            start_time = time.time()
            error = None
            hostnames = []

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
                response.update(
                    {"hostnames": hostnames, "hostname_count": len(hostnames)}
                )

            return response

        except Exception as e:
            # Handle invalid IP address or other errors
            return {
                "ip": ip,
                "nameserver": nameserver or resolver_type,
                "query_time_seconds": 0.0,
                "error": format_error_response(
                    e, context={"ip": ip, "operation": "reverse_lookup"}
                ),
            }

    # Execute concurrent reverse lookups with semaphore
    semaphore = asyncio.Semaphore(actual_workers)

    async def rate_limited_reverse_lookup(ip: str):
        """Execute reverse lookup with semaphore rate limiting"""
        async with semaphore:
            return await reverse_lookup_single_ip(ip)

    # Create and execute all tasks
    tasks = [rate_limited_reverse_lookup(ip) for ip in ips]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Handle task-level exceptions
    processed_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            processed_results.append(
                {
                    "ip": ips[i],
                    "nameserver": nameserver or resolver_type,
                    "query_time_seconds": 0.0,
                    "error": format_error_response(
                        result,
                        context={"ip": ips[i], "operation": "bulk_reverse_lookup"},
                    ),
                }
            )
        else:
            processed_results.append(result)

    total_time = time.time() - start_time
    successful_queries = sum(1 for r in processed_results if "error" not in r)
    failed_queries = len(processed_results) - successful_queries

    return {
        "bulk_reverse_lookup": True,
        "nameserver": nameserver or resolver_type,
        "ip_count": len(ips),
        "successful_queries": successful_queries,
        "failed_queries": failed_queries,
        "total_query_time_seconds": round(total_time, 3),
        "average_query_time_seconds": round(total_time / len(ips), 3) if ips else 0,
        "results": processed_results,
    }
