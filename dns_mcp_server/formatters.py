"""
DNS record formatting utilities
Handles formatting of various DNS record types and error responses
"""

from datetime import datetime
from typing import Any


def format_error_response(
    error: Exception, context: dict[str, Any] | None = None
) -> dict[str, Any]:
    """
    Format error responses with OSINT context and insights

    Args:
        error: The exception that occurred
        context: Additional context (domain, resolver, etc.)

    Returns:
        Formatted error dictionary with OSINT insights
    """
    error_type = type(error).__name__
    error_msg = str(error)

    # Base error response
    response = {
        "error": "unknown",
        "type": error_type,
        "details": error_msg,
        "timestamp": datetime.utcnow().isoformat(),
    }

    # Add context if provided
    if context:
        response.update(context)

    # OSINT-aware error classification
    if "NXDOMAIN" in error_msg or "No such domain" in error_msg:
        response.update(
            {
                "error": "domain_not_found",
                "type": "NXDOMAIN",
                "osint_insights": {
                    "possible_scenarios": [
                        "Domain never existed (typosquatting target)",
                        "Domain expired (abandoned infrastructure)",
                        "Domain suspended (possible takedown)",
                        "DNS configuration error",
                    ],
                    "investigation_tips": [
                        "Check historical DNS records",
                        "Search for similar domain variations",
                        "Verify domain registration status",
                    ],
                },
            }
        )
    elif "No answer" in error_msg or "NODATA" in error_msg:
        response.update(
            {
                "error": "no_records",
                "type": "NoAnswer",
                "osint_insights": {
                    "possible_scenarios": [
                        "Record type not configured",
                        "Selective DNS response (geo-blocking)",
                        "DNS filtering/sinkholing",
                    ],
                    "investigation_tips": [
                        "Try different record types",
                        "Query from different resolver locations",
                        "Check if domain is parked",
                    ],
                },
            }
        )
    elif "timeout" in error_msg.lower() or "Timeout" in error_type:
        response.update(
            {
                "error": "timeout",
                "type": "Timeout",
                "osint_insights": {
                    "possible_scenarios": [
                        "Slow/overloaded nameserver",
                        "Network filtering",
                        "DDoS protection triggering",
                    ],
                    "investigation_tips": [
                        "Retry with longer timeout",
                        "Try alternative resolver",
                        "Check nameserver health",
                    ],
                },
            }
        )
    elif "SERVFAIL" in error_msg:
        response.update(
            {
                "error": "server_failure",
                "type": "SERVFAIL",
                "osint_insights": {
                    "possible_scenarios": [
                        "Authoritative server error",
                        "DNSSEC validation failure",
                        "Nameserver misconfiguration",
                    ],
                    "investigation_tips": [
                        "Try different resolver",
                        "Check DNSSEC status",
                        "Verify nameserver configuration",
                    ],
                },
            }
        )
    elif "REFUSED" in error_msg:
        response.update(
            {
                "error": "query_refused",
                "type": "REFUSED",
                "osint_insights": {
                    "possible_scenarios": [
                        "Recursive queries disabled",
                        "Access control restrictions",
                        "Rate limiting active",
                    ],
                    "investigation_tips": [
                        "Try authoritative nameserver",
                        "Use different source IP",
                        "Reduce query rate",
                    ],
                },
            }
        )

    return response


def format_dns_response(
    domain: str,
    record_type: str,
    records: list,
    query_time: float,
    resolver_info: dict[str, Any],
    error: Exception | None = None,
) -> dict[str, Any]:
    """
    Format DNS query response with comprehensive metadata

    Args:
        domain: Queried domain
        record_type: DNS record type
        records: List of DNS records (empty if error)
        query_time: Query execution time in seconds
        resolver_info: Resolver configuration details
        error: Exception if query failed

    Returns:
        Formatted response dictionary
    """
    response = {
        "domain": domain,
        "record_type": record_type.upper(),
        "nameserver": resolver_info.get("resolver_id", "unknown"),
        "query_time_seconds": round(query_time, 3),
    }

    if error:
        response["error"] = format_error_response(
            error,
            context={
                "domain": domain,
                "record_type": record_type,
                "resolver": resolver_info.get("resolver_id"),
            },
        )
    else:
        response.update({"records": records, "record_count": len(records)})

    return response


def format_bulk_response(
    domains: list,
    record_type: str,
    results: list,
    total_time: float,
    resolver_info: dict[str, Any],
) -> dict[str, Any]:
    """
    Format bulk DNS query response

    Args:
        domains: List of queried domains
        record_type: DNS record type
        results: List of individual query results
        total_time: Total execution time
        resolver_info: Resolver configuration details

    Returns:
        Formatted bulk response dictionary
    """
    successful_queries = sum(1 for r in results if "error" not in r)
    failed_queries = len(results) - successful_queries

    return {
        "bulk_query": True,
        "record_type": record_type.upper(),
        "nameserver": resolver_info.get("resolver_id", "unknown"),
        "domain_count": len(domains),
        "successful_queries": successful_queries,
        "failed_queries": failed_queries,
        "total_query_time_seconds": round(total_time, 3),
        "average_query_time_seconds": round(total_time / len(domains), 3)
        if domains
        else 0,
        "results": results,
    }
