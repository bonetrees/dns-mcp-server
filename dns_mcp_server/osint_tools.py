"""
OSINT-specific DNS analysis tools

This module provides advanced DNS reconnaissance tools specifically designed for
Open Source Intelligence (OSINT) and threat intelligence investigations. These
tools help security researchers identify infrastructure patterns, detect anomalies,
and analyze DNS configurations for potential security issues.

Key OSINT Tools:
1. **DNS Propagation Check**: Detect inconsistencies across multiple resolvers
2. **Wildcard Detection**: Identify catch-all DNS configurations
3. **Response Time Analysis**: Detect performance anomalies and filtering

Usage Examples:
    ```python
    from dns_mcp_server.osint_tools import (
        dns_propagation_check,
        dns_wildcard_check,
        dns_response_analysis
    )
    
    # Check DNS consistency across resolvers
    result = await dns_propagation_check(
        domain="suspicious-domain.com",
        record_type="A"
    )
    
    if not result["is_consistent"]:
        print("WARNING: DNS inconsistency detected!")
        print(f"Trust level: {result['osint_analysis']['trust_level']}")
    
    # Detect wildcard DNS (common in phishing)
    wildcard_result = await dns_wildcard_check(
        domain="phishing-domain.com",
        test_count=5
    )
    
    if wildcard_result["has_wildcard"]:
        risk = wildcard_result["osint_insights"]["risk_level"]
        print(f"Wildcard DNS detected - Risk: {risk}")
    
    # Analyze response times for anomalies
    timing_result = await dns_response_analysis(
        domain="c2-server.com",
        iterations=15
    )
    
    rating = timing_result["osint_insights"]["performance_rating"]
    print(f"Performance: {rating}")
    ```

Security Applications:
- **Threat Actor Infrastructure Mapping**: Identify related domains and infrastructure
- **Phishing Detection**: Detect wildcard configurations used in phishing kits
- **DNS Poisoning Detection**: Identify inconsistent responses across resolvers
- **C2 Server Analysis**: Profile command and control server response patterns
- **Domain Reputation Analysis**: Assess domain trustworthiness and configuration

Default Resolvers for Propagation Analysis:
- Google (8.8.8.8)
- Cloudflare (1.1.1.1)
- Quad9 (9.9.9.9)
- OpenDNS (208.67.222.222)
- Level3 (4.2.2.1)
- Verisign (64.6.64.6)

Note:
    All OSINT tools include detailed analysis with security implications,
    investigation tips, and risk assessments. Results include timestamps
    for forensic timeline analysis.
"""

import asyncio
import time
import secrets
import string
import statistics
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

from .server import mcp
from .resolvers import create_resolver
from .formatters import format_error_response
from .config import (
    DEFAULT_PROPAGATION_RESOLVERS, 
    config, 
    get_performance_rating, 
    is_cdn_related
)


@mcp.tool()
async def dns_propagation_check(
    domain: str,
    record_type: str = "A",
    resolvers: Optional[Dict[str, str]] = None,
    timeout: int = 10
) -> Dict:
    """
    Check DNS propagation across multiple resolvers to detect inconsistencies
    
    Useful for detecting:
    - DNS cache poisoning
    - Geographic DNS steering
    - DNS filtering/censorship
    - Propagation delays
    
    Args:
        domain: Domain name to query
        record_type: DNS record type to check (A, AAAA, MX, TXT, etc.)
        resolvers: Custom resolver dict (name: IP), uses defaults if None
        timeout: Query timeout in seconds
        
    Returns:
        Dictionary with propagation analysis and OSINT insights
    """
    if resolvers is None:
        resolvers = DEFAULT_PROPAGATION_RESOLVERS.copy()
    
    start_time = time.time()
    results = {}
    
    async def query_resolver(resolver_name: str, resolver_ip: str) -> Tuple[str, Dict]:
        """Query a single resolver and return results"""
        try:
            resolver = create_resolver(
                nameserver=resolver_ip,
                resolver_type="custom",
                timeout=float(timeout)
            )
            
            query_start = time.time()
            records = await resolver.query(domain, record_type.upper())
            query_time = time.time() - query_start
            
            return resolver_name, {
                "success": True,
                "records": records,
                "record_count": len(records),
                "query_time_seconds": round(query_time, 3),
                "resolver_ip": resolver_ip
            }
            
        except Exception as e:
            query_time = time.time() - query_start if 'query_start' in locals() else 0
            
            return resolver_name, {
                "success": False,
                "error": format_error_response(
                    e,
                    context={
                        "domain": domain,
                        "record_type": record_type,
                        "resolver": resolver_name,
                        "resolver_ip": resolver_ip
                    }
                ),
                "query_time_seconds": round(query_time, 3),
                "resolver_ip": resolver_ip
            }
    
    # Execute all queries concurrently
    tasks = [
        query_resolver(name, ip) 
        for name, ip in resolvers.items()
    ]
    
    query_results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Process results
    for result in query_results:
        if isinstance(result, Exception):
            continue  # Skip failed tasks
        resolver_name, resolver_result = result
        results[resolver_name] = resolver_result
    
    total_time = time.time() - start_time
    
    # Analyze consistency
    successful_results = {
        name: result for name, result in results.items() 
        if result.get("success", False)
    }
    
    failed_results = {
        name: result for name, result in results.items()
        if not result.get("success", False)
    }
    
    # Group resolvers by their record responses
    response_groups = defaultdict(list)
    unique_responses = []
    
    for resolver_name, result in successful_results.items():
        if "records" in result:
            # Create a hashable representation of the records
            record_tuple = tuple(sorted(result["records"]))
            response_groups[record_tuple].append(resolver_name)
            
            # Track unique responses
            if record_tuple not in [tuple(sorted(r)) for r in unique_responses]:
                unique_responses.append(result["records"])
    
    is_consistent = len(response_groups) <= 1
    
    # Calculate response time statistics
    response_times = [
        result["query_time_seconds"] 
        for result in successful_results.values()
    ]
    
    time_stats = {}
    if response_times:
        time_stats = {
            "min_time": round(min(response_times), 3),
            "max_time": round(max(response_times), 3),
            "avg_time": round(statistics.mean(response_times), 3),
            "median_time": round(statistics.median(response_times), 3)
        }
        
        if len(response_times) > 1:
            time_stats["std_dev"] = round(statistics.stdev(response_times), 3)
    
    # OSINT Analysis
    osint_analysis = {
        "consistency_status": "CONSISTENT" if is_consistent else "INCONSISTENT",
        "trust_level": "HIGH" if is_consistent and len(failed_results) == 0 else 
                      "MEDIUM" if is_consistent else "LOW",
        "potential_issues": []
    }
    
    if not is_consistent:
        osint_analysis["potential_issues"].extend([
            "DNS response inconsistency detected",
            "Possible DNS cache poisoning",
            "Geographic DNS steering active", 
            "DNS filtering or censorship",
            "Domain propagation still in progress"
        ])
    
    if len(failed_results) > len(successful_results):
        osint_analysis["potential_issues"].append("High resolver failure rate - possible blocking")
    
    if time_stats.get("max_time", 0) > 2.0:
        osint_analysis["potential_issues"].append("Slow DNS response detected")
    
    # Format response groups for output
    formatted_groups = []
    for record_tuple, resolver_list in response_groups.items():
        formatted_groups.append({
            "resolvers": resolver_list,
            "records": list(record_tuple),
            "resolver_count": len(resolver_list)
        })
    
    return {
        "domain": domain,
        "record_type": record_type.upper(),
        "total_resolvers_queried": len(resolvers),
        "successful_queries": len(successful_results),
        "failed_queries": len(failed_results),
        "is_consistent": is_consistent,
        "unique_response_count": len(response_groups),
        "total_query_time_seconds": round(total_time, 3),
        "response_time_stats": time_stats,
        "resolver_results": results,
        "response_groups": formatted_groups,
        "osint_analysis": osint_analysis
    }


@mcp.tool()
async def dns_wildcard_check(
    domain: str,
    test_count: int = None,
    nameserver: Optional[str] = None,
    resolver_type: str = "system",
    timeout: int = 10
) -> Dict:
    """
    Check if domain has wildcard DNS entries by testing random subdomains
    
    Important for identifying:
    - Catch-all DNS configurations
    - Potential phishing infrastructure 
    - CDN/hosting wildcard setups
    - Subdomain takeover risks
    
    Args:
        domain: Domain to test for wildcards
        test_count: Number of random subdomains to test (default from config)
        nameserver: Custom nameserver IP (optional)
        resolver_type: Predefined resolver type
        timeout: Query timeout in seconds
        
    Returns:
        Dictionary with wildcard analysis and security implications
    """
    # Use config default if not specified
    if test_count is None:
        test_count = config.default_wildcard_test_count
    
    # Validate test count
    test_count = config.validate_wildcard_count(test_count)
    resolver = create_resolver(
        nameserver=nameserver,
        resolver_type=resolver_type,
        timeout=float(timeout)
    )
    
    start_time = time.time()
    
    # Generate random subdomains (very unlikely to exist legitimately)
    test_subdomains = []
    for _ in range(test_count):
        random_subdomain = ''.join(secrets.choice(
            string.ascii_lowercase + string.digits
        ) for _ in range(config.wildcard_subdomain_length))
        test_subdomains.append(f"{random_subdomain}.{domain}")
    
    # Test both A and CNAME records for each subdomain
    wildcard_results = {}
    test_results = []
    
    async def test_subdomain(test_domain: str, record_type: str) -> Dict:
        """Test a single subdomain for a specific record type"""
        try:
            query_start = time.time()
            records = await resolver.query(test_domain, record_type)
            query_time = time.time() - query_start
            
            return {
                "test_domain": test_domain,
                "record_type": record_type,
                "has_wildcard": True,
                "records": records,
                "record_count": len(records),
                "query_time_seconds": round(query_time, 3)
            }
            
        except Exception as e:
            query_time = time.time() - query_start if 'query_start' in locals() else 0
            
            return {
                "test_domain": test_domain,
                "record_type": record_type,
                "has_wildcard": False,
                "query_time_seconds": round(query_time, 3),
                "error": format_error_response(
                    e,
                    context={
                        "domain": test_domain,
                        "record_type": record_type,
                        "operation": "wildcard_test"
                    }
                )
            }
    
    # Create tasks for concurrent testing
    tasks = []
    for test_domain in test_subdomains:
        for record_type in ["A", "CNAME"]:
            tasks.append(test_subdomain(test_domain, record_type))
    
    # Execute all tests concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Process results
    wildcard_detected = {"A": False, "CNAME": False}
    wildcard_records = {"A": set(), "CNAME": set()}
    
    for result in results:
        if isinstance(result, Exception):
            continue
            
        test_results.append(result)
        
        if result.get("has_wildcard", False):
            record_type = result["record_type"]
            wildcard_detected[record_type] = True
            
            # Collect all wildcard records for pattern analysis
            for record in result.get("records", []):
                wildcard_records[record_type].add(record)
    
    has_any_wildcard = any(wildcard_detected.values())
    total_time = time.time() - start_time
    
    # Analyze wildcard patterns
    wildcard_analysis = {}
    for record_type, detected in wildcard_detected.items():
        if detected:
            records_list = list(wildcard_records[record_type])
            wildcard_analysis[record_type] = {
                "detected": True,
                "unique_records": records_list,
                "record_count": len(records_list),
                "pattern_analysis": {
                    "single_target": len(records_list) == 1,
                    "multiple_targets": len(records_list) > 1
                }
            }
        else:
            wildcard_analysis[record_type] = {"detected": False}
    
    # OSINT and Security Analysis
    risk_level = "LOW"
    security_implications = []
    
    if has_any_wildcard:
        risk_level = "MEDIUM"
        security_implications.extend([
            "All subdomains resolve to same target",
            "Potential for subdomain confusion attacks",
            "May indicate shared hosting environment"
        ])
        
        # Higher risk if multiple different targets
        if any(len(wildcard_records[rt]) > 1 for rt in wildcard_records):
            risk_level = "HIGH"
            security_implications.append("Multiple wildcard targets - unusual configuration")
        
        # Check for common CDN/hosting patterns
        all_records = set()
        for record_set in wildcard_records.values():
            all_records.update(record_set)
        
        has_cdn_pattern = any(
            is_cdn_related(record) 
            for record in all_records
        )
        
        if has_cdn_pattern:
            security_implications.append("CDN/hosting wildcard detected - likely legitimate")
            risk_level = "LOW" if risk_level == "MEDIUM" else risk_level
    else:
        security_implications.append("No wildcard DNS detected - specific subdomain configuration")
    
    return {
        "domain": domain,
        "test_subdomains": test_subdomains,
        "test_count": test_count,
        "has_wildcard": has_any_wildcard,
        "wildcard_analysis": wildcard_analysis,
        "total_query_time_seconds": round(total_time, 3),
        "resolver_info": {
            "resolver_id": resolver.resolver_id,
            "nameserver": nameserver,
            "resolver_type": resolver_type
        },
        "test_results": test_results,
        "osint_insights": {
            "risk_level": risk_level,
            "security_implications": security_implications,
            "investigation_notes": [
                "Wildcard DNS can be legitimate (CDN/hosting) or suspicious (phishing)",
                "Check domain registration age and reputation",
                "Monitor for suspicious subdomain creation patterns",
                "Verify wildcard targets against known good infrastructure"
            ]
        }
    }
    
@mcp.tool()
async def dns_response_analysis(
    domain: str,
    iterations: int = None,
    record_type: str = "A", 
    nameserver: Optional[str] = None,
    resolver_type: str = "system",
    timeout: int = 10
) -> Dict:
    """
    Analyze DNS response times for anomaly detection
    
    Useful for identifying:
    - DDoS protection triggers
    - Rate limiting
    - Network filtering
    - Infrastructure health issues
    
    Args:
        domain: Domain name to analyze
        iterations: Number of queries to perform (default from config)
        record_type: DNS record type to query
        nameserver: Custom nameserver IP (optional)
        resolver_type: Predefined resolver type
        timeout: Query timeout in seconds
        
    Returns:
        Dictionary with response time analysis and anomaly detection
    """
    # Use config default if not specified
    if iterations is None:
        iterations = config.default_propagation_iterations
    resolver = create_resolver(
        nameserver=nameserver,
        resolver_type=resolver_type,
        timeout=float(timeout)
    )
    
    start_time = time.time()
    response_times = []
    errors = []
    successful_queries = 0
    
    for i in range(iterations):
        iteration_start = time.time()
        
        try:
            records = await resolver.query(domain, record_type.upper())
            response_time = time.time() - iteration_start
            response_times.append(response_time)
            successful_queries += 1
            
        except Exception as e:
            response_time = time.time() - iteration_start
            errors.append({
                "iteration": i + 1,
                "query_time_seconds": round(response_time, 3),
                "error": format_error_response(
                    e,
                    context={
                        "domain": domain,
                        "record_type": record_type,
                        "iteration": i + 1,
                        "resolver": resolver.resolver_id
                    }
                )
            })
        
        # Small delay to avoid overwhelming the resolver
        if i < iterations - 1:  # Don't delay after the last iteration
            await asyncio.sleep(config.default_bulk_delay)
    
    total_time = time.time() - start_time
    
    # Calculate response time statistics
    analysis = {}
    if response_times:
        analysis = {
            "min_time": round(min(response_times), 4),
            "max_time": round(max(response_times), 4),
            "avg_time": round(statistics.mean(response_times), 4),
            "median_time": round(statistics.median(response_times), 4)
        }
        
        if len(response_times) > 1:
            analysis["std_dev"] = round(statistics.stdev(response_times), 4)
            
            # Detect anomalies (times > threshold from config)
            mean = statistics.mean(response_times)
            std_dev = statistics.stdev(response_times)
            threshold = mean + (config.anomaly_threshold_multiplier * std_dev)
            
            anomalous_times = [
                round(t, 4) for t in response_times 
                if t > threshold
            ]
            
            analysis["anomalous_times"] = anomalous_times
            analysis["anomaly_count"] = len(anomalous_times)
            analysis["anomaly_threshold"] = round(threshold, 4)
    
    # Performance and anomaly assessment
    performance_rating = get_performance_rating(analysis.get("avg_time", 0)) if analysis else "UNKNOWN"
    
    # Calculate failure rate
    failure_rate = len(errors) / iterations if iterations > 0 else 0
    
    # Detect potential issues
    potential_issues = []
    if failure_rate > config.high_failure_rate_threshold:
        potential_issues.append("High failure rate - possible blocking or filtering")
    
    if analysis.get("avg_time", 0) > config.performance_thresholds["poor"]:
        potential_issues.append("Very slow responses - infrastructure issues")
    
    if analysis.get("std_dev", 0) > config.high_variance_threshold:
        potential_issues.append("High response time variance - unstable performance")
    
    if analysis.get("anomaly_count", 0) > 0:
        potential_issues.append(f"Response time anomalies detected ({analysis['anomaly_count']} outliers)")
    
    if len(errors) > 0 and failure_rate < 1.0:
        potential_issues.append("Intermittent failures - possible rate limiting")
    
    if not potential_issues:
        potential_issues.append("No significant issues detected")
    
    return {
        "domain": domain,
        "record_type": record_type.upper(),
        "iterations": iterations,
        "successful_queries": successful_queries,
        "failed_queries": len(errors),
        "failure_rate": round(failure_rate, 3),
        "total_analysis_time_seconds": round(total_time, 3),
        "response_time_analysis": analysis,
        "errors": errors,
        "resolver_info": {
            "resolver_id": resolver.resolver_id,
            "nameserver": nameserver,
            "resolver_type": resolver_type
        },
        "osint_insights": {
            "performance_rating": performance_rating,
            "anomaly_detection": "DETECTED" if analysis.get("anomaly_count", 0) > 0 else "NONE",
            "potential_issues": potential_issues,
            "investigation_tips": [
                "Compare response times across different resolvers",
                "Test from different network locations if possible", 
                "Monitor for patterns in failure timing",
                "Check if anomalies correlate with specific query types"
            ]
        }
    }
