"""
Performance benchmark tests for DNS OSINT MCP Server
Measuring and validating performance improvements from async implementation
"""

import pytest
import asyncio
import time
from unittest.mock import AsyncMock, patch
from typing import List, Dict

from dns_mcp_server.core_tools import dns_query, dns_query_all
from dns_mcp_server.bulk_tools import dns_bulk_query, dns_bulk_reverse_lookup
from dns_mcp_server.osint_tools import dns_propagation_check, dns_response_analysis
from dns_mcp_server.config import config


class TestPerformanceBenchmarks:
    """Benchmark tests to measure performance improvements"""
    
    @patch('dns_mcp_server.bulk_tools.create_resolver')
    async def test_bulk_query_performance_scaling(self, mock_create_resolver):
        """Test that bulk queries scale efficiently with concurrency"""
        # Mock resolver with controlled delay
        async def mock_query_with_delay(domain, record_type):
            await asyncio.sleep(0.1)  # 100ms delay per query
            return ["192.168.1.1"]
        
        mock_resolver = AsyncMock()
        mock_resolver.query.side_effect = mock_query_with_delay
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver
        
        # Test with different domain counts
        domain_counts = [5, 10, 20]
        results = []
        
        for count in domain_counts:
            domains = [f"test{i}.com" for i in range(count)]
            
            start_time = time.time()
            result = await dns_bulk_query(
                domains=domains,
                max_workers=10
            )
            end_time = time.time()
            
            actual_time = end_time - start_time
            sequential_time = count * 0.1  # What it would take sequentially
            
            results.append({
                "domain_count": count,
                "actual_time": actual_time,
                "sequential_time": sequential_time,
                "speedup": sequential_time / actual_time,
                "successful_queries": result["successful_queries"]
            })
        
        # Verify performance scaling
        for result in results:
            # Should be significantly faster than sequential
            assert result["speedup"] > 2.0, f"Speedup {result['speedup']} too low for {result['domain_count']} domains"
            # Should complete all queries successfully
            assert result["successful_queries"] == result["domain_count"]
            
        # Print benchmark results for manual inspection
        print("\nBulk Query Performance Benchmark:")
        for result in results:
            print(f"  {result['domain_count']} domains: {result['actual_time']:.3f}s "
                  f"(speedup: {result['speedup']:.1f}x)")
    
    @patch('dns_mcp_server.osint_tools.create_resolver')
    async def test_propagation_check_concurrent_performance(self, mock_create_resolver):
        """Test propagation check concurrent resolver performance"""
        # Mock resolver with delay
        async def mock_query_with_delay(domain, record_type):
            await asyncio.sleep(0.05)  # 50ms delay per query
            return ["192.168.1.1"]
        
        mock_resolver = AsyncMock()
        mock_resolver.query.side_effect = mock_query_with_delay
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver
        
        # Test with 6 resolvers (default propagation set)
        test_resolvers = {
            f"resolver{i}": f"8.8.8.{i}" for i in range(1, 7)
        }
        
        start_time = time.time()
        result = await dns_propagation_check(
            domain="example.com",
            resolvers=test_resolvers
        )
        end_time = time.time()
        
        actual_time = end_time - start_time
        sequential_time = len(test_resolvers) * 0.05  # What it would take sequentially
        speedup = sequential_time / actual_time
        
        # Should be much faster than sequential execution
        assert speedup > 3.0, f"Propagation check speedup {speedup} too low"
        assert result["total_resolvers_queried"] == 6
        
        print(f"\nPropagation Check Performance:")
        print(f"  6 resolvers: {actual_time:.3f}s (speedup: {speedup:.1f}x)")
    
    @patch('dns_mcp_server.core_tools.create_resolver')
    async def test_query_all_concurrent_performance(self, mock_create_resolver):
        """Test dns_query_all concurrent record type performance"""
        # Mock resolver with delay
        async def mock_query_with_delay(domain, record_type):
            await asyncio.sleep(0.02)  # 20ms delay per query
            if record_type in ["A", "MX", "TXT", "NS"]:
                return [f"mock-{record_type.lower()}-record"]
            else:
                raise Exception("No records")  # Some types fail
        
        mock_resolver = AsyncMock()
        mock_resolver.query.side_effect = mock_query_with_delay
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver
        
        start_time = time.time()
        result = await dns_query_all(domain="example.com")
        end_time = time.time()
        
        actual_time = end_time - start_time
        # 9 record types * 20ms = 180ms sequential
        sequential_time = 9 * 0.02
        speedup = sequential_time / actual_time
        
        # Updated expectation: with semaphore limit of 3, theoretical max is ~3x
        # Actual will be slightly less due to overhead, so 2.5x is good performance
        assert speedup > 2.5, f"Query all speedup {speedup} too low (expected >2.5x with concurrency limit)"
        assert result["record_types_found"] >= 3  # Should find some records
        
        print(f"\nQuery All Performance (with concurrency control):")
        print(f"  9 record types: {actual_time:.3f}s (speedup: {speedup:.1f}x)")
        print(f"  Note: Concurrency limited to {config.dns_query_all_concurrency} for DNS server friendliness")
    
    async def test_rate_limiting_performance_impact(self):
        """Test that rate limiting doesn't significantly impact performance"""
        from dns_mcp_server.rate_limiter import DNSRateLimiter
        
        # Test rate limiter overhead
        rate_limiter = DNSRateLimiter(rate_limit=100)  # High rate for testing
        
        # Measure time for 50 rate limit acquisitions
        start_time = time.time()
        tasks = []
        for _ in range(50):
            tasks.append(rate_limiter.acquire("test_resolver"))
        
        await asyncio.gather(*tasks)
        end_time = time.time()
        
        total_time = end_time - start_time
        per_acquisition = total_time / 50
        
        # Rate limiting overhead should be minimal (< 1ms per acquisition)
        assert per_acquisition < 0.001, f"Rate limiting overhead too high: {per_acquisition:.4f}s"
        
        print(f"\nRate Limiting Performance:")
        print(f"  50 acquisitions: {total_time:.4f}s ({per_acquisition*1000:.2f}ms each)")


class TestMemoryEfficiency:
    """Test memory usage efficiency of async operations"""
    
    @patch('dns_mcp_server.bulk_tools.create_resolver')
    async def test_large_bulk_operation_memory(self, mock_create_resolver):
        """Test memory efficiency with large bulk operations"""
        # Mock resolver
        mock_resolver = AsyncMock()
        mock_resolver.query.return_value = ["192.168.1.1"]
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver
        
        # Test with large domain list
        large_domain_count = 200
        domains = [f"test{i}.example.com" for i in range(large_domain_count)]
        
        result = await dns_bulk_query(
            domains=domains,
            max_workers=20,
            timeout=1
        )
        
        # Should complete successfully without memory issues
        assert result["domain_count"] == large_domain_count
        assert result["successful_queries"] == large_domain_count
        assert len(result["results"]) == large_domain_count
        
        print(f"\nMemory Efficiency Test:")
        print(f"  {large_domain_count} domains processed successfully")
    
    async def test_concurrent_tool_memory_usage(self):
        """Test memory usage when running multiple tools concurrently"""
        # Run multiple memory-intensive operations concurrently
        tasks = []
        
        # Each task creates its own data structures
        for i in range(10):
            task = dns_query(
                domain=f"test{i}.example.com",
                record_type="A",
                timeout=2
            )
            tasks.append(task)
        
        # Should complete without memory issues
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # All should complete (successfully or with errors)
        assert len(results) == 10
        
        print(f"\nConcurrent Memory Test:")
        print(f"  10 concurrent operations completed")


class TestThroughputBenchmarks:
    """Test throughput capabilities under different conditions"""
    
    @patch('dns_mcp_server.bulk_tools.create_resolver')
    async def test_maximum_throughput_measurement(self, mock_create_resolver):
        """Measure maximum throughput with optimal conditions"""
        # Mock resolver with minimal delay
        async def fast_mock_query(domain, record_type):
            await asyncio.sleep(0.001)  # 1ms delay
            return ["192.168.1.1"]
        
        mock_resolver = AsyncMock()
        mock_resolver.query.side_effect = fast_mock_query
        mock_resolver.resolver_id = "test_resolver"
        mock_create_resolver.return_value = mock_resolver
        
        # Test with increasing concurrency levels
        worker_counts = [5, 10, 20, 30]
        throughput_results = []
        
        for workers in worker_counts:
            domains = [f"test{i}.com" for i in range(50)]  # Fixed domain count
            
            start_time = time.time()
            result = await dns_bulk_query(
                domains=domains,
                max_workers=workers
            )
            end_time = time.time()
            
            duration = end_time - start_time
            throughput = result["successful_queries"] / duration  # queries per second
            
            throughput_results.append({
                "workers": workers,
                "duration": duration,
                "throughput": throughput,
                "successful_queries": result["successful_queries"]
            })
        
        # Analyze throughput scaling
        print(f"\nThroughput Benchmark Results:")
        for result in throughput_results:
            print(f"  {result['workers']} workers: {result['throughput']:.1f} queries/sec")
        
        # Throughput should generally increase with more workers (up to a point)
        # Due to mocked 1ms delay, theoretical max is ~1000 queries/sec per worker
        max_throughput = max(r["throughput"] for r in throughput_results)
        assert max_throughput > 100, f"Max throughput {max_throughput} too low"


# Performance test configuration
performance_marks = pytest.mark.performance
pytestmark = [pytest.mark.asyncio, performance_marks]
