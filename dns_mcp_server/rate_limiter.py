"""
Rate limiting utilities for DNS operations
Implements per-resolver rate limiting to prevent overwhelming DNS servers
"""

from asyncio_throttle import Throttler


class DNSRateLimiter:
    """
    Per-resolver rate limiter for DNS operations
    Maintains separate throttlers for each resolver type
    """

    def __init__(self, rate_limit: int = 30):
        """
        Initialize rate limiter

        Args:
            rate_limit: Requests per second per resolver (default: 30)
        """
        self.rate_limit = rate_limit
        self._throttlers: dict[str, Throttler] = {}

    def get_throttler(self, resolver_type: str) -> Throttler:
        """
        Get or create throttler for resolver type

        Args:
            resolver_type: Resolver identifier (e.g., 'google', 'cloudflare')

        Returns:
            Throttler instance for the resolver
        """
        if resolver_type not in self._throttlers:
            self._throttlers[resolver_type] = Throttler(
                rate_limit=self.rate_limit,
                period=1.0,  # Per second
            )
        return self._throttlers[resolver_type]

    async def acquire(self, resolver_type: str):
        """
        Acquire rate limit token for resolver

        Args:
            resolver_type: Resolver identifier
        """
        throttler = self.get_throttler(resolver_type)
        async with throttler:
            pass  # Token acquired and released automatically

    def get_stats(self) -> dict[str, dict]:
        """
        Get rate limiting statistics for all resolvers

        Returns:
            Dictionary with stats per resolver
        """
        stats = {}
        for resolver_type, throttler in self._throttlers.items():
            stats[resolver_type] = {
                "rate_limit": self.rate_limit,
                "current_tokens": getattr(throttler, "_tokens", "unknown"),
                "active": bool(self._throttlers.get(resolver_type)),
            }
        return stats


# Global rate limiter instance
dns_rate_limiter = DNSRateLimiter(rate_limit=30)
