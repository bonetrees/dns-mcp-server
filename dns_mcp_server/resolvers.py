"""
Async DNS resolver configuration and management
Supports multiple resolver types with aiodns for async operations
"""

import asyncio
from typing import Optional, List
import aiodns
import dns.resolver
from .rate_limiter import dns_rate_limiter


# Resolver configurations
RESOLVER_CONFIGS = {
    "public": ["8.8.8.8", "1.1.1.1", "9.9.9.9"],
    "google": ["8.8.8.8", "8.8.4.4"],
    "cloudflare": ["1.1.1.1", "1.0.0.1"],
    "quad9": ["9.9.9.9", "149.112.112.112"],
    "opendns": ["208.67.222.222", "208.67.220.220"]
}


class AsyncDNSResolver:
    """
    Async DNS resolver with rate limiting and multiple resolver support
    """
    
    def __init__(
        self, 
        nameservers: Optional[List[str]] = None,
        resolver_type: str = "system",
        timeout: float = 10.0
    ):
        """
        Initialize async DNS resolver
        
        Args:
            nameservers: Custom nameserver IPs (overrides resolver_type)
            resolver_type: Predefined resolver type or "system"
            timeout: Query timeout in seconds
        """
        self.resolver_type = resolver_type
        self.timeout = timeout
        
        # Create aiodns resolver
        self.resolver = aiodns.DNSResolver(timeout=timeout)
        
        # Configure nameservers
        if nameservers:
            self.resolver.nameservers = nameservers
            self.resolver_id = f"custom-{'-'.join(nameservers[:2])}"
        elif resolver_type in RESOLVER_CONFIGS:
            self.resolver.nameservers = RESOLVER_CONFIGS[resolver_type]
            self.resolver_id = resolver_type
        else:
            # Use system default resolvers
            self.resolver_id = "system"
    
    async def query(self, domain: str, record_type: str) -> List[str]:
        """
        Perform rate-limited async DNS query
        
        Args:
            domain: Domain to query
            record_type: DNS record type (A, AAAA, MX, etc.)
            
        Returns:
            List of formatted DNS records
            
        Raises:
            Various aiodns exceptions for DNS errors
        """
        # Apply rate limiting
        await dns_rate_limiter.acquire(self.resolver_id)
        
        # Map record types to aiodns query types
        query_type_map = {
            'A': 'A',
            'AAAA': 'AAAA', 
            'MX': 'MX',
            'TXT': 'TXT',
            'NS': 'NS',
            'SOA': 'SOA',
            'CNAME': 'CNAME',
            'CAA': 'CAA',
            'SRV': 'SRV',
            'PTR': 'PTR'
        }
        
        aiodns_type = query_type_map.get(record_type.upper())
        if not aiodns_type:
            raise ValueError(f"Unsupported record type: {record_type}")
        
        # Perform async DNS query
        try:
            result = await self.resolver.query(domain, aiodns_type)
            
            # Format results based on record type
            if isinstance(result, list):
                return [self._format_record(record_type.upper(), record) for record in result]
            else:
                return [self._format_record(record_type.upper(), result)]
                
        except Exception as e:
            # Re-raise with consistent error types for handling
            raise e
    
    def _format_record(self, record_type: str, record) -> str:
        """
        Format DNS record based on type
        
        Args:
            record_type: DNS record type
            record: Raw DNS record from aiodns
            
        Returns:
            Formatted record string
        """
        if record_type == "MX":
            return f"{record.priority} {record.host}"
        elif record_type == "SOA":
            return f"{record.mname} {record.rname} {record.serial} {record.refresh} {record.retry} {record.expire} {record.minimum}"
        elif record_type == "TXT":
            # Handle TXT records which can be bytes or strings
            if hasattr(record, 'text'):
                text = record.text
                if isinstance(text, bytes):
                    return text.decode('utf-8', errors='replace')
                return str(text)
            return str(record)
        elif record_type == "SRV":
            return f"{record.priority} {record.weight} {record.port} {record.target}"
        elif record_type == "CAA":
            return f"{record.flags} {record.tag} {record.value}"
        elif record_type == "NS":
            return str(record.host if hasattr(record, 'host') else record)
        else:
            # Default formatting for A, AAAA, CNAME, PTR
            if hasattr(record, 'host'):
                return str(record.host)
            elif hasattr(record, 'name'):
                return str(record.name)
            else:
                return str(record)


def create_resolver(
    nameserver: Optional[str] = None,
    resolver_type: str = "system", 
    timeout: float = 10.0
) -> AsyncDNSResolver:
    """
    Factory function to create async DNS resolver
    
    Args:
        nameserver: Custom nameserver IP (overrides resolver_type)
        resolver_type: Predefined resolver type
        timeout: Query timeout in seconds
        
    Returns:
        Configured AsyncDNSResolver instance
    """
    nameservers = [nameserver] if nameserver else None
    return AsyncDNSResolver(
        nameservers=nameservers,
        resolver_type=resolver_type,
        timeout=timeout
    )
