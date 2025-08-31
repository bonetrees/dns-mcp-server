# DNS OSINT MCP Server

A DNS reconnaissance toolkit built as an MCP server for threat intelligence and OSINT investigations. Provides DNS querying capabilities with support for multiple resolvers and concurrent operations.

## Features

### Core DNS Tools
- **dns_query**: Query specific DNS record types (A, AAAA, MX, TXT, NS, SOA, CNAME, CAA, SRV, PTR)
- **dns_reverse_lookup**: Reverse DNS (PTR) lookups for IP addresses
- **dns_bulk_query**: Concurrent bulk queries for multiple domains
- **dns_bulk_reverse_lookup**: Concurrent reverse DNS lookups for multiple IPs
- **dns_query_all**: Comprehensive domain profiling with concurrent queries of all record types

### OSINT Analysis Tools
- **dns_propagation_check**: Detect DNS inconsistencies across multiple resolvers
- **dns_wildcard_check**: Identify wildcard DNS configurations and security risks
- **dns_response_analysis**: Analyze response times for anomaly detection

### Advanced Capabilities
- **Async Performance**: High-speed concurrent operations with rate limiting (3-5x faster than sequential)
- **Multiple Resolver Support**: System, public, Google, Cloudflare, Quad9, OpenDNS, or custom resolvers
- **Per-Resolver Rate Limiting**: 30 requests/second per resolver to prevent abuse
- **OSINT-Focused Error Handling**: Detailed DNS exception analysis with actionable intelligence
- **Threat Intelligence Features**: Designed for threat actor infrastructure mapping and analysis
- **Centralized Configuration**: Robust parameter validation and configurable defaults
- **Comprehensive Testing**: 90%+ test coverage with edge cases, performance benchmarks, and real-world scenarios

## Prerequisites

- Python 3.10+
- Poetry for dependency management

## Architecture

```
dns_mcp_server/
├── server.py           # FastMCP server with plugin architecture
├── config.py           # Centralized configuration management
├── resolvers.py        # Async DNS resolvers with aiodns
├── rate_limiter.py     # Per-resolver rate limiting
├── formatters.py       # OSINT-aware error formatting
├── core_tools.py       # Basic DNS query tools
├── bulk_tools.py       # High-performance bulk operations
└── osint_tools.py      # Advanced OSINT analysis tools

tests/
├── test_config.py      # Configuration validation tests
├── test_edge_cases.py  # Error resilience & edge cases
├── test_performance.py # Performance benchmarks
├── test_osint_tools.py # OSINT tool functionality
└── test_async_dns.py   # Async DNS operations
```

**Key Design Principles:**
- **Plugin Architecture**: Tools auto-register with FastMCP server
- **Async-First**: All DNS operations use asyncio for maximum performance
- **Rate Limited**: Per-resolver throttling prevents abuse
- **OSINT-Focused**: Error messages include threat intelligence context
- **Highly Testable**: Comprehensive mocking and integration tests

## Installation

1. **Clone and setup the repository:**
```bash
cd /path/to/dns-mcp-server
poetry install
```

2. **Run the server:**
```bash
# Using Poetry (recommended)
poetry run dns-mcp-server

# Or using Python module
python -m dns_mcp_server

# Or with Poetry
poetry run python -m dns_mcp_server
```

## Configuration

Add to your Claude MCP settings:

```json
{
  "mcpServers": {
    "dns-osint": {
      "command": "poetry",
      "args": ["run", "dns-mcp-server"],
      "cwd": "/path/to/dns-mcp-server"
    }
  }
}
```
- Note: You may need to add full paths to `poetry` and `dns-mcp-server`
- Note: You may need to point poetry directly to your project folder file like:
  `"args": ["run","-C", "/path/to/dns-mcp-server","python", "-m", "dns_mcp_server"]`
## OSINT Use Cases

### Threat Actor Infrastructure Mapping
```python
# Comprehensive domain profiling
dns_query_all(domain="suspicious.example.com", resolver_type="public")

# Check DNS consistency across resolvers
dns_propagation_check(domain="malware.example.com", record_type="A")

# Analyze response patterns
dns_response_analysis(domain="c2.example.com", iterations=15)
```

### Phishing and Malware Analysis
```python
# Detect wildcard DNS (common in phishing kits)
dns_wildcard_check(domain="phishing.example.com", test_count=5)

# Compare results across resolvers to detect DNS poisoning
dns_propagation_check(
    domain="suspicious.example.com",
    resolvers={"google": "8.8.8.8", "cloudflare": "1.1.1.1", "quad9": "9.9.9.9"}
)
```

### Infrastructure Reconnaissance 
```python
# Bulk domain analysis
dns_bulk_query(
    domains=["domain1.com", "domain2.com", "domain3.com"],
    record_type="A",
    resolver_type="cloudflare",
    max_workers=10
)

# Reverse lookup for IP ranges
dns_bulk_reverse_lookup(
    ips=["192.168.1.1", "192.168.1.2", "192.168.1.3"],
    resolver_type="quad9"
)

# Mail server analysis
dns_query(domain="target.com", record_type="MX", resolver_type="google")
```

### DNS Security Assessment
```python
# Check for DNS inconsistencies (potential security issues)
result = dns_propagation_check(domain="company.com")
if not result["is_consistent"]:
    print("WARNING: DNS inconsistency detected!")
    print(f"Trust level: {result['osint_analysis']['trust_level']}")

# Wildcard detection for subdomain security
wildcard_result = dns_wildcard_check(domain="company.com")
if wildcard_result["has_wildcard"]:
    risk = wildcard_result["osint_insights"]["risk_level"]
    print(f"Wildcard DNS detected - Risk level: {risk}")
```

## Resolver Types

- **system**: Use system default resolvers
- **public**: Multi-resolver approach (8.8.8.8, 1.1.1.1, 9.9.9.9)
- **google**: Google DNS (8.8.8.8, 8.8.4.4)
- **cloudflare**: Cloudflare DNS (1.1.1.1, 1.0.0.1)
- **quad9**: Quad9 DNS (9.9.9.9, 149.112.112.112)
- **opendns**: OpenDNS (208.67.222.222, 208.67.220.220)
- **custom**: Specify custom nameserver IP

## DNS Record Types Supported

- **A**: IPv4 addresses
- **AAAA**: IPv6 addresses  
- **MX**: Mail exchange servers
- **TXT**: Text records (SPF, DKIM, verification)
- **NS**: Nameservers
- **SOA**: Start of authority
- **CNAME**: Canonical names
- **CAA**: Certificate authority authorization
- **SRV**: Service records
- **PTR**: Reverse DNS records

## Example Responses

### Single Query Response
```json
{
  "domain": "example.com",
  "record_type": "A",
  "nameserver": "cloudflare",
  "query_time_seconds": 0.045,
  "records": ["93.184.216.34"],
  "record_count": 1
}
```

### Comprehensive Domain Profile
```json
{
  "domain": "example.com",
  "nameserver": "public",
  "total_query_time_seconds": 0.234,
  "records": {
    "A": ["93.184.216.34"],
    "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
    "MX": ["10 mail.example.com"],
    "TXT": ["v=spf1 include:_spf.example.com ~all"],
    "NS": ["ns1.example.com", "ns2.example.com"]
  },
  "record_types_found": 5,
  "total_records": 6,
  "errors": {
    "CAA": {"error": "no_records", "type": "NoAnswer"}
  }
}
```

## Security & Ethics

This tool is designed for legitimate security research, threat intelligence, and OSINT investigations. Always ensure you have proper authorization before conducting reconnaissance activities.

## Development

### Enhanced Testing Framework
The project includes comprehensive testing with multiple categories:

```bash
# Run all tests
poetry run pytest

# Or use the enhanced test runner
python test_runner.py all

# Test specific categories
python test_runner.py config      # Configuration tests
python test_runner.py edge        # Edge cases and error resilience
python test_runner.py performance # Performance benchmarks
python test_runner.py osint       # OSINT tool tests
python test_runner.py integration # Network-dependent tests
```

### Phase Integration Tests
```bash
# Test Phase 1: Async performance improvements
python test_runner.py async

# Test Phase 2: OSINT analysis tools
python test_runner.py phase2

# Test Phase 3: Code organization & testing
python test_runner.py phase3
```

### Configuration Management
The server uses centralized configuration for all settings:

```python
from dns_mcp_server.config import config

# Default settings
print(f"Rate limit: {config.default_rate_limit}/sec")
print(f"Timeout: {config.default_timeout}s")
print(f"Max workers: {config.default_max_workers}")

# Validation functions
from dns_mcp_server.config import validate_record_type, get_performance_rating

# Automatic validation and clamping
record_type = validate_record_type("a")  # Returns "A"
rating = get_performance_rating(0.05)    # Returns "EXCELLENT"
```

### Code Formatting
```bash
poetry run black .
poetry run isort .
```

## Completed Enhancements

- **Async Performance Optimization**: 5-10x faster bulk queries with concurrent execution
- **OSINT Analysis Tools**: DNS propagation check, wildcard detection, response time analysis
- **Enhanced Error Handling**: OSINT-aware error messages with investigation tips
- **Centralized Configuration**: Robust parameter validation and configurable defaults
- **Comprehensive Testing**: 90%+ test coverage with performance benchmarks
- **Per-Resolver Rate Limiting**: Prevents DNS server abuse and blocking
- **Professional Code Organization**: Modular architecture with proper documentation

## Future Enhancements

### TODO: DNS Walking & Subdomain Discovery
*Added during pair programming session - August 19, 2025*

- [ ] **Dictionary-Based Subdomain Enumeration**: Brute force common subdomains using wordlists
  ```python
  dns_subdomain_walk(domain="target.com", wordlist=["www", "mail", "api"], max_workers=50)
  ```

- [ ] **Certificate Transparency Integration**: Discover subdomains via CT logs
  ```python  
  dns_ct_subdomain_search(domain="target.com")  # Passive subdomain discovery
  ```

- [ ] **DNS Zone Transfer Attempts**: Try AXFR/IXFR zone transfers
  ```python
  dns_zone_transfer(domain="target.com")  # Attempt zone transfer
  ```

- [ ] **Passive DNS Database Queries**: Integration with passive DNS sources
  ```python
  dns_passive_lookup(domain="target.com")  # Historical DNS data
  ```

### Current Roadmap
- [ ] Subdomain enumeration capabilities *(see DNS Walking section above)*
- [ ] DNS zone transfer attempts *(see DNS Walking section above)*
- [ ] Certificate transparency integration *(see DNS Walking section above)*
- [ ] Historical DNS data analysis
- [ ] Advanced correlation features
- [ ] Export capabilities (JSON, CSV)
- [ ] Web dashboard interface
- [ ] Machine learning-based anomaly detection

## License

This project is open source and available under the MIT License.

---

**Happy OSINT hunting!**
