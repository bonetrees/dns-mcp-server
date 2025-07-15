# DNS OSINT MCP Server

A comprehensive DNS reconnaissance toolkit built as an MCP server for threat intelligence and OSINT investigations. Provides powerful DNS querying capabilities with support for multiple resolvers and concurrent operations.

## 🚀 Features

### Core DNS Tools
- **dns_query**: Query specific DNS record types (A, AAAA, MX, TXT, NS, SOA, CNAME, CAA, SRV, PTR)
- **dns_reverse_lookup**: Reverse DNS (PTR) lookups for IP addresses
- **dns_bulk_query**: Efficient bulk queries for multiple domains
- **dns_query_all**: Comprehensive domain profiling with concurrent queries of all record types

### Advanced Capabilities
- **Multiple Resolver Support**: System, public, Google, Cloudflare, Quad9, OpenDNS, or custom resolvers
- **Concurrent Operations**: Fast parallel queries for comprehensive domain analysis
- **Intelligent Error Handling**: Detailed DNS exception handling with actionable intelligence
- **OSINT-Focused**: Designed specifically for threat actor infrastructure mapping and analysis

## 📋 Prerequisites

- Python 3.9+
- Poetry for dependency management

## 🛠️ Installation

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

## 🔧 Configuration

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

## 🕵️ OSINT Use Cases

### Threat Actor Infrastructure Mapping
```python
# Comprehensive domain profiling
dns_query_all(domain="suspicious.example.com", resolver_type="public")

# Compare results across resolvers
dns_query(domain="malware.example.com", resolver_type="system")
dns_query(domain="malware.example.com", resolver_type="public")
```

### Bulk Domain Analysis
```python
# Analyze multiple suspicious domains
dns_bulk_query(
    domains=["domain1.com", "domain2.com", "domain3.com"],
    record_type="A",
    resolver_type="cloudflare"
)
```

### Infrastructure Reconnaissance
```python
# Reverse lookup for IP ranges
dns_reverse_lookup(ip="192.168.1.1", resolver_type="quad9")

# Mail server analysis
dns_query(domain="target.com", record_type="MX", resolver_type="google")
```

## 🌐 Resolver Types

- **system**: Use system default resolvers
- **public**: Multi-resolver approach (8.8.8.8, 1.1.1.1, 9.9.9.9)
- **google**: Google DNS (8.8.8.8, 8.8.4.4)
- **cloudflare**: Cloudflare DNS (1.1.1.1, 1.0.0.1)
- **quad9**: Quad9 DNS (9.9.9.9, 149.112.112.112)
- **opendns**: OpenDNS (208.67.222.222, 208.67.220.220)
- **custom**: Specify custom nameserver IP

## 📊 DNS Record Types Supported

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

## 🔍 Example Responses

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

## 🛡️ Security & Ethics

This tool is designed for legitimate security research, threat intelligence, and OSINT investigations. Always ensure you have proper authorization before conducting reconnaissance activities.

## 🚧 Development

### Running Tests
```bash
poetry run pytest
```

### Code Formatting
```bash
poetry run black .
poetry run isort .
```

## 📈 Future Enhancements

- [ ] Subdomain enumeration capabilities
- [ ] DNS zone transfer attempts
- [ ] Certificate transparency integration
- [ ] Historical DNS data analysis
- [ ] Advanced correlation features
- [ ] Export capabilities (JSON, CSV)

## 📄 License

This project is open source and available under the MIT License.

---

**Happy OSINT hunting!** 🕵️‍♂️🔍
