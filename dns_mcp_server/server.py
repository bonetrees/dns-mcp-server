#!/usr/bin/env python3
"""
Main FastMCP server with plugin-style modular architecture
Imports tool modules to trigger registration with the shared mcp instance
"""

from fastmcp import FastMCP

# Create the main FastMCP instance
mcp = FastMCP("DNS OSINT Server")

# Import tool modules to register their functions with the mcp instance
# This plugin-style architecture automatically registers all @mcp.tool() decorated functions
from . import core_tools      # Basic async DNS tools (dns_query, dns_reverse_lookup, dns_query_all)
from . import bulk_tools      # Async bulk operations (dns_bulk_query, dns_bulk_reverse_lookup)


def main():
    """Main entry point for the DNS MCP server"""
    mcp.run()


if __name__ == "__main__":
    main()
