"""
DNS OSINT MCP Server
Comprehensive DNS reconnaissance tools for threat intelligence and OSINT investigations
"""

__version__ = "0.1.0"
__author__ = "Your Name"
__email__ = "your.email@example.com"

from .server import main, mcp

__all__ = ["mcp", "main"]
