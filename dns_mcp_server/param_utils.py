"""
Fix for FastMCP integer parameter validation issues.
This module provides workarounds for known FastMCP parameter type handling issues.
"""

from typing import Any, Union


def ensure_int(value: Any) -> Union[int, None]:
    """
    Ensure a value is converted to int or None.
    Works around FastMCP parameter validation issues.
    
    Args:
        value: Value to convert (can be str, int, or None)
        
    Returns:
        int or None
    """
    if value is None:
        return None
    
    # Handle string representation of integers
    if isinstance(value, str):
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
    
    # Already an integer
    if isinstance(value, int):
        return value
    
    # Try to convert other types
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def validate_optional_int(value: Any, default: int = None) -> Union[int, None]:
    """
    Validate and convert an optional integer parameter.
    
    Args:
        value: Value to validate
        default: Default value if conversion fails
        
    Returns:
        Validated integer or default
    """
    result = ensure_int(value)
    return result if result is not None else default
