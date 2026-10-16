"""Fallback adapters for generic JSON, forms, multipart, and text HTTP traffic."""
from normalization.adapters.generic.http import (
    GenericHTTPAdapter,
    sanitize_structured,
    summarize_http_body,
)

__all__ = ["GenericHTTPAdapter", "sanitize_structured", "summarize_http_body"]
