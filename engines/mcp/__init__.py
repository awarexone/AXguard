"""AXGuard Native MCP — AI-agent security interface over existing engines.

Local-first. No AwareXone cloud. Optional install: ``pip install 'axguard[mcp]'``.
"""

from __future__ import annotations

__all__ = ["__version__", "create_server", "serve_stdio", "TOOL_CATALOG"]
__version__ = "0.2.0"


def create_server(*args, **kwargs):
    from engines.mcp.server import create_server as _create

    return _create(*args, **kwargs)


def serve_stdio(*args, **kwargs) -> None:
    from engines.mcp.server import serve_stdio as _serve

    _serve(*args, **kwargs)


def TOOL_CATALOG():
    from engines.mcp.tools.catalog import TOOL_CATALOG as catalog

    return catalog
