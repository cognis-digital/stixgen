"""STIXGEN MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import sys

from stixgen.core import STIXGenError, scan, to_json


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-stixgen[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("Install the MCP extra: pip install 'cognis-stixgen[mcp]'",
              file=sys.stderr)
        return 1
    app = FastMCP("stixgen")

    @app.tool()
    def stixgen_scan(target: str) -> str:
        """Build STIX 2.1 bundles from a list of IOCs/observables. Returns JSON findings."""
        if not target or not target.strip():
            return to_json({"error": "target must be a non-empty string"})
        try:
            return to_json(scan(target))
        except STIXGenError as exc:
            return to_json({"error": str(exc)})

    app.run()
    return 0
