"""STIXGEN MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from stixgen.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-stixgen[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-stixgen[mcp]'")
        return 1
    app = FastMCP("stixgen")

    @app.tool()
    def stixgen_scan(target: str) -> str:
        """Build STIX 2.1 bundles from a list of IOCs/observables. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
