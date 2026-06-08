"""STIXGEN — build STIX 2.1 bundles from a list of IOCs/observables.

Defensive intel-sharing tool. Takes IOCs you already own/observed (IPs, domains,
URLs, file hashes, emails, CVEs) and produces a clean, valid STIX 2.1 bundle so
the intel can be shared with partners and ingested by TIPs/SIEMs.

Standard library only. Zero install. No network.
"""
from .core import (
    IOC,
    classify_ioc,
    build_bundle,
    parse_iocs,
    summarize,
    render_html,
    STIXGenError,
)

TOOL_NAME = "stixgen"
TOOL_VERSION = "1.0.0"

__all__ = [
    "IOC",
    "classify_ioc",
    "build_bundle",
    "parse_iocs",
    "summarize",
    "render_html",
    "STIXGenError",
    "TOOL_NAME",
    "TOOL_VERSION",
]
