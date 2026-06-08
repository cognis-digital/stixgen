"""Core engine for STIXGEN.

Classifies raw IOC strings, then emits STIX 2.1 Domain Objects (Indicators)
backed by SCO patterns, plus an Identity (the producer) and the wrapping Bundle.

Deterministic where it matters: object UUIDs are derived from the IOC value so
the same input always produces the same id (good for dedupe + diffing bundles).
"""
from __future__ import annotations

import hashlib
import html
import ipaddress
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


class STIXGenError(Exception):
    """Raised for malformed input or build failures."""


# Stable namespace so derived ids are reproducible across runs/machines.
_NS = uuid.UUID("e7c4f0a2-2b1d-4c3e-9f7a-1d2e3b4c5d6e")

# STIX 2.1 fixed values
_SPEC_VERSION = "2.1"

# Hash classification by hex length
_HASH_KINDS = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://\S+$")

# Severity weighting per IOC kind (analyst-tunable defaults).
_SEVERITY = {
    "url": "high",
    "file": "high",
    "ipv4-addr": "medium",
    "ipv6-addr": "medium",
    "domain-name": "medium",
    "email-addr": "medium",
    "vulnerability": "low",
}
_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "unknown": 0}


@dataclass
class IOC:
    """A single classified observable."""

    value: str
    kind: str  # stix SCO type, or 'vulnerability', or 'unknown'
    pattern: str = ""  # STIX pattern (empty for unknown)
    severity: str = "unknown"
    note: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def valid(self) -> bool:
        return self.kind != "unknown"


def _det_id(stix_type: str, value: str) -> str:
    """Deterministic STIX id: type--uuid5(value)."""
    u = uuid.uuid5(_NS, f"{stix_type}:{value.lower()}")
    return f"{stix_type}--{u}"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _esc_pattern(value: str) -> str:
    """Escape a value for embedding inside a STIX pattern single-quoted string."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def classify_ioc(raw: str) -> IOC:
    """Classify a single raw IOC string into a STIX-aware IOC.

    Order matters: CVE and URL before domain (a URL contains a domain).
    Defanged forms (hxxp, [.], (dot)) are refanged first — common in feeds.
    """
    value = raw.strip()
    if not value:
        return IOC(value=raw, kind="unknown", note="empty")

    refanged = _refang(value)
    q = _esc_pattern(refanged)

    # CVE / vulnerability
    if _CVE_RE.match(refanged):
        cve = refanged.upper()
        return IOC(
            value=cve,
            kind="vulnerability",
            pattern="",
            severity=_SEVERITY["vulnerability"],
            note="CVE reference",
        )

    # URL
    if _URL_RE.match(refanged):
        return IOC(
            value=refanged,
            kind="url",
            pattern=f"[url:value = '{q}']",
            severity=_SEVERITY["url"],
        )

    # File hash
    if _HEX_RE.match(refanged) and len(refanged) in _HASH_KINDS:
        algo = _HASH_KINDS[len(refanged)]
        stix_algo = {"MD5": "MD5", "SHA-1": "SHA-1", "SHA-256": "SHA-256",
                     "SHA-512": "SHA-512"}[algo]
        return IOC(
            value=refanged.lower(),
            kind="file",
            pattern=f"[file:hashes.'{stix_algo}' = '{refanged.lower()}']",
            severity=_SEVERITY["file"],
            note=f"{algo} hash",
            extra={"algo": stix_algo},
        )

    # IP address (v4/v6)
    try:
        ip = ipaddress.ip_address(refanged)
        if ip.version == 4:
            return IOC(
                value=refanged,
                kind="ipv4-addr",
                pattern=f"[ipv4-addr:value = '{q}']",
                severity=_SEVERITY["ipv4-addr"],
            )
        return IOC(
            value=refanged,
            kind="ipv6-addr",
            pattern=f"[ipv6-addr:value = '{q}']",
            severity=_SEVERITY["ipv6-addr"],
        )
    except ValueError:
        pass

    # Email
    if _EMAIL_RE.match(refanged):
        return IOC(
            value=refanged,
            kind="email-addr",
            pattern=f"[email-addr:value = '{q}']",
            severity=_SEVERITY["email-addr"],
        )

    # Domain
    if _DOMAIN_RE.match(refanged):
        return IOC(
            value=refanged.lower(),
            kind="domain-name",
            pattern=f"[domain-name:value = '{_esc_pattern(refanged.lower())}']",
            severity=_SEVERITY["domain-name"],
        )

    return IOC(value=value, kind="unknown", note="unrecognized IOC format")


def _refang(value: str) -> str:
    """Convert common defanged IOC notations back to live form for parsing."""
    v = value
    v = re.sub(r"^h(?:xx|tt)?ps?\[?:\]?//", lambda m: m.group(0)
               .replace("hxxp", "http").replace("hxxps", "https")
               .replace("[:]", ":").replace("[", "").replace("]", ""),
               v, flags=re.IGNORECASE)
    v = v.replace("hxxps://", "https://").replace("hxxp://", "http://")
    v = v.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    v = re.sub(r"\(dot\)", ".", v, flags=re.IGNORECASE)
    v = v.replace("[:]", ":").replace("[://]", "://")
    v = v.replace("[@]", "@").replace("(at)", "@")
    return v


def parse_iocs(text: str) -> list[IOC]:
    """Parse raw text (one IOC per line, '#' comments allowed) into IOCs."""
    out: list[IOC] = []
    seen: set[tuple[str, str]] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # tolerate CSV-ish 'value,tag' — take the first field
        token = line.split(",")[0].strip().strip('"').strip("'")
        if not token:
            continue
        ioc = classify_ioc(token)
        key = (ioc.kind, ioc.value.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(ioc)
    return out


def _identity_sdo(producer: str) -> dict:
    iid = _det_id("identity", producer)
    ts = _now()
    return {
        "type": "identity",
        "spec_version": _SPEC_VERSION,
        "id": iid,
        "created": ts,
        "modified": ts,
        "name": producer,
        "identity_class": "organization",
    }


def _indicator_sdo(ioc: IOC, created_by: str, labels: list[str]) -> dict:
    iid = _det_id("indicator", ioc.value)
    ts = _now()
    sdo = {
        "type": "indicator",
        "spec_version": _SPEC_VERSION,
        "id": iid,
        "created_by_ref": created_by,
        "created": ts,
        "modified": ts,
        "name": f"{ioc.kind}: {ioc.value}",
        "indicator_types": ["malicious-activity"],
        "pattern": ioc.pattern,
        "pattern_type": "stix",
        "pattern_version": _SPEC_VERSION,
        "valid_from": ts,
    }
    if labels:
        sdo["labels"] = labels
    return sdo


def _vulnerability_sdo(ioc: IOC, created_by: str) -> dict:
    vid = _det_id("vulnerability", ioc.value)
    ts = _now()
    return {
        "type": "vulnerability",
        "spec_version": _SPEC_VERSION,
        "id": vid,
        "created_by_ref": created_by,
        "created": ts,
        "modified": ts,
        "name": ioc.value,
        "external_references": [
            {"source_name": "cve", "external_id": ioc.value}
        ],
    }


def build_bundle(iocs: list[IOC], producer: str = "STIXGEN",
                 labels: Optional[list[str]] = None,
                 include_invalid: bool = False) -> dict:
    """Build a STIX 2.1 bundle dict from classified IOCs.

    Returns the bundle (always at least the producer Identity). Invalid IOCs
    are skipped unless include_invalid is set (they can never be skipped into
    the bundle as objects — they have no pattern — the flag is informational).
    """
    labels = labels or []
    identity = _identity_sdo(producer)
    objects: list[dict] = [identity]

    for ioc in iocs:
        if not ioc.valid:
            continue
        if ioc.kind == "vulnerability":
            objects.append(_vulnerability_sdo(ioc, identity["id"]))
        else:
            objects.append(_indicator_sdo(ioc, identity["id"], labels))

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
    return bundle


def summarize(iocs: list[IOC]) -> dict:
    """Produce a counts/severity summary for reporting and exit codes."""
    by_kind: dict[str, int] = {}
    by_sev: dict[str, int] = {"high": 0, "medium": 0, "low": 0, "unknown": 0}
    valid = 0
    for ioc in iocs:
        by_kind[ioc.kind] = by_kind.get(ioc.kind, 0) + 1
        by_sev[ioc.severity] = by_sev.get(ioc.severity, 0) + 1
        if ioc.valid:
            valid += 1
    top = "unknown"
    for sev in ("high", "medium", "low"):
        if by_sev.get(sev):
            top = sev
            break
    return {
        "total": len(iocs),
        "valid": valid,
        "invalid": len(iocs) - valid,
        "by_kind": by_kind,
        "by_severity": by_sev,
        "top_severity": top,
    }


_SEV_COLOR = {
    "high": "#c0392b",
    "medium": "#d35400",
    "low": "#27746b",
    "unknown": "#7f8c8d",
}


def render_html(iocs: list[IOC], summary: dict, producer: str,
                bundle_id: str) -> str:
    """Render a clean, self-contained HTML intel report (the tool's UI)."""
    e = html.escape
    rows = []
    for ioc in sorted(iocs, key=lambda i: -_SEVERITY_RANK.get(i.severity, 0)):
        color = _SEV_COLOR.get(ioc.severity, "#7f8c8d")
        valid_badge = ("✓" if ioc.valid else "✗")
        rows.append(
            "<tr>"
            f"<td><span class='sev' style='background:{color}'>"
            f"{e(ioc.severity)}</span></td>"
            f"<td><code>{e(ioc.kind)}</code></td>"
            f"<td class='val'>{e(ioc.value)}</td>"
            f"<td><code class='pat'>{e(ioc.pattern) or '&mdash;'}</code></td>"
            f"<td class='ok'>{valid_badge} {e(ioc.note)}</td>"
            "</tr>"
        )
    rows_html = "\n".join(rows)

    sev = summary["by_severity"]
    kind_rows = "".join(
        f"<li><b>{e(k)}</b>: {v}</li>"
        for k, v in sorted(summary["by_kind"].items())
    )
    gen = _now()

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>STIXGEN Intel Report — {e(producer)}</title>
<style>
 :root {{ --bg:#0f1419; --card:#1a2129; --ink:#e6edf3; --mut:#8b98a5; }}
 * {{ box-sizing:border-box; }}
 body {{ margin:0; background:var(--bg); color:var(--ink);
   font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; padding:24px; }}
 h1 {{ font-size:20px; margin:0 0 4px; }}
 .sub {{ color:var(--mut); font-size:12px; margin-bottom:20px; }}
 .cards {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px; }}
 .card {{ background:var(--card); border-radius:10px; padding:14px 18px;
   min-width:120px; border:1px solid #2a323c; }}
 .card .n {{ font-size:26px; font-weight:700; }}
 .card .l {{ color:var(--mut); font-size:11px; text-transform:uppercase;
   letter-spacing:.06em; }}
 .pill {{ display:inline-block; padding:2px 8px; border-radius:20px;
   font-size:11px; color:#fff; margin-right:6px; }}
 table {{ width:100%; border-collapse:collapse; background:var(--card);
   border-radius:10px; overflow:hidden; }}
 th,td {{ text-align:left; padding:9px 12px; border-bottom:1px solid #2a323c;
   vertical-align:top; }}
 th {{ background:#222b35; color:var(--mut); font-size:11px;
   text-transform:uppercase; letter-spacing:.05em; }}
 td.val {{ font-family:ui-monospace,Menlo,Consolas,monospace; word-break:break-all; }}
 code {{ color:#7ee0c8; }}
 code.pat {{ color:#9cb4ff; font-size:12px; word-break:break-all; }}
 .sev {{ color:#fff; padding:2px 8px; border-radius:4px; font-size:11px;
   text-transform:uppercase; font-weight:600; }}
 .ok {{ color:var(--mut); font-size:12px; }}
 ul {{ list-style:none; padding:0; margin:0; color:var(--mut); }}
 footer {{ color:var(--mut); font-size:11px; margin-top:20px; }}
</style></head><body>
<h1>STIXGEN Threat Intel Report</h1>
<div class="sub">Producer: <b>{e(producer)}</b> &middot; Bundle
  <code>{e(bundle_id)}</code> &middot; Generated {e(gen)}</div>
<div class="cards">
  <div class="card"><div class="n">{summary['total']}</div>
    <div class="l">IOCs Parsed</div></div>
  <div class="card"><div class="n">{summary['valid']}</div>
    <div class="l">STIX Objects</div></div>
  <div class="card"><div class="n">{summary['invalid']}</div>
    <div class="l">Unrecognized</div></div>
  <div class="card">
    <div class="n">
      <span class="pill" style="background:{_SEV_COLOR['high']}">{sev['high']}</span>
      <span class="pill" style="background:{_SEV_COLOR['medium']}">{sev['medium']}</span>
      <span class="pill" style="background:{_SEV_COLOR['low']}">{sev['low']}</span>
    </div>
    <div class="l">Severity (H/M/L)</div></div>
</div>
<div class="card" style="margin-bottom:20px">
  <div class="l" style="margin-bottom:6px">By type</div>
  <ul>{kind_rows}</ul></div>
<table>
<thead><tr><th>Severity</th><th>Type</th><th>Value</th>
  <th>STIX Pattern</th><th>Status</th></tr></thead>
<tbody>
{rows_html}
</tbody></table>
<footer>Generated by STIXGEN — STIX 2.1 bundle generator. Defensive
  intel-sharing only. Verify IOCs before disseminating.</footer>
</body></html>
"""
