"""Capture-provider inventory for the staged Windows native-capture migration.

This module intentionally reports capabilities without selecting an experimental
provider. The existing Scapy/Npcap path remains authoritative until a native
provider passes the parity suite documented in the v0.4 roadmap.
"""
from __future__ import annotations

import importlib.util
import os
import platform
import shutil
from typing import Any, Callable, Mapping


REQUIRED_FEATURES = (
    "ethernet",
    "ip",
    "tcp_udp",
    "dns_http_tls_metadata",
    "connection_grouping",
    "payload_hex",
    "tcp_health_latency",
    "interface_selection",
    "continuous_capture",
)


def _support(**overrides: str) -> dict[str, str]:
    result = {feature: "supported" for feature in REQUIRED_FEATURES}
    result.update(overrides)
    return result


def provider_inventory(
    *,
    system_name: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return honest runtime and migration capabilities for capture providers."""
    system_name = system_name or platform.system()
    environ = environ or os.environ
    is_windows = system_name == "Windows"
    scapy_installed = importlib.util.find_spec("scapy") is not None
    pktmon_path = which("pktmon") if is_windows else None
    experimental_requested = environ.get("NSCOUT_EXPERIMENTAL_PKTMON", "").lower() in {
        "1", "true", "yes", "on"
    }

    return {
        "active_provider": "scapy",
        "migration_policy": "npcap_fallback_until_verified_parity",
        "providers": [
            {
                "id": "scapy",
                "label": "Scapy live capture",
                "available": scapy_installed,
                "selectable": scapy_installed,
                "maturity": "current",
                "windows_dependency": "Npcap",
                "capabilities": _support(),
                "limitations": [
                    "Windows live capture still requires a compatible Npcap installation.",
                    "Capture permissions and driver availability are verified only when capture starts.",
                ],
            },
            {
                "id": "windows_pktmon_probe",
                "label": "Windows Packet Monitor feasibility probe",
                "available": bool(pktmon_path),
                "selectable": False,
                "requested": experimental_requested,
                "maturity": "research",
                "executable": pktmon_path,
                "capabilities": _support(
                    payload_hex="partial",
                    continuous_capture="not_verified",
                    interface_selection="partial",
                    tcp_health_latency="not_verified",
                ),
                "limitations": [
                    "An opt-in capture-to-PCAPNG prototype exists but is not connected to the live capture engine.",
                    "ETL/PCAPNG conversion is batch-oriented and can contain duplicate stack snapshots.",
                    "Elevation, loss behavior, interface mapping and shutdown recovery need Windows VM validation.",
                ],
            },
            {
                "id": "wfp_callout",
                "label": "Purpose-built WFP callout",
                "available": False,
                "selectable": False,
                "maturity": "contingency_only",
                "capabilities": _support(**{feature: "not_verified" for feature in REQUIRED_FEATURES}),
                "limitations": [
                    "Would require WDK development, VM testing, installer integration and production driver signing.",
                    "Will not be pursued unless supported in-box capture cannot meet essential parity requirements.",
                ],
            },
        ],
    }
