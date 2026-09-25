"""Passive monitoring helpers: ARP table polling."""

import subprocess
import re
from typing import List, Dict


def list_arp_table() -> List[Dict[str, str]]:
    """Parse `ip neigh show` into a list of {ip, mac, state} dicts."""
    try:
        out = subprocess.run(
            ["ip", "-o", "neigh", "show"],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except (subprocess.TimeoutExpired, OSError):
        return []
    entries = []
    for line in out.splitlines():
        # e.g. "10.0.0.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        m = re.match(r"^(\S+)\s+dev\s+(\S+)\s+lladdr\s+([0-9a-fA-F:]{17})", line)
        if not m:
            continue
        ip, dev, mac = m.group(1), m.group(2), m.group(3)
        state_m = re.search(r"\b(REACHABLE|STALE|DELAY|PROBE|FAILED|PERMANENT|INCOMPLETE|NONE)\b", line)
        entries.append({
            "ip": ip,
            "interface": dev,
            "mac": mac.lower(),
            "state": state_m.group(1) if state_m else "unknown",
        })
    return entries
