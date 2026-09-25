"""Passive sniffer detection via random-IP ARP probes.

Technique: send "ARP who-has <random_ip>?" broadcasts where random_ip is an
IP picked at random inside the target subnet. Normal hosts reply only to
their own address and drop the frame; a NIC in promiscuous/sniffing mode
tends to reply for the fake address. Collect the responding MACs and flag
them as potential sniffers.
"""

import json
import random
from datetime import datetime, timezone
from ipaddress import ip_network
from typing import List, Optional


def get_own_mac(iface: Optional[str] = None) -> Optional[str]:
    """Return this host's MAC address (lowercase) read from sysfs."""
    if not iface:
        return None
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return f.read().strip().lower()
    except Exception:
        return None


def _pick_fake_ip(cidr: str) -> str:
    net = ip_network(cidr, strict=False)
    hosts = [str(ip) for ip in net.hosts()]
    if not hosts:
        hosts = [str(net.network_address)]
    return random.choice(hosts)


def detect_sniffers(
    iface: Optional[str] = None,
    cidr: str = "192.0.2.0/24",
    timeout: float = 2.0,
    probes: int = 3,
) -> List[dict]:
    """Send `probes` random-IP ARP who-has broadcasts and flag responders.

    Returns a list of dicts: [{"mac": str, "random_ip": str, "ts": str}, ...]
    """
    try:
        from scapy.all import ARP, Ether, srp
    except Exception:
        return []

    own_mac = (get_own_mac(iface) or "").lower()

    flagged = {}
    for _ in range(max(1, int(probes))):
        fake_ip = _pick_fake_ip(cidr)
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=fake_ip, op=1)
        try:
            ans, _ = srp(
                pkt,
                timeout=timeout,
                retry=0,
                iface=iface,
                verbose=False,
            )
        except Exception:
            continue
        for _sent, rcv in ans:
            mac = (rcv.getfieldval("hwsrc") or "").lower()
            if not mac or mac == own_mac:
                continue
            if mac not in flagged:
                flagged[mac] = {
                    "mac": mac,
                    "random_ip": fake_ip,
                    "ts": datetime.now(timezone.utc).isoformat(),
                }
    return list(flagged.values())


def parse_evidence(raw) -> List[dict]:
    """Parse stored sniffing evidence (JSON text or list) into a list."""
    if not raw:
        return []
    if isinstance(raw, list):
        return raw
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except Exception:
        return []
