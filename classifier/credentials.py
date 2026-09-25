"""Default credentials lookup table for common network devices.

Keyed by lowercase ``(vendor, product)`` tuples. Each entry maps to a list
of known default credential sets (username / password pairs) that ship with
the out-of-the-box firmware of that device.

Only *known-default* credentials are listed here (e.g. ``admin/admin``,
``admin/password``). This is a passive, read-only reference table used to
alert an operator that a device may still be using factory defaults. It does
NOT perform any login attempts.
"""

from typing import Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Lookup table
# --------------------------------------------------------------------------- #
# (vendor, product) -> [ { username, password, note? }, ... ]
DEFAULT_CREDENTIALS: Dict[Tuple[str, str], List[Dict[str, str]]] = {
    # -- Routers / switches -------------------------------------------------- #
    ("ubiquiti", "unifi controller"): [
        {"username": "admin", "password": "admin",
         "note": "Change on first launch; default is often left in place."},
    ],
    ("mikrotik", "routeros"): [
        {"username": "admin", "password": "",
         "note": "Historically blank password (pre-6.4)."},
    ],
    ("zyxel", "nas"): [
        {"username": "admin", "password": "1234"},
    ],
    ("zyxel", "usg"): [
        {"username": "admin", "password": "admin"},
    ],
    ("tp-link", "omada controller"): [
        {"username": "admin", "password": "admin"},
    ],
    ("tp-link", "cpe"): [
        {"username": "admin", "password": "admin"},
    ],
    ("aruba", "instant ap"): [
        {"username": "admin", "password": "admin",
         "note": "Factory default until first login change."},
    ],
    ("aruba", "clearpass"): [
        {"username": "admin", "password": "admin"},
    ],
    # -- IP cameras / NVRs --------------------------------------------------- #
    ("hikvision", "ip camera"): [
        {"username": "admin", "password": "",
         "note": "Empty password until first login; forces set."},
    ],
    ("hikvision", "nvr"): [
        {"username": "admin", "password": ""},
    ],
    ("dahua", "ip camera"): [
        {"username": "admin", "password": "admin"},
    ],
    ("dahua", "nvr"): [
        {"username": "admin", "password": "admin"},
    ],
    # -- NAS / storage ------------------------------------------------------- #
    ("synology", "diskstation"): [
        {"username": "admin", "password": "admin",
         "note": "Modern DSM forces a new password on first boot."},
    ],
    # -- Misc -----------------------
    ("netgear", "router"): [
        {"username": "admin", "password": "password"},
    ],
    ("linksys", "router"): [
        {"username": "admin", "password": "admin"},
    ],
    ("cisco", "ios router"): [
        {"username": "cisco", "password": "cisco",
         "note": "Legacy enable password used in labs/docs."},
    ],
}

# Normalised alias map: common product fragments -> canonical product key.
# Used when the detected product string does not exactly match a table key.
ALIAS: Dict[Tuple[str, str], Tuple[str, str]] = {
    ("ubiquiti", "edgerouter"): ("ubiquiti", "unifi controller"),
    ("mikrotik", "router"): ("mikrotik", "routeros"),
    ("hikvision", "camera"): ("hikvision", "ip camera"),
    ("dahua", "camera"): ("dahua", "ip camera"),
    ("synology", "ds"): ("synology", "diskstation"),
    ("linksys", "ea"): ("linksys", "router"),
}


def _norm(value: Optional[str]) -> str:
    return (value or "").strip().lower()


def lookup_credentials(
    vendor: Optional[str],
    product: Optional[str],
) -> List[Dict[str, str]]:
    """Return default credentials for a (vendor, product) pair.

    Falls back to an alias resolution, then a vendor-only scan, then empty.
    """
    vendor = _norm(vendor)
    product = _norm(product)

    if vendor and product:
        key = (vendor, product)
        if key in DEFAULT_CREDENTIALS:
            return DEFAULT_CREDENTIALS[key]
        alias = ALIAS.get(key)
        if alias and alias in DEFAULT_CREDENTIALS:
            return DEFAULT_CREDENTIALS[alias]

    # Vendor-wide fallback: any product whose vendor matches.
    for (v, _p), creds in DEFAULT_CREDENTIALS.items():
        if v == vendor:
            return creds
    return []


def credentials_for_service(service: Dict[str, str]) -> List[Dict[str, str]]:
    """Convenience wrapper that reads vendor/product from a service dict."""
    return lookup_credentials(
        service.get("manufacturer") or service.get("vendor"),
        service.get("product"),
    )


def credentials_for_host(host: Dict[str, object]) -> List[Dict[str, str]]:
    """Collect de-duplicated default creds across all services of a host."""
    seen: List[Tuple[str, str]] = []
    creds: List[Dict[str, str]] = []
    for svc in host.get("services", []) or []:
        for cred in credentials_for_service(svc):
            sig = (cred.get("username", ""), cred.get("password", ""))
            if sig not in seen:
                seen.append(sig)
                entry = dict(cred)
                entry["matched_product"] = svc.get("product")
                entry["matched_vendor"] = svc.get("manufacturer") or svc.get("vendor")
                creds.append(entry)
    return creds
