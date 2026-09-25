"""Passive WiFi attack detection (nmcli-based, no monitor mode).

Rules:
  - EVIL_TWIN  : unencrypted clone of a protected SSID (critique)
  - ROGUE_AP   : same SSID seen on 2+ BSSIDs (haute)
  - WEAK_CRYPT : WEP (critique), TKIP (haute), open (moyenne)
  - AD_HOC     : Ad-Hoc mode (moyenne)
  - NEW_AP     : BSSID not in baseline (basse, only when baseline non-empty)
"""

from typing import Any, Dict, List, Optional, Set

SEVERITY_RANK = {
    "critique": 0,
    "haute": 1,
    "moyenne": 2,
    "basse": 3,
}

PROTECTED_TOKENS = ("WPA", "WPA2", "WPA3", "802.1X", "802-1X", "SAE")


def _normalize_security(security: Optional[List[str]]) -> List[str]:
    return [s.strip().upper() for s in (security or []) if s and s.strip()]


def _is_protected(sec: List[str]) -> bool:
    return any(tok in s for s in sec for tok in PROTECTED_TOKENS)


def _emit(results: List[Dict[str, Any]], net: Dict[str, Any],
          attack_type: str, severity: str, description: str) -> None:
    results.append({
        "type": attack_type,
        "severity": severity,
        "bssid": net.get("bssid"),
        "ssid": net.get("ssid"),
        "description": description,
    })


def detect_attacks(
    networks: List[Dict[str, Any]],
    baseline: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Detect WiFi attacks from a list of network dicts.

    network dict keys: bssid, ssid, mode, channel, quality, security (list)
    baseline: list of known-good network dicts (must contain "bssid").

    Returns list of dicts: type, severity, bssid, ssid, description.
    Deduplicated per (bssid, type).
    """
    results: List[Dict[str, Any]] = []
    networks = list(networks or [])
    baseline_bssids: Set[str] = {
        b["bssid"] for b in (baseline or []) if b.get("bssid")
    }

    by_ssid: Dict[str, List[Dict[str, Any]]] = {}
    for net in networks:
        sec = _normalize_security(net.get("security"))
        net = dict(net)
        net["security"] = sec
        ssid = (net.get("ssid") or "").strip()
        if ssid and ssid != "(caché)":
            by_ssid.setdefault(ssid.upper(), []).append(net)

    protected_ssids = {
        ssid for ssid, dups in by_ssid.items()
        if any(_is_protected(n["security"]) for n in dups)
    }

    # EVIL_TWIN: open SSID that also exists with protection
    for ssid, dups in by_ssid.items():
        if ssid not in protected_ssids:
            continue
        for n in dups:
            if n["security"]:
                continue
            _emit(
                results, n, "EVIL_TWIN", "critique",
                f"Réseau ouvert '{n['ssid']}' clonant un SSID protégé (evil twin)",
            )

    # ROGUE_AP: protected SSID duplicated on 2+ BSSIDs
    for ssid, dups in by_ssid.items():
        if len({n["bssid"] for n in dups if n.get("bssid")}) < 2:
            continue
        for n in dups:
            if not n.get("bssid"):
                continue
            _emit(
                results, n, "ROGUE_AP", "haute",
                f"SSID '{n['ssid']}' visible sur "
                f"{len({x['bssid'] for x in dups if x.get('bssid')})} BSSID différents",
            )

    # per-network checks
    for net in networks:
        bssid = net.get("bssid")
        if not bssid:
            continue
        sec = net["security"]
        if "WEP" in sec:
            _emit(results, net, "WEAK_CRYPT", "critique",
                  f"Chiffrement WEP (obsolète) sur '{net.get('ssid') or '(caché)'}'")
        elif "TKIP" in sec:
            _emit(results, net, "WEAK_CRYPT", "haute",
                  f"Chiffrement TKIP (faible) sur '{net.get('ssid') or '(caché)'}'")
        elif not sec:
            _emit(results, net, "WEAK_CRYPT", "moyenne",
                  f"Réseau non chiffré '{net.get('ssid') or '(caché)'}'")

        if (net.get("mode") or "").lower().startswith("ad-hoc"):
            _emit(results, net, "AD_HOC", "moyenne",
                  f"Mode Ad-Hoc (IBSS) détecté sur '{net.get('ssid') or '(caché)'}'")

        if baseline_bssids and bssid not in baseline_bssids:
            _emit(results, net, "NEW_AP", "basse",
                  f"BSSID {bssid} absent de la référence (nouveau point d'accès)")

    # dedup per (bssid, type), keep highest severity
    best: Dict[tuple, Dict[str, Any]] = {}
    for r in results:
        key = (r["bssid"], r["type"])
        cur = best.get(key)
        if cur is None or _rank(r) < _rank(cur):
            best[key] = r
    return list(best.values())


def _rank(r: Dict[str, Any]) -> int:
    return SEVERITY_RANK.get(r.get("severity", ""), 99)
