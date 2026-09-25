"""Vérifications de conformité sécurité : protocoles insûrs, TLS, identifiants par défaut."""

from typing import Any, Dict, List

INSECURE_PORTS = {
    21: "FTP",
    23: "Telnet",
}


def _open_port_list(host: Dict[str, Any]) -> List[int]:
    ports = host.get("open_ports") or []
    out: List[int] = []
    if isinstance(ports, str):
        parts = [p.strip() for p in ports.split(",")]
    else:
        parts = [str(p) for p in ports]
    for p in parts:
        if p.isdigit():
            out.append(int(p))
    for svc in host.get("services") or []:
        try:
            out.append(int(svc.get("port")))
        except (TypeError, ValueError):
            continue
    return sorted(set(out))


def run_compliance_checks(host: Dict[str, Any]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    ports = set(_open_port_list(host))

    for port, proto in INSECURE_PORTS.items():
        if port in ports:
            findings.append({
                "check": "insecure_protocol",
                "severity": "critical",
                "message": f"Protocole insécure exposé : {proto} (port {port}/tcp)",
            })

    if 80 in ports and 443 not in ports:
        findings.append({
            "check": "missing_tls",
            "severity": "high",
            "message": "Service HTTP non chiffré (80/tcp sans 443/tcp)",
        })

    for svc in host.get("services") or []:
        creds = svc.get("default_credentials")
        if creds:
            names = ", ".join(
                f"{c.get('username')}/{c.get('password')}" for c in creds if isinstance(c, dict)
            )
            label = svc.get("name") or f"port {svc.get('port')}"
            findings.append({
                "check": "default_credentials",
                "severity": "high",
                "message": f"Identifiants par défaut possibles sur {label} : {names}",
            })

    return findings
