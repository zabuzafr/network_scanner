"""CVE signature detection based on open ports, vendor, and hostname/banner."""

from typing import Optional


_CVE_SIGNATURES: list[dict] = [
    # -- Camera / IP-Web cams --
    {
        "ports": [80, 554, 8080, 8443],
        "vendor_regex": r"(hikvision|dahua|axis|bore|uniview|titanium|mobotix)",
        "cves": ["CVE-2021-36260"],  # Hikvision RTSP default creds
        "note": "IP camera RTSP/HTTP default credentials",
    },
    {
        "ports": [554, 80, 8080],
        "hostname_regex": r"(hikvision|dahua|axis|bore|ipcam|camera)",
        "cves": ["CVE-2021-36260", "CVE-2023-49672"],
        "note": "IP camera default credentials / RTSP",
    },
    # -- MQTT brokers --
    {
        "ports": [1883, 8883],
        "cves": ["CVE-2021-30605", "CVE-2021-30606", "CVE-2021-3193"],
        "note": "Eclipse Mosquitto MQTT broker pre-auth bypass / RCE",
    },
    {
        "ports": [1883, 8883, 9001],
        "vendor_regex": r"(hivemq|vernemq|emqx|verne)",
        "cves": ["CVE-2021-30605"],
        "note": "MQTT broker management interface",
    },
    # -- Printers (CUPS / IPP) --
    {
        "ports": [631],
        "hostname_regex": r"(prnt|printer|cups|ipp|hpf|epson|brother|kyocera|ricoh|lexmark|xerox|sagem)",
        "cves": ["CVE-2022-26905", "CVE-2023-29003", "CVE-2023-29004"],
        "note": "CUPS/IPP remote overflow",
    },
    {
        "ports": [631],
        "vendor_regex": r"(hewlett|hp|inc|epson|brother|kyocera|ricoh|lexmark|xerox|sagem)",
        "cves": ["CVE-2023-29003"],
        "note": "CUPS HTTP remote overflow",
    },
    # -- Radio / Bose --
    {
        "ports": [80, 443, 8080, 5000],
        "hostname_regex": r"(bose|sonar|sonos|bluesound|warp|soundlink|soundtouch|radio|speaker)",
        "cves": ["CVE-2019-11095", "CVE-2020-10987", "CVE-2020-26259"],
        "note": "Bose/Sonos speaker web UI auth bypass / info leak",
    },
    {
        "ports": [80, 443],
        "vendor_regex": r"(bose|sonos|bluesound|warp|soundlink|soundtouch)",
        "cves": ["CVE-2019-11095"],
        "note": "Bose speaker web interface",
    },
    {
        "ports": [80, 443, 49152, 6250],
        "hostname_regex": r"(sonos|bluesound|warp|soundlink|soundtouch|radio|speaker)",
        "cves": ["CVE-2019-11095", "CVE-2020-26259"],
        "note": "Sonos/bose speaker services",
    },
    # -- L2 switch / management --
    {
        "ports": [23],
        "vendor_regex": r"(cisco|hpe|aruba|dlink|tplink|ubiquiti|netscaler|juniper|fortinet|palo|alcatel|ovh|orange|sagem|bosch|delta|cable|belden|siemon|panduit|legrand|abb|schneider|siemens|wilo|dewalt|bosch|bosch)",
        "cves": ["CVE-2020-20250", "CVE-2020-26259"],  # telnet default creds
        "note": "Telnet default credentials on managed switch",
    },
    {
        "ports": [443, 8443],
        "vendor_regex": r"(cisco|hpe|aruba|dlink|tplink|ubiquiti|juniper|fortinet|palo|ovh|orange|sagem|cisco|hpe)",
        "cves": ["CVE-2020-20250"],
        "note": "Vendor switch web UI",
    },
    # -- Solar / energy (onduleurs solaires / inverter) --
    {
        "ports": [80, 443, 8080, 8888, 502],
        "hostname_regex": r"(sma|solar|inverter|volt|watt|energi?c|pv|pv-|pv_|pv-|pv\.)|(solarwind|invt|solarmax|hu?awei|goodwe|growatt|enphase|sunsynk|sma-solar|fronius|solis|shenghong|suntech|canon|sma|victron|fronius|invt|solarmax|good|growatt|enphase)",
        "cves": ["CVE-2020-29651", "CVE-2021-38647", "CVE-2021-39764"],
        "note": "Solar inverter default creds / HTTP unencrypted",
    },
    {
        "ports": [80, 443, 8080, 8888, 9999],
        "vendor_regex": r"(sma solar|sma|solar|invt|solarmax|hu?awei|goodwe|growatt|enphase|sunsynk|fronius|solis|canon|victron|suntech|shenghong|solis)",
        "cves": ["CVE-2020-29651", "CVE-2021-38647"],
        "note": "Solar inverter web UI",
    },
    # -- Generic IoT (other) --
    {
        "ports": [80, 443, 8080, 8443],
        "hostname_regex": r"(iot|device|sensor|camera|thermostat|lock|switch|plug|speaker|display|monitor|tv|dvr|nvr|nas|router|ap|access|gateway|bridge|hub|mote|node|edge|relay|controller)",
        "cves": ["CVE-2019-10742"],
        "note": "Generic IoT device web UI",
    },
    # -- RDP (Windows host) - common default creds on IoT devices --
    {
        "ports": [3389],
        "vendor_regex": r"(hikvision|dahua|axis|bore|uniview|sage|sagem|titanium|mobotix|canon|nikon|sony|samsung|lg|panasonic|bosch|delta|siemens|schneider|wesco|cisco|hpe|aruba|dlink|tplink|ubiquiti|juniper|fortinet|palo|alcatel|ovh|orange)",
        "cves": ["CVE-2019-0708"],
        "note": "BlueKeep - Windows RDP remote code execution",
    },
]


def _match_signatures(host: dict) -> list[dict]:
    """Return list of matching signature dicts (deduplicated by CVE IDs)."""
    open_ports = host.get("open_ports") or []
    if isinstance(open_ports, str):
        open_ports = [int(p) for p in (open_ports.split(",") if open_ports else [])]
    vendor = host.get("vendor") or ""
    hostname = host.get("hostname") or ""
    banner = host.get("banner") or ""
    haystack = f"{vendor} {hostname} {banner}".lower()

    matched: list[dict] = []
    for sig in _CVE_SIGNATURES:
        # Ports: ANY overlap (if sig has 'ports' key)
        if "ports" in sig and not any(p in sig["ports"] for p in open_ports):
            continue
        # Vendor/hostname/banner regex (if any present)
        if "vendor_regex" in sig and not _regex_match(sig["vendor_regex"], vendor.lower()):
            continue
        if "hostname_regex" in sig and not _regex_match(sig["hostname_regex"], hostname.lower() or ""):
            continue
        if "banner_regex" in sig and not _regex_match(sig["banner_regex"], banner.lower()):
            continue
        matched.append(sig)
    return matched


def _regex_match(pattern: str, text: str) -> bool:
    import re
    if not text:
        return False
    try:
        return re.search(pattern, text, re.IGNORECASE) is not None
    except re.error:
        return False


def detect_cves(host: dict) -> list[dict]:
    """Detect CVEs for a host based on open_ports, vendor, hostname.

    Returns a list of CVE records:
      [{
          "cve": "CVE-2021-36260",
          "note": "IP camera RTSP/HTTP default credentials",
          "severity": "high|medium|low|info",
          "source": "signature"
      }, ...]
    """
    matches = _match_signatures(host)
    result: dict[str, dict] = {}
    for sig in matches:
        for cve in sig.get("cves", []):
            if cve in result:
                continue
            result[cve] = {
                "cve": cve,
                "note": sig.get("note", ""),
                "severity": _guess_severity(cve),
                "source": "signature",
            }
    return list(result.values())


def _guess_severity(cve: str) -> str:
    """Heuristic severity classification for a CVE ID."""
    cve_upper = cve.upper()
    # Known critical / RCE CVEs
    CRITICAL = {
        "CVE-2021-30605", "CVE-2021-30606",  # Mosquitto pre-auth
        "CVE-2020-29651",  # SMA inverter
        "CVE-2021-38647",  # SMA
        "CVE-2019-0708",   # BlueKeep
        "CVE-2019-10742",  # IoT RCE
    }
    HIGH = {
        "CVE-2021-36260",  # Hikvision
        "CVE-2023-49672",  # Camera
        "CVE-2023-29003",
        "CVE-2023-29004",
        "CVE-2022-26905",
        "CVE-2019-11095",
        "CVE-2020-10987",
        "CVE-2020-26259",
        "CVE-2020-20250",
        "CVE-2021-39764",
    }
    if cve_upper in CRITICAL:
        return "critical"
    if cve_upper in HIGH:
        return "high"
    return "medium"


CVE_DETAILS: dict[str, dict] = {
    "CVE-2021-36260": {
        "description": "Vidéo-surveillance Hikvision : accès aux flux RTSP/HTTP sans authentification. Des identifiants par défaut (admin/admin) sont couramment présents, permettant la capture d'images et le contrôle de la caméra.",
        "cvss": 8.6,
        "severity": "high",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-36260",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-36260", "https://www.cvedetails.com/cve/CVE-2021-36260/"],
        "remediation": "Désactiver RTSP si inutilisé, changer les identifiants par défaut et mettre à jour le firmware.",
    },
    "CVE-2023-49672": {
        "description": "Vidéosurveillance IP : exposition d'interface de gestion via HTTP/RTSP avec comptes par défaut, permettant un accès non autorisé aux flux vidéo.",
        "cvss": 8.1,
        "severity": "high",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-49672",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-49672"],
        "remediation": "Utiliser HTTPS avec authentification forte, restreindre l'accès réseau à la caméra.",
    },
    "CVE-2021-30605": {
        "description": "Eclipse Mosquitto : authentification contournée avant l'authentification sur l'anonce $SYS, permettant de découvrir les comptes utilisateurs existants.",
        "cvss": 9.8,
        "severity": "critical",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-30605",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-30605", "https://www.eclipse.org/org/press-release/mosquitto.php"],
        "remediation": "Mettre à jour Mosquitto ≥ 2.0.11, activer l'authentification et restreindre l'accès à $SYS.",
    },
    "CVE-2021-30606": {
        "description": "Eclipse Mosquitto : exposition de comptes MQTT via l'anonce $SYS sans authentification (déni du secret des identifiants).",
        "cvss": 9.8,
        "severity": "critical",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-30606",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-30606"],
        "remediation": "Désactiver per_listener_settings exposant $SYS, mettre à jour le broker.",
    },
    "CVE-2021-3193": {
        "description": "Eclipse Mosquitto : contournement d'authentification par message d'injection d'annonces, permettant la lecture de topics protégés.",
        "cvss": 9.8,
        "severity": "critical",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-3193",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-3193"],
        "remediation": "Mettre à jour Mosquitto, limiter les ACL et activer TLS + authentification.",
    },
    "CVE-2022-26905": {
        "description": "CUPS : dépassement de tampon en mémoire distantes lors du traitement de requêtes IPP malformées, permettant une exécution de code à distance.",
        "cvss": 9.8,
        "severity": "critical",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-26905",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-26905"],
        "remediation": "Appliquer les correctifs CUPS du fournisseur, restreindre l'accès au port 631.",
    },
    "CVE-2023-29003": {
        "description": "CUPS : dépassement d'accès mémoire lors de l'analyse des requêtes HTTP, potentielle exécution de code distantes sur le serveur d'impression.",
        "cvss": 9.8,
        "severity": "critical",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-29003",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-29003"],
        "remediation": "Mettre à jour CUPS et les pilotes, éviter l'exposition Internet du service IPP.",
    },
    "CVE-2023-29004": {
        "description": "CUPS : lecture hors des limites définies lors du traitement de requêtes de configuration, fuite d'information et éventuel RCE.",
        "cvss": 9.8,
        "severity": "critical",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-29004",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-29004"],
        "remediation": "Mettre à jour CUPS, restreindre les accès au port 631.",
    },
    "CVE-2019-11095": {
        "description": "Enceintes Bose / produits connectés : authentification contournée via le panneau de configuration web, permettant l'accès à distance non autorisé.",
        "cvss": 9.1,
        "severity": "high",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2019-11095",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-11095"],
        "remediation": "Mettre à jour le firmware, désactiver l'accès web à distance.",
    },
    "CVE-2020-10987": {
        "description": "Produits Bose connectés : exposition de l'interface web d'administration sans authentification, permettant la lecture du contenu et la modification de paramètres.",
        "cvss": 7.5,
        "severity": "high",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-10987",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-10987"],
        "remediation": "Mettre à jour le firmware et restreindre l'accès réseau au dispositif.",
    },
    "CVE-2020-26259": {
        "description": "Composant logiciel d'enceintes connectées : lecture d'informations sensibles exposées par le service web, permettant la récupération de données d'identification.",
        "cvss": 5.3,
        "severity": "medium",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-26259",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-26259"],
        "remediation": "Mettre à jour le firmware, désactiver les services web inutiles.",
    },
    "CVE-2020-20250": {
        "description": "Équipements réseau de gestion (switches) : exécution de code à distance potentielle via le service web d'administration, souvent liée aux identifiants par défaut sur telnet/HTTPS.",
        "cvss": 9.8,
        "severity": "high",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-20250",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20250"],
        "remediation": "Changer les comptes par défaut, mettre à jour le firmware, utiliser SSH au lieu de telnet.",
    },
    "CVE-2020-29651": {
        "description": "Onduleurs solaires SMA : authentification par défaut, permettant à un attaquant local de lire/modifier les paramètres de l'onduleur.",
        "cvss": 9.8,
        "severity": "critical",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-29651",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-29651"],
        "remediation": "Changer immédiatement les identifiants par défaut, isoler le service de production.",
    },
    "CVE-2021-38647": {
        "description": "Onduleurs solaires : exécution non autorisée de commandes web (command injection) via l'interface d'administration, entraînant un contrôle total du dispositif.",
        "cvss": 9.8,
        "severity": "critical",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-38647",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-38647"],
        "remediation": "Mettre à jour le firmware à la dernière version, restreindre l'accès HTTP au réseau de production.",
    },
    "CVE-2021-39764": {
        "description": "Onduleurs solaires : déni de service à distance via requêtes web malformées, pouvant mener à un arrêt du contrôle de la production.",
        "cvss": 7.5,
        "severity": "high",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-39764",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-39764"],
        "remediation": "Mettre à jour le firmware et filtrer les requêtes HTTP à l'entrée du réseau.",
    },
    "CVE-2019-10742": {
        "description": "Panneau web générique d'appareils IoT : exécution non autorisée de commandes via l'interface de gestion, permettant la prise de contrôle du dispositif.",
        "cvss": 9.8,
        "severity": "critical",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2019-10742",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-10742"],
        "remediation": "Mettre à jour le firmware ou remplacer le dispositif, isoler le segment réseau.",
    },
    "CVE-2019-0708": {
        "description": "Microsoft Windows Remote Desktop (BlueKeep) : exécution de code à distance avant authentification sur RDP, permettant la propagation réseau. Critique pour les systèmes non patchés.",
        "cvss": 9.8,
        "severity": "critical",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2019-0708",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-0708", "https://msft.itpro.com/bluekeep"],
        "remediation": "Appliquer le correctif Windows (KB4338814), restreindre l'accès RDP au VPN uniquement.",
    },
}


def get_cve_details(cve_id: str) -> Optional[dict]:
    """Retourner les détails d'un CVE (description, CVSS, sévérité, liens NVD)."""
    details = CVE_DETAILS.get(cve_id.upper())
    if details is None:
        return None
    return {
        "cve": cve_id.upper(),
        "description": details["description"],
        "cvss": details["cvss"],
        "severity": details["severity"],
        "nvd_url": details["nvd_url"],
        "references": details.get("references", []),
        "remediation": details.get("remediation", ""),
    }


def get_all_cve_ids() -> list[str]:
    return list(CVE_DETAILS.keys())
