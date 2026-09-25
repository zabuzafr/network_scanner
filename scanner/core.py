"""Scanner core: ARP/TCP/ICMP scanning with OS fingerprinting and host enrichment."""

from typing import Optional
from ipaddress import ip_address, ip_network

from scapy.all import ARP, Ether, sr, srp, sr1, TCP, IP, ICMP, UDP, SNMP, conf
from scapy.layers.snmp import SNMPget, SNMPresponse, SNMPvarbind
from scapy.asn1.asn1 import ASN1_NULL
import re
import socket
import ssl
import time
import manuf

DEFAULT_PORTS = (22, 80, 135, 139, 143, 161, 389, 445, 443, 465, 587, 631,
                 993, 995, 1433, 1521, 3306, 3389, 4443, 5432, 5900, 54321,
                 8080, 8443, 1883, 8883, 9100, 9101, 9102, 9104, 9105)


def arp_scan(network_cidr: str, iface: Optional[str] = None, timeout: int = 2) -> list[dict]:
    """ARP who-has (broadcast) → list of dicts {ip, mac}."""
    net = ip_network(network_cidr, strict=False)
    arp = ARP(pdst=str(net))
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    answers, _ = srp(
        ether/arp,
        timeout=timeout,
        retry=1,
        iface=iface or conf.iface,
        verbose=False
    )
    hosts = []
    for _, rcv in answers:
        hosts.append({"ip": rcv.psrc, "mac": rcv.hwsrc})
    return hosts


def guess_os_by_ttl(ttl: Optional[int]) -> Optional[str]:
    """Heuristic OS detection based on observed TTL."""
    if ttl is None:
        return None
    if ttl <= 70:
        return "Linux/macOS/Unix (TTL=64)"
    if ttl <= 140:
        return "Windows (TTL=128)"
    return "Network/embedded (TTL=255)"


def os_fingerprint(
    ip: str,
    icmp_timeout: float = 1.0,
    tcp_timeout: float = 1.0,
    tcp_probes: tuple = (443, 80)
) -> tuple[Optional[str], Optional[int], str]:
    """
    Best-effort OS fingerprinting:
      1) ICMP Echo → TTL
      2) TCP SYN on common ports → TTL
    Returns (os_guess, ttl, method)
    """
    try:
        r = sr1(IP(dst=ip)/ICMP(), timeout=icmp_timeout, verbose=False)
        if r is not None and r.haslayer(IP):
            ttl = r.getlayer(IP).ttl
            return (guess_os_by_ttl(ttl), ttl, "ICMP")
    except Exception:
        pass

    for port in tcp_probes:
        try:
            ans, _ = sr(IP(dst=ip)/TCP(dport=port, flags="S"), timeout=tcp_timeout, verbose=False)
            if not ans:
                continue
            for _, rcv in ans:
                if rcv.haslayer(IP):
                    ttl = int(rcv.getlayer(IP).ttl)
                    return (guess_os_by_ttl(ttl), ttl, f"TCP:{port}")
        except Exception:
            continue

    return (None, None, "none")


def tcp_port_scan(ip: str, timeout: float = 0.5, ports: tuple = DEFAULT_PORTS) -> list[int]:
    """TCP connect scan: return list of open ports."""
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                open_ports.append(port)
        except (OSError, socket.timeout):
            continue
    return open_ports


PORT_NAMES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 123: "ntp", 135: "msrpc",
    139: "netbios", 143: "imap", 161: "snmp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 502: "modbus", 543: "dce-rpc",
    554: "rtsp", 587: "submissions", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 3000: "pgadmin", 3306: "mysql",
    3389: "rdp", 4443: "https-alt", 5432: "postgresql", 54321: "postgres-alt",
    5900: "vnc", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    8899: "https", 9001: "http-alt", 9100: "jetdirect", 9101: "jetdirect",
    9102: "jetdirect", 9104: "jetdirect", 9105: "jetdirect",
    1883: "mqtt", 8883: "mqtts", 42000: "unifi",
    17550: "cam", 17551: "cam-rtsp", 3052: "dvr", 37781: "hikvision",
    49152: "cam", 49153: "cam",
}

TLS_HTTP_PORTS = {443, 4443, 8443, 8899, 9001, 9443, 42000}

def _make_service(port: int, name: Optional[str] = None, banner: Optional[str] = None,
                  product: Optional[str] = None, manufacturer: Optional[str] = None,
                  model: Optional[str] = None, firmware: Optional[str] = None,
                  product_hint: bool = False) -> dict:
    return {
        "port": port,
        "name": name or PORT_NAMES.get(port, "unknown"),
        "banner": banner,
        "product": product,
        "manufacturer": manufacturer,
        "model": model,
        "firmware": firmware,
        "product_hint": product_hint,
    }


def _probe_http(ip: str, port: int, timeout: float = 2.0, use_tls: bool = False) -> dict:
    svc = _make_service(port)
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=ip)
        buf = b""
        try:
            sock.sendall(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            sock.settimeout(timeout)
            while b"\r\n\r\n" not in buf and b"\n\n" not in buf and len(buf) < 8192:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                buf += chunk
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass
        head, _, body = buf.partition(b"\r\n\r\n")
        if b"\r\n\r\n" not in buf and b"\n\n" in buf:
            head, _, body = buf.partition(b"\n\n")
        head = head.decode("latin-1", errors="replace")
        server = None
        title = None
        for line in head.splitlines():
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
        if body:
            body_text = body[:4096].decode("latin-1", errors="replace")
            m = re.search(r"<title[^>]*>(.*?)</title>", body_text, re.I | re.S)
            if m:
                title = m.group(1).strip()
        banner_parts = []
        if server:
            banner_parts.append("Server: " + server)
        if title:
            banner_parts.append("title: " + title)
        if body:
            first_line = next((ln.strip() for ln in body.decode("latin-1", errors="replace").splitlines()
                               if ln.strip() and not ln.strip().startswith(("<", "{", "[")))),
            if first_line:
                banner_parts.append("first: " + first_line[:120])
        banner = " | ".join(banner_parts) if banner_parts else None
        if server:
            product = server
            manufacturer = None
            model = None
            firmware = None
            low = server.lower()
            for vendor, vname in (
                ("hikvision", "Hikvision"), ("dahua", "Dahua"), ("uniview", "Uniview"),
                ("ubiquiti", "Ubiquiti"), ("unifi", "UniFi"), ("netgear", "Netgear"),
                ("cisco", "Cisco"), ("juniper", "Juniper"), ("mikrotik", "MikroTik"),
                ("tp-link", "TP-Link"), ("tplink", "TP-Link"), ("hpe", "HPE"),
                ("lexmark", "Lexmark"), ("hp", "HP"), ("xerox", "Xerox"),
                ("bosch", "Bosch"), ("panasonic", "Panasonic"), ("sony", "Sony"),
                ("samsung", "Samsung"), ("axis", "Axis"), ("mobotix", "Mobotix"),
            ):
                if vendor in low:
                    manufacturer = vname
                    break
            m2 = re.search(r"(v|version|release|build)[/\s_-]?(\d+\.\d+[\w.]*)", low)
            if m2:
                firmware = m2.group(2)
            m3 = re.search(r"([A-Z]{2,}-[A-Z0-9]{2,}-[A-Z0-9]{2,})\b", server)
            if m3:
                model = m3.group(1)
            return _make_service(port, banner=banner, product=product,
                                 manufacturer=manufacturer, model=model,
                                 firmware=firmware, product_hint=True)
        if title:
            return _make_service(port, banner=banner, product=title[:120], product_hint=True)
        return _make_service(port, banner=banner)
    except (OSError, ssl.SSLError, ConnectionError):
        return svc


def _probe_ftp(ip: str, timeout: float = 2.0) -> dict:
    try:
        with socket.create_connection((ip, 21), timeout=timeout) as sock:
            banner = sock.recv(512).decode("latin-1", errors="replace").strip()
            if banner and banner.startswith("220"):
                return _make_service(21, banner=banner, product=banner.split()[-1] if len(banner.split()) > 3 else None, product_hint=True)
        return _make_service(21)
    except OSError:
        return _make_service(21)


def _probe_ssh(ip: str, timeout: float = 2.0) -> dict:
    try:
        with socket.create_connection((ip, 22), timeout=timeout) as sock:
            banner = sock.recv(256).decode("latin-1", errors="replace").strip()
            if banner.startswith("SSH-"):
                m = re.match(r"SSH-2\.0-(\w+)", banner)
                product = m.group(1) if m else banner
                ver_m = re.search(r"(\d+\.\d+[\w.]*)", product)
                firmware = ver_m.group(1) if ver_m else None
                return _make_service(22, banner=banner, product=product, firmware=firmware, product_hint=True)
        return _make_service(22)
    except OSError:
        return _make_service(22)


def _probe_telnet(ip: str, timeout: float = 2.0) -> dict:
    try:
        with socket.create_connection((ip, 23), timeout=timeout) as sock:
            sock.sendall(b"\x0d\x0a")
            sock.settimeout(timeout)
            buf = b""
            try:
                while len(buf) < 1024:
                    chunk = sock.recv(512)
                    if not chunk:
                        break
                    buf += chunk
                    if b"\r\n" in chunk:
                        break
            except OSError:
                pass
            banner = buf.decode("latin-1", errors="replace").strip()
            if banner:
                return _make_service(23, banner=banner, product=banner[:120], product_hint=True)
        return _make_service(23)
    except OSError:
        return _make_service(23)


def _snmp_varbind_text(vb) -> Optional[str]:
    """Extract raw textual value from an SNMPvarbind, or None for non-text types."""
    try:
        val = vb.value
        raw = getattr(val, "val", None)
        if isinstance(raw, (bytes, bytearray)):
            text = raw.decode("latin-1", errors="replace")
            if not text.strip():
                return None
            printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
            if printable / len(text) < 0.7:
                return None
            return text.strip()
    except Exception:
        pass
    return None


def _probe_snmp(ip: str, timeout: float = 2.0) -> dict:
    try:
        oids = ("1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.2.0")
        pdu = SNMPget(
            id=1,
            error=0,
            error_index=0,
            varbindlist=[SNMPvarbind(oid=oid, value=ASN1_NULL(0)) for oid in oids],
        )
        req = SNMP(version=1, community="public", PDU=pdu)
        pkt = IP(dst=ip)/UDP(dport=161)/req
        resp = sr1(pkt, timeout=timeout, verbose=False)
        if resp is not None and resp.haslayer(SNMP):
            snmp = resp.getlayer(SNMP)
            try:
                resp_pdu = snmp.getfieldval("PDU")
            except Exception:
                resp_pdu = None
            values = []
            if resp_pdu is not None:
                for vb in (resp_pdu.varbindlist or []):
                    text = _snmp_varbind_text(vb)
                    if text:
                        values.append(text)
            if values:
                banner = "; ".join(v[:160] for v in values)[:320]
                product = values[0][:200]
                return _make_service(161, banner=banner, product=product, product_hint=True)
        return _make_service(161)
    except Exception:
        return _make_service(161)


def _probe_rtsp(ip: str, timeout: float = 2.0, port: int = 554) -> dict:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.sendall(b"OPTIONS rtsp://%s:554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n" % ip.encode())
            sock.settimeout(timeout)
            buf = b""
            try:
                while b"\r\n\r\n" not in buf and len(buf) < 4096:
                    chunk = sock.recv(2048)
                    if not chunk:
                        break
                    buf += chunk
            except OSError:
                pass
            banner = buf.decode("latin-1", errors="replace").strip()
            server = None
            title = None
            for line in banner.splitlines():
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()
            if server:
                return _make_service(port, banner=banner[:320], product=server, product_hint=True)
        return _make_service(port, banner=banner[:320] if banner else None)
    except OSError:
        return _make_service(port)


def _probe_printer(ip: str, port: int, timeout: float = 2.0) -> dict:
    if port in (9100, 9101, 9102, 9104, 9105):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.sendall(b"GET /device/identifiers HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                sock.settimeout(timeout)
                buf = b""
                try:
                    while b"\r\n\r\n" not in buf and len(buf) < 4096:
                        chunk = sock.recv(2048)
                        if not chunk:
                            break
                        buf += chunk
                except OSError:
                    pass
                text = buf.decode("latin-1", errors="replace")
                m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
                if m and m.group(1).strip():
                    return _make_service(port, banner=text[:320], product=m.group(1).strip(), product_hint=True)
                m2 = re.search(r"(Xerox.*|HP.*|Lexmark.*|Ricoh.*|Toshiba.*|Kyocera.*)", text)
                if m2:
                    return _make_service(port, banner=text[:320], product=m2.group(1)[:120], product_hint=True)
            return _make_service(port)
        except OSError:
            return _make_service(port)
    return _make_service(port)


def probe_service(ip: str, port: int, timeout: float = 1.5) -> dict:
    """
    Probe a single open port for service fingerprinting.
    Returns a service dict with port, name, banner, and optional product fields.
    """
    if port in (80, 8080, 8000):
        return _probe_http(ip, port, timeout, use_tls=False)
    if port in TLS_HTTP_PORTS:
        return _probe_http(ip, port, timeout, use_tls=True)
    if port == 21:
        return _probe_ftp(ip, timeout)
    if port == 22:
        return _probe_ssh(ip, timeout)
    if port == 23:
        return _probe_telnet(ip, timeout)
    if port in (161, 162):
        return _probe_snmp(ip, timeout)
    if port == 554:
        return _probe_rtsp(ip, timeout)
    if port in (9100, 9101, 9102, 9104, 9105):
        return _probe_printer(ip, port, timeout)
    return _make_service(port)


def enrich_host(
    ip: str,
    mac: Optional[str] = None,
    icmp_timeout: float = 1.0,
    tcp_timeout: float = 1.0,
    tcp_probes: tuple = (443, 80),
    port_scan: bool = True,
    port_scan_ports: tuple = DEFAULT_PORTS,
    port_scan_timeout: float = 0.5,
    banner_probe: bool = True,
    banner_timeout: float = 1.5,
) -> dict:
    """
    Enrich host record with hostname, OS fingerprint, open ports, MAC metadata,
    and per-port service banners (HTTP, SNMP, FTP, SSH, RTSP, etc.).
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except Exception:
        hostname = None

    mtype = None
    vendor = None
    if mac:
        try:
            mtype = "unicast" if int(mac.replace(":", ""), 16) & 0x01 == 0x00 else "multicast"
        except Exception:
            mtype = "unknown"
        try:
            p = manuf.MacParser()
            vendor = p.get_manuf_long(mac)
        except Exception:
            vendor = None

    os_guess, ttl, ttl_src = os_fingerprint(ip, icmp_timeout, tcp_timeout, tcp_probes)

    open_ports = []
    if port_scan:
        open_ports = tcp_port_scan(ip, port_scan_timeout, port_scan_ports)

    services = []
    if banner_probe and open_ports:
        for port in open_ports:
            try:
                svc = probe_service(ip, port, banner_timeout)
                services.append(svc)
            except Exception:
                services.append(_make_service(port))

    banner = None
    product = None
    for svc in services:
        if banner is None and svc.get("banner"):
            banner = svc["banner"]
        if product is None and svc.get("product"):
            product = svc["product"]
        if banner is not None and product is not None:
            break

    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "mac_type": mtype,
        "vendor": vendor,
        "os_guess": os_guess,
        "ttl": ttl,
        "ttl_src": ttl_src,
        "open_ports": open_ports,
        "services": services,
        "banner": banner,
        "product": product,
    }


def scan_ip(
    ip: str,
    mac: Optional[str] = None,
    icmp_timeout: float = 1.0,
    tcp_timeout: float = 1.0,
    tcp_probes: tuple = (443, 80),
    port_scan: bool = True,
    port_scan_ports: tuple = DEFAULT_PORTS,
    port_scan_timeout: float = 0.5,
    banner_probe: bool = True,
    banner_timeout: float = 1.5,
) -> dict:
    """Scan and enrich a single IP address."""
    try:
        ip_address(ip)
    except ValueError:
        raise ValueError(f"IP invalide: {ip}")
    return enrich_host(
        ip, mac,
        icmp_timeout, tcp_timeout, tcp_probes,
        port_scan, port_scan_ports, port_scan_timeout,
        banner_probe, banner_timeout,
    )


def scan_network(
    network_cidr: str,
    iface: Optional[str] = None,
    timeout: int = 2,
    icmp_timeout: float = 1.0,
    tcp_timeout: float = 1.0,
    tcp_probes: tuple = (443, 80),
    port_scan: bool = True,
    port_scan_ports: tuple = DEFAULT_PORTS,
    port_scan_timeout: float = 0.5,
    banner_probe: bool = True,
    banner_timeout: float = 1.5,
) -> list[dict]:
    """Full network scan: ARP + enrichment + optional port scan."""
    basic_hosts = arp_scan(network_cidr, iface, timeout)
    enriched = []
    for h in basic_hosts:
        enriched.append(enrich_host(
            h["ip"], h.get("mac"),
            icmp_timeout, tcp_timeout, tcp_probes,
            port_scan, port_scan_ports, port_scan_timeout,
            banner_probe, banner_timeout,
        ))
    return enriched