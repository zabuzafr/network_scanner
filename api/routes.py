"""API routes."""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, field_validator
from typing import List, Optional, Dict, Any
import uuid
import json
import re
import subprocess
import threading
import ipaddress
from utils.datetime_utils import utcnow

from sqlalchemy.orm import joinedload
from scanner.core import scan_network, scan_ip
from scanner.passive import list_arp_table
from scanner.sniffing import detect_sniffers, get_own_mac
from classifier.engine import create_engine_from_yaml
from classifier.cves import detect_cves, get_cve_details, get_all_cve_ids
from classifier.compliance import run_compliance_checks
from db.models import Host, Alert, MacHistory, ScanSession, Service, WifiNetwork, WifiAttack
from scanner.wifi_detect import detect_attacks
from db.init import SessionLocal
from api.config import settings
from utils.logging import setup_logging
import logging

setup_logging()
log = logging.getLogger("network_scanner.routes")

router = APIRouter()

MAX_SCAN_HISTORY = 100
SCAN_REGISTRY: Dict[str, Dict[str, Any]] = {}

MONITOR: Dict[str, Any] = {
    "running": False,
    "start_time": None,
    "poll_interval": 2.0,
    "entries": {},
    "last_poll": None,
    "total_seen": 0,
}
MONITOR_LOCK = threading.Lock()
MONITOR_STOP = threading.Event()


def _track_mac(session, ip: str, mac: Optional[str], host_id: int) -> None:
    if not mac:
        return
    known_macs = [
        row.mac
        for row in session.query(MacHistory).filter_by(host_ip=ip).all()
    ]
    if mac not in known_macs:
        prev_macs = [m for m in known_macs if m and m != mac]
        session.add(
            MacHistory(
                host_ip=ip,
                mac=mac,
                first_seen=utcnow(),
                last_seen=utcnow(),
            )
        )
        if prev_macs:
            session.add(
                Alert(
                    host_id=host_id,
                    type="mac_change",
                    severity="critical",
                    message=f"MAC changé de {', '.join(prev_macs)} vers {mac}",
                    timestamp=utcnow(),
                )
            )
    else:
        entry = (
            session.query(MacHistory).filter_by(host_ip=ip, mac=mac).first()
        )
        entry.last_seen = utcnow()

    if host_id is not None:
        h = session.query(Host).filter_by(id=host_id).first()
        if h is not None and h.mac != mac:
            h.mac = mac


def _set_scan_state(scan_id: str, status: str, **extra: Any) -> None:
    state = SCAN_REGISTRY.get(scan_id)
    if state is None:
        state = SCAN_REGISTRY[scan_id] = {}
    state["status"] = status
    state.update(extra)
    if len(SCAN_REGISTRY) > MAX_SCAN_HISTORY:
        oldest = sorted(SCAN_REGISTRY, key=lambda k: SCAN_REGISTRY[k].get("_order", 0))[: len(SCAN_REGISTRY) - MAX_SCAN_HISTORY]
        for k in oldest:
            del SCAN_REGISTRY[k]
    state["_order"] = len(SCAN_REGISTRY)


def _persist_scan(hosts: list, cidr: str = "_", iface: str = None) -> int:
    session = SessionLocal()
    try:
        scan_session = ScanSession(cidr=cidr or "_", iface=iface, status="running")
        session.add(scan_session)
        session.flush()
        session_id = scan_session.id
        for h in hosts:
            record = session.query(Host).filter_by(ip=h["ip"]).first()
            if record is None:
                record = Host(ip=h["ip"])
                session.add(record)
            record.scan_session_id = session_id
            session.flush()
            for key in ("hostname", "mac", "vendor", "open_ports", "cves", "classifications"):
                if key in h:
                    if key == "open_ports" and isinstance(h[key], list):
                        setattr(record, key, ",".join(str(p) for p in h[key]))
                    elif key in ("cves", "classifications"):
                        setattr(record, key, json.dumps(h[key]))
                    else:
                        setattr(record, key, h[key])
            if "banner" in h and h.get("banner"):
                record.banner = h["banner"]
            record.is_sniffing = 1 if h.get("is_sniffing") else 0
            evidence = h.get("sniffing_evidence")
            record.sniffing_evidence = json.dumps(evidence) if evidence else None
            if record.is_sniffing:
                session.add(
                    Alert(
                        host_id=record.id,
                        type="sniffing_detected",
                        severity="high",
                        message="Détection de possible écoute réseau (mode promiscue) sur cet hôte",
                        timestamp=utcnow(),
                    )
                )
            _track_mac(session, record.ip, h.get("mac"), record.id)
            for svc in h.get("services", []) or []:
                port = svc.get("port")
                if port is None:
                    continue
                existing = (
                    session.query(Service)
                    .filter_by(host_ip=h["ip"], port=port, scan_session_id=session_id)
                    .first()
                )
                if existing is None:
                    existing = Service(
                        host_ip=h["ip"],
                        host_id=record.id,
                        scan_session_id=session_id,
                        port=port,
                    )
                    session.add(existing)
                existing.name = svc.get("name")
                existing.product = svc.get("product")
                existing.manufacturer = svc.get("manufacturer")
                existing.version = svc.get("firmware") or svc.get("model") or svc.get("version")
                existing.banner = svc.get("banner")
                creds = svc.get("default_credentials")
                existing.default_credentials = json.dumps(creds) if creds else None
                existing.last_seen = utcnow()
        scan_session.total_hosts = len(hosts)
        scan_session.completed = len(hosts)
        scan_session.end_time = utcnow()
        scan_session.status = "completed"
        session.commit()
        return session_id
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _run_scan(scan_id: str, cidr: str, iface: str, timeout: int) -> None:
    try:
        port_scan_ports = tuple(int(p) for p in settings.port_scan_ports.split(",") if p.strip())
        hosts = scan_network(
            cidr,
            iface=iface,
            timeout=timeout,
            icmp_timeout=settings.icmp_timeout,
            tcp_timeout=settings.tcp_timeout,
            tcp_probes=tuple(int(p) for p in settings.tcp_probes.split(",") if p.strip()),
            port_scan=True,
            port_scan_ports=port_scan_ports,
            port_scan_timeout=settings.port_scan_timeout,
            banner_probe=settings.banner_probe,
            banner_timeout=settings.banner_timeout,
        )
        log.info(f"Scan {scan_id} completed: {len(hosts)} hosts found")

        for h in hosts:
            h["cves"] = detect_cves(h)

        engine = create_engine_from_yaml(settings.rules_yaml)
        classified_hosts = engine.classify_hosts(hosts)

        for h in hosts:
            ip = h.get("ip", "unknown")
            h["classifications"] = classified_hosts.get(ip, [])

        try:
            sniffers = detect_sniffers(iface=iface, cidr=cidr, timeout=float(timeout))
        except Exception as e:
            log.warning(f"Scan {scan_id} sniffer detection error: {e}")
            sniffers = []
        if sniffers:
            log.info(f"Scan {scan_id}: {len(sniffers)} possible sniffer(s) detected")
            sniffer_map = {}
            for s in sniffers:
                mac = (s.get("mac") or "").lower()
                if mac:
                    sniffer_map[mac] = s
            own_mac = (get_own_mac(iface) or "").lower()
            for h in hosts:
                mac = (h.get("mac") or "").lower()
                if mac and mac != own_mac and mac in sniffer_map:
                    h["is_sniffing"] = True
                    h["sniffing_evidence"] = [sniffer_map[mac]]
                    cls = h.get("classifications") or []
                    if not any(c.get("category") == "sniffing" for c in cls):
                        cls.append(
                            {
                                "rule_name": "sniffing_detected",
                                "category": "sniffing",
                                "description": "Réponse à une sonde ARP à IP aléatoire (mode promiscue probable)",
                                "priority": 1,
                                "tags": ["sniffing", "promiscuous"],
                            }
                        )
                    h["classifications"] = cls

        session_id = _persist_scan(hosts, cidr=cidr, iface=iface)
        log.info(f"Scan {scan_id} persisted (session {session_id})")

        _set_scan_state(scan_id, "completed", hosts=hosts, hosts_scanned=len(hosts))
    except Exception as e:
        log.error(f"Scan {scan_id} error: {e}")
        _set_scan_state(scan_id, "error", error=str(e))


class ScanRequest(BaseModel):
    cidr: Optional[str] = None
    iface: Optional[str] = None
    timeout: Optional[int] = 2

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, v: Optional[str]) -> Optional[str]:
        if v:
            try:
                ipaddress.ip_network(v, strict=False)
            except ValueError:
                raise ValueError("Invalid CIDR format")
        return v

    @field_validator("timeout")
    @classmethod
    def clamp_timeout(cls, v: Optional[int]) -> Optional[int]:
        if v is None:
            return v
        return max(1, min(int(v), 30))


class ScanStartedResponse(BaseModel):
    scan_id: str
    status: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    hosts_scanned: Optional[int] = None
    hosts: Optional[List[Dict[str, Any]]] = None
    error: Optional[str] = None


@router.post("/scan", response_model=ScanStartedResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Démarrer une session de scan sur un réseau (ou une IP unique) en arrière-plan."""
    cidr = request.cidr or settings.scan_default_cidr
    iface = request.iface or settings.scan_default_iface
    timeout = request.timeout or settings.scan_timeout

    scan_id = str(uuid.uuid4())
    _set_scan_state(scan_id, "running")
    background_tasks.add_task(_run_scan, scan_id, cidr, iface, timeout)

    return ScanStartedResponse(scan_id=scan_id, status="running")


@router.get("/scan/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    state = SCAN_REGISTRY.get(scan_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanStatusResponse(
        scan_id=scan_id,
        status=state.get("status", "running"),
        hosts_scanned=state.get("hosts_scanned"),
        hosts=state.get("hosts"),
        error=state.get("error"),
    )


@router.get("/cves/{cve_id}")
async def get_cve(cve_id: str):
    details = get_cve_details(cve_id)
    if details is None:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} introuvable")
    return details


@router.get("/cves")
async def list_cves():
    return {"cves": get_all_cve_ids()}


@router.get("/alerts")
async def list_alerts(host_ip: Optional[str] = None):
    try:
        session = SessionLocal()
        try:
            q = session.query(Alert)
            if host_ip:
                q = q.join(Host).filter(Host.ip == host_ip)
            alerts = q.order_by(Alert.timestamp.desc()).all()
            return [a.to_dict() for a in alerts]
        finally:
            session.close()
    except Exception as e:
        log.error(f"List alerts error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/hosts", response_model=List[Dict[str, Any]])
async def list_hosts(limit: int = 100, offset: int = 0):
    """Lister les hôtes connus, paginés par dernier scan."""
    if limit < 0:
        limit = 100
    if offset < 0:
        offset = 0
    try:
        session = SessionLocal()
        try:
            latest_session = (
                session.query(ScanSession)
                .order_by(ScanSession.start_time.desc())
                .first()
            )
            latest_ips = set()
            session_start = None
            if latest_session is not None:
                session_start = latest_session.start_time
                latest_ips = {
                    h.ip
                    for h in (
                        session.query(Host)
                        .filter(Host.scan_session_id == latest_session.id)
                        .all()
                    )
                }
            hosts = (
                session.query(Host)
                .options(joinedload(Host.services))
                .offset(offset)
                .limit(limit)
                .all()
            )
            out = []
            for h in hosts:
                d = h.to_dict()
                raw_services = [s.to_dict() for s in h.services]
                # Deduplicate services by port, keep the latest last_seen
                dedup: Dict[str, Dict[str, Any]] = {}
                for svc in raw_services:
                    key = str(svc.get("port"))
                    cur = dedup.get(key)
                    if cur is None or (
                        svc.get("last_seen") and (
                            not cur.get("last_seen")
                            or str(svc["last_seen"]) > str(cur["last_seen"])
                        )
                    ):
                        dedup[key] = svc
                d["services"] = list(dedup.values())
                d["online"] = h.ip in latest_ips
                d["is_new"] = bool(
                    session_start
                    and h.first_seen
                    and h.first_seen >= session_start
                    and h.ip in latest_ips
                )
                d["compliance"] = run_compliance_checks(d)
                out.append(d)
            return out
        finally:
            session.close()
    except Exception as e:
        log.error(f"List hosts error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/interfaces")
async def list_interfaces():
    """Lister les interfaces réseau de la machine (ip -o link / ip -o addr)."""
    try:
        link_out = subprocess.run(
            ["ip", "-o", "link"], capture_output=True, text=True, timeout=5
        ).stdout
        addr_out = subprocess.run(
            ["ip", "-o", "addr"], capture_output=True, text=True, timeout=5
        ).stdout

        ifaces: Dict[str, Dict[str, Any]] = {}
        for line in link_out.splitlines():
            cols = line.split()
            if len(cols) < 3:
                continue
            name = cols[1].rstrip(":")
            state = "UNKNOWN"
            mtu = None
            flags: set = set()
            if len(cols) > 2:
                flags = {
                    f.strip()
                    for f in cols[2].strip("<>").split(",")
                    if f.strip()
                }
            for i, c in enumerate(cols):
                if c == "state" and i + 1 < len(cols):
                    state = cols[i + 1]
                elif c == "mtu" and i + 1 < len(cols):
                    try:
                        mtu = int(cols[i + 1])
                    except ValueError:
                        pass
            ifaces[name] = {
                "name": name,
                "state": state,
                "flags": sorted(flags),
                "type": "loopback" if name == "lo" else ("wireless" if name.startswith(("wl", "wlan")) else "wired"),
                "mtu": mtu,
                "addresses": [],
            }
        for line in addr_out.splitlines():
            cols = line.split()
            if len(cols) < 4:
                continue
            name = cols[1]
            if len(cols) >= 3 and cols[2] in ("inet", "inet6"):
                addr = cols[3]
            else:
                continue
            if name not in ifaces:
                ifaces[name] = {"name": name, "state": "UNKNOWN", "flags": [], "type": "wired", "mtu": None, "addresses": []}
            ifaces[name]["addresses"].append(addr)
        return {"interfaces": list(ifaces.values())}
    except Exception as e:
        log.error(f"List interfaces error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class ScanIpRequest(BaseModel):
    ip: str
    port_scan: bool = True
    port_scan_ports: Optional[str] = None
    timeout: Optional[float] = None


def _run_ip_scan(scan_id: str, ip: str, args: Dict[str, Any]) -> None:
    try:
        kwargs: Dict[str, Any] = {
            "icmp_timeout": args.get("icmp_timeout", settings.icmp_timeout),
            "tcp_timeout": args.get("tcp_timeout", settings.tcp_timeout),
        }
        if args.get("port_scan"):
            ports = args.get("port_scan_ports") or settings.port_scan_ports
            kwargs["port_scan"] = True
            kwargs["port_scan_ports"] = tuple(int(p) for p in ports.split(",") if p.strip())
            kwargs["port_scan_timeout"] = settings.port_scan_timeout
            kwargs["banner_probe"] = settings.banner_probe
            kwargs["banner_timeout"] = settings.banner_timeout
        hosts = [scan_ip(ip, **kwargs)]
        log.info(f"Scan IP {scan_id} completed: {len(hosts)} host(s)")

        for h in hosts:
            h["cves"] = detect_cves(h)

        engine = create_engine_from_yaml(settings.rules_yaml)
        classified_hosts = engine.classify_hosts(hosts)
        for h in hosts:
            ip_addr = h.get("ip", "unknown")
            h["classifications"] = classified_hosts.get(ip_addr, [])

        try:
            session_id = _persist_scan(hosts, cidr=ip, iface=args.get("iface"))
            log.info(f"Scan IP {scan_id} persisted (session {session_id})")
        except Exception as e:
            log.error(f"Scan IP {scan_id} persistence failed: {e}")

        _set_scan_state(scan_id, "completed", hosts=hosts, hosts_scanned=len(hosts))
    except Exception as e:
        log.error(f"Scan IP {scan_id} error: {e}")
        _set_scan_state(scan_id, "error", error=str(e))


@router.post("/scan/ip", response_model=ScanStartedResponse)
async def start_ip_scan(request: ScanIpRequest, background_tasks: BackgroundTasks):
    try:
        ipaddress.ip_address(request.ip)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"IP invalide: {request.ip}")

    scan_id = str(uuid.uuid4())
    _set_scan_state(scan_id, "running")
    args = {
        "icmp_timeout": settings.icmp_timeout,
        "tcp_timeout": settings.tcp_timeout,
        "port_scan": request.port_scan,
        "port_scan_ports": request.port_scan_ports,
        "iface": settings.scan_default_iface,
    }
    if request.timeout is not None:
        args["icmp_timeout"] = request.timeout
        args["tcp_timeout"] = request.timeout
    background_tasks.add_task(_run_ip_scan, scan_id, request.ip, args)
    return ScanStartedResponse(scan_id=scan_id, status="running")


def _monitor_run() -> None:
    while not MONITOR_STOP.is_set():
        try:
            entries = list_arp_table()
        except Exception as e:
            log.error(f"Monitor poll error: {e}")
            with MONITOR_LOCK:
                MONITOR["last_error"] = str(e)
            MONITOR_STOP.wait(MONITOR["poll_interval"])
            continue
        with MONITOR_LOCK:
            now = utcnow()
            MONITOR["last_poll"] = now.isoformat()
            table = MONITOR["entries"]
            for e in entries:
                if e.get("state") in ("FAILED", "INCOMPLETE"):
                    continue
                rec = table.get(e["ip"])
                if rec is None:
                    rec = {
                        "ip": e["ip"],
                        "mac": e.get("mac"),
                        "interface": e.get("interface"),
                        "first_seen": now.isoformat(),
                        "last_seen": now.isoformat(),
                        "seen_count": 0,
                        "last_state": e.get("state"),
                    }
                    table[e["ip"]] = rec
                    MONITOR["total_seen"] += 1
                    with SessionLocal() as session:
                        host = session.query(Host).filter_by(ip=e["ip"]).first()
                        if host is None:
                            host = Host(ip=e["ip"])
                            session.add(host)
                            session.flush()
                        _track_mac(session, e["ip"], e.get("mac"), host.id)
                        session.commit()
                else:
                    if rec.get("mac") and e.get("mac") and rec["mac"] != e.get("mac"):
                        with SessionLocal() as session:
                            host = session.query(Host).filter_by(ip=e["ip"]).first()
                            if host:
                                host.last_seen = now
                                session.add(
                                    Alert(
                                        host_id=host.id,
                                        type="mac_change",
                                        severity="critical",
                                        message=f"MAC observé: {e.get('mac')} (table ARP)",
                                    )
                                )
                                session.commit()
                        rec["mac"] = e.get("mac")
                    rec["last_seen"] = now.isoformat()
                    rec["seen_count"] += 1
                    rec["last_state"] = e.get("state")
    with MONITOR_LOCK:
        MONITOR["running"] = False


@router.post("/monitor/start")
async def monitor_start(poll_interval: Optional[float] = None):
    with MONITOR_LOCK:
        if MONITOR["running"]:
            return {"running": True, "message": "Monitor déjà actif", "start_time": MONITOR["start_time"]}
        MONITOR["running"] = True
        MONITOR["start_time"] = utcnow().isoformat()
        MONITOR["entries"] = {}
        MONITOR["last_poll"] = None
        MONITOR["total_seen"] = 0
        MONITOR["poll_interval"] = poll_interval or 2.0
        MONITOR_STOP.clear()
        t = threading.Thread(target=_monitor_run, daemon=True)
        t.start()
    return {"running": True, "start_time": MONITOR["start_time"]}


@router.post("/monitor/stop")
async def monitor_stop():
    MONITOR_STOP.set()
    with MONITOR_LOCK:
        was_running = MONITOR["running"]
    return {"running": False, "was_running": was_running}


@router.get("/monitor/status")
async def monitor_status():
    """Retourner l'état du monitor (thread actif, compteur d'entrées)."""
    with MONITOR_LOCK:
        snapshot = dict(MONITOR)
        snapshot["entries"] = dict(MONITOR["entries"])
    return snapshot


@router.get("/wifi/interface")
async def wifi_interface():
    """Lister les interfaces WiFi détectées via `iw dev`."""
    try:
        out = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5).stdout
        ifaces = re.findall(r"^\s*Interface\s+(\w+)", out, re.MULTILINE)
        # exclure les interfaces P2P/Ad-hoc "Unnamed/non-netdev"
        return {"interfaces": ifaces, "available": bool(ifaces)}
    except Exception as e:
        return {"interfaces": [], "available": False, "error": str(e)}


@router.get("/wifi/scan")
async def wifi_scan(iface: Optional[str] = None):
    """Scanner les réseaux WiFi, mettre à jour la baseline et détecter les attaques."""
    try:
        if not iface:
            try:
                raw = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5).stdout
                m = re.search(r"^\s*Interface\s+(\w+)", raw, re.MULTILINE)
                iface = m.group(1) if m else None
            except Exception:
                iface = None
        if not iface:
            raise ValueError("Aucune interface WiFi trouvée")
        out = subprocess.run(
            ["nmcli", "-t", "-f", "BSSID,SSID,MODE,FREQ,SIGNAL,SECURITY", "device", "wifi", "list"],
            capture_output=True, text=True, timeout=15,
        )
        if out.returncode != 0:
            raise ValueError(out.stderr.strip() or "Échec du scan WiFi")
        networks: Dict[str, Dict[str, Any]] = {}
        for line in out.stdout.splitlines():
            parts = line.rsplit(":", 5)
            if len(parts) < 2:
                continue
            bssids = parts[0].split(";")
            ssid = parts[1]
            mode = parts[2]
            freq = parts[3]
            quality = parts[4]
            security = parts[5]
            for b in bssids:
                if b == "BSSID/SSID" or not b:
                    continue
                b = b.replace("\\:", ":")
                net = networks.setdefault(b, {
                    "bssid": b,
                    "ssid": ssid if ssid != "--" else "(caché)",
                    "mode": mode,
                    "channel": freq,
                    "quality": quality,
                    "security": security.split() if security else [],
                })
                if not net.get("mode"):
                    net["mode"] = mode
                if not net.get("channel"):
                    net["channel"] = freq
                if not net.get("quality"):
                    net["quality"] = quality
        db = SessionLocal()
        try:
            baseline = [{"bssid": wn.bssid, "ssid": wn.ssid or ""} for wn in db.query(WifiNetwork).all()]
            attacks = detect_attacks(list(networks.values()), baseline)
            now = utcnow()
            for net in networks.values():
                wn = db.query(WifiNetwork).filter(WifiNetwork.bssid == net["bssid"]).first()
                if wn:
                    wn.ssid = net["ssid"]
                    wn.mode = net["mode"]
                    wn.channel = net["channel"]
                    wn.security = json.dumps(net["security"])
                    wn.signal = net.get("quality")
                    wn.last_seen = now
                else:
                    db.add(WifiNetwork(
                        bssid=net["bssid"], ssid=net["ssid"], mode=net["mode"],
                        channel=net["channel"], security=json.dumps(net["security"]),
                        signal=net.get("quality"), first_seen=now, last_seen=now,
                    ))
            for atk in attacks:
                exists = db.query(WifiAttack).filter(
                    WifiAttack.bssid == atk["bssid"],
                    WifiAttack.type == atk["type"],
                    WifiAttack.acknowledged == 0,
                ).first()
                if exists:
                    exists.severity = atk["severity"]
                    exists.description = atk["description"]
                else:
                    db.add(WifiAttack(
                        bssid=atk["bssid"], ssid=atk["ssid"], type=atk["type"],
                        severity=atk["severity"], description=atk["description"],
                    ))
            db.commit()
        finally:
            db.close()
        return {"iface": iface, "networks": list(networks.values()), "attacks": attacks}
    except Exception as e:
        log.error(f"WiFi scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/wifi/attacks")
async def wifi_attacks(acknowledged: Optional[bool] = None):
    """Lister les attaques WiFi détectées (optionnellement filtrées par statut d'acquittement)."""
    db = SessionLocal()
    try:
        q = db.query(WifiAttack)
        if acknowledged is not None:
            q = q.filter(WifiAttack.acknowledged == (1 if acknowledged else 0))
        attacks = q.order_by(WifiAttack.created_at.desc()).all()
        return {"attacks": [a.to_dict() for a in attacks]}
    finally:
        db.close()


@router.post("/wifi/networks/{bssid}/acknowledge")
async def wifi_acknowledge(bssid: str):
    """Acquitter toutes les attaques et le réseau d'un BSSID donné."""
    if not re.fullmatch(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid):
        raise HTTPException(status_code=400, detail="BSSID invalide")
    db = SessionLocal()
    try:
        wn = db.query(WifiNetwork).filter(WifiNetwork.bssid == bssid).first()
        if wn:
            wn.acknowledged = 1
        n = db.query(WifiAttack).filter(
            WifiAttack.bssid == bssid, WifiAttack.acknowledged == 0).update({"acknowledged": 1})
        db.commit()
        return {"bssid": bssid, "attacks_acknowledged": n, "network_found": bool(wn)}
    finally:
        db.close()


@router.delete("/wifi/attacks/{attack_id}")
async def wifi_delete_attack(attack_id: int):
    """Supprimer une attaque WiFi par identifiant."""
    db = SessionLocal()
    try:
        atk = db.query(WifiAttack).filter(WifiAttack.id == attack_id).first()
        if not atk:
            raise HTTPException(status_code=404, detail="Attaque introuvable")
        db.delete(atk)
        db.commit()
        return {"deleted": attack_id}
    finally:
        db.close()


@router.delete("/wifi/attacks")
async def wifi_clear_attacks():
    """Supprimer toutes les attaques WiFi enregistrées."""
    db = SessionLocal()
    try:
        n = db.query(WifiAttack).delete()
        db.commit()
        return {"deleted": n}
    finally:
        db.close()
