"""Tests des nouvelles fonctionnalités : CVE détaillées, conformité, suivi MAC, alertes."""

import asyncio
import json
import subprocess
from datetime import datetime
from unittest.mock import patch, MagicMock

import pytest
from fastapi import BackgroundTasks, HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from classifier.cves import detect_cves, get_cve_details, get_all_cve_ids
from classifier.compliance import run_compliance_checks, INSECURE_PORTS, _open_port_list
from scanner.passive import list_arp_table
from db.models import Host, Service, Alert, MacHistory, Base
from api.routes import MONITOR, MONITOR_STOP


class TestCveDetails:
    def test_valid_cve_returns_dict(self):
        details = get_cve_details("CVE-2021-36260")
        assert details is not None
        assert details["cve"] == "CVE-2021-36260"
        assert details["cvss"] == 8.6
        assert details["severity"] == "high"
        assert "nvd_url" in details
        assert "description" in details

    def test_lowercase_normalized(self):
        details = get_cve_details("cve-2021-36260")
        assert details is not None
        assert details["cve"] == "CVE-2021-36260"

    def test_unknown_cve_returns_none(self):
        assert get_cve_details("CVE-1999-0001") is None

    def test_all_cve_ids(self):
        ids = get_all_cve_ids()
        assert len(ids) == 17
        assert "CVE-2021-36260" in ids
        assert "CVE-2021-30605" in ids


class TestDetectCves:
    def test_camera_vendor_signature(self):
        host = {"open_ports": [554, 80], "vendor": "Hikvision"}
        cves = detect_cves(host)
        ids = [c["cve"] for c in cves]
        assert "CVE-2021-36260" in ids
        sev = {c["cve"]: c["severity"] for c in cves}
        assert sev["CVE-2021-36260"] == "high"

    def test_mqtt_ports(self):
        host = {"open_ports": [1883]}
        cves = detect_cves(host)
        assert len(cves) == 3
        sev = {c["cve"]: c["severity"] for c in cves}
        assert sev["CVE-2021-30605"] == "critical"
        assert sev["CVE-2021-30606"] == "critical"
        assert sev["CVE-2021-3193"] == "medium"

    def test_printer_hostname(self):
        host = {"open_ports": [631], "hostname": "printer01"}
        cves = detect_cves(host)
        assert len(cves) == 3
        for c in cves:
            assert c["severity"] == "high"

    def test_no_match(self):
        host = {"open_ports": [22, 25]}
        assert detect_cves(host) == []

    def test_string_ports(self):
        host = {"open_ports": "1883"}
        cves = detect_cves(host)
        assert len(cves) == 3

    def test_each_cve_has_details_filled(self):
        host = {"open_ports": [1883]}
        for c in detect_cves(host):
            assert c["cve"]
            assert c["severity"] in ("critical", "high", "medium")
            assert "note" in c
            assert "source" in c


class TestCompliance:
    def test_telnet_insecure_protocol(self):
        findings = run_compliance_checks({"open_ports": [23]})
        assert any(
            f["check"] == "insecure_protocol" and f["severity"] == "critical" and "Telnet" in f["message"]
            for f in findings
        )

    def test_missing_tls(self):
        findings = run_compliance_checks({"open_ports": [80]})
        assert any(
            f["check"] == "missing_tls" and f["severity"] == "high" for f in findings
        )

    def test_no_missing_tls_when_443(self):
        findings = run_compliance_checks({"open_ports": [80, 443]})
        assert not any(f["check"] == "missing_tls" for f in findings)

    def test_default_credentials(self):
        host = {
            "services": [
                {
                    "name": "RTSP",
                    "port": 554,
                    "default_credentials": [{"username": "admin", "password": "admin"}],
                }
            ]
        }
        findings = run_compliance_checks(host)
        creds = [f for f in findings if f["check"] == "default_credentials"]
        assert creds
        assert creds[0]["severity"] == "high"
        assert "admin/admin" in creds[0]["message"]

    def test_clean_host_no_findings(self):
        assert run_compliance_checks({"open_ports": [443, 22]}) == []

    def test_open_port_list_handles_string(self):
        assert _open_port_list({"open_ports": "23, 80"}) == [23, 80]

    def test_insecure_ports_map(self):
        assert INSECURE_PORTS[21] == "FTP"
        assert INSECURE_PORTS[23] == "Telnet"


class TestTrackMac:
    @pytest.fixture
    def session(self):
        from db.models import Base

        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        s = Session()
        yield s
        s.close()

    def _host_ip(self):
        return "10.0.0.50"

    def test_first_mac_recorded_no_alert(self, session):
        from api.routes import _track_mac

        _track_mac(session, self._host_ip(), "AA:BB:CC:DD:EE:01", host_id=1)
        session.flush()
        from db.models import MacHistory, Alert

        assert session.query(MacHistory).count() == 1
        assert session.query(Alert).count() == 0

    def test_same_mac_no_alert(self, session):
        from api.routes import _track_mac

        _track_mac(session, self._host_ip(), "AA:BB:CC:DD:EE:01", host_id=1)
        _track_mac(session, self._host_ip(), "AA:BB:CC:DD:EE:01", host_id=1)
        session.flush()
        from db.models import MacHistory, Alert

        assert session.query(MacHistory).count() == 1
        assert session.query(Alert).count() == 0

    def test_changed_mac_creates_alert(self, session):
        from api.routes import _track_mac

        _track_mac(session, self._host_ip(), "AA:BB:CC:DD:EE:01", host_id=1)
        _track_mac(session, self._host_ip(), "FF:EE:DD:CC:BB:AA", host_id=1)
        session.flush()
        from db.models import MacHistory, Alert

        assert session.query(MacHistory).count() == 2
        alerts = session.query(Alert).all()
        assert len(alerts) == 1
        assert alerts[0].type == "mac_change"
        assert alerts[0].severity == "critical"
        assert alerts[0].host_id == 1
        d = alerts[0].to_dict()
        assert d["type"] == "mac_change"
        assert "MAC changé" in d["message"]

    def test_none_mac_noop(self, session):
        from api.routes import _track_mac

        _track_mac(session, self._host_ip(), None, host_id=1)
        _track_mac(session, self._host_ip(), "", host_id=1)
        session.flush()
        from db.models import MacHistory

        assert session.query(MacHistory).count() == 0


# ---------------------------------------------------------------------------
# Nouvelles fonctionnalités : ARP passif, interfaces, scan IP, monitor, WiFi
# ---------------------------------------------------------------------------


class TestListArpTable:
    def test_parses_arp_entries(self):
        fake = MagicMock()
        fake.returncode = 0
        fake.stdout = (
            "10.0.0.10 dev eth0 lladdr AA:BB:CC:DD:EE:01 REACHABLE\n"
            "10.0.0.11 dev eth0 lladdr aa:bb:cc:dd:ee:02 STALE\n"
            "10.0.0.99 dev eth0 FAILED\n"
            "garbage line without lladdr\n"
        )
        with patch("scanner.passive.subprocess.run", return_value=fake):
            entries = list_arp_table()
        assert len(entries) == 2
        assert entries[0]["ip"] == "10.0.0.10"
        assert entries[0]["interface"] == "eth0"
        assert entries[0]["mac"] == "aa:bb:cc:dd:ee:01"
        assert entries[0]["state"] == "REACHABLE"
        assert entries[1]["mac"] == "aa:bb:cc:dd:ee:02"
        assert entries[1]["state"] == "STALE"

    def test_timeout_returns_empty(self):
        with patch(
            "scanner.passive.subprocess.run",
            side_effect=subprocess.TimeoutExpired("ip", 5),
        ):
            assert list_arp_table() == []

    def test_oserror_returns_empty(self):
        with patch("scanner.passive.subprocess.run", side_effect=OSError):
            assert list_arp_table() == []


class TestListInterfaces:
    def test_parses_interfaces(self):
        from api.routes import list_interfaces

        link_stdout = (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN mode DEFAULT group default qlen 1000\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP mode DEFAULT group default qlen 1000\n"
            "3: wlan0: <BROADCAST,MULTICAST> mtu 1500 state DOWN mode DEFAULT group default qlen 1000\n"
        )

        def fake_run(cmd, **kwargs):
            m = MagicMock()
            m.returncode = 0
            if cmd[2] == "link":
                m.stdout = link_stdout
            elif cmd[2] == "addr":
                m.stdout = (
                    "1: lo    inet 127.0.0.1/8 scope host lo\n"
                    "2: eth0    inet 192.0.2.130/24 brd 192.0.2.255 scope global eth0\n"
                )
            return m

        with patch("api.routes.subprocess.run", side_effect=fake_run):
            result = asyncio.run(list_interfaces())

        ifaces = {i["name"]: i for i in result["interfaces"]}
        assert ifaces["lo"]["type"] == "loopback"
        assert any(
            a.startswith("127.0.0.1") for a in ifaces["lo"]["addresses"]
        )
        assert ifaces["eth0"]["type"] == "wired"
        assert ifaces["eth0"]["state"] == "UP"
        assert ifaces["wlan0"]["type"] == "wireless"
        assert ifaces["wlan0"]["state"] == "DOWN"


class TestScanIpValidation:
    def test_invalid_ip_raises_422(self):
        from api.routes import start_ip_scan, ScanIpRequest

        with pytest.raises(HTTPException) as exc:
            asyncio.run(start_ip_scan(ScanIpRequest(ip="not-a-valid-ip"), BackgroundTasks()))
        assert exc.value.status_code == 422


class TestStartIpScan:
    def test_returns_running_and_queues_task(self):
        from api.routes import start_ip_scan, ScanIpRequest, _run_ip_scan

        bt = BackgroundTasks()
        resp = asyncio.run(
            start_ip_scan(ScanIpRequest(ip="10.0.0.50"), bt)
        )
        assert resp.status == "running"
        assert resp.scan_id
        assert len(bt.tasks) == 1
        assert bt.tasks[0].func == _run_ip_scan


class _MonitorBase:
    @pytest.fixture
    def reset_monitor(self, monkeypatch):
        import api.routes as routes

        routes.MONITOR["running"] = False
        routes.MONITOR["start_time"] = None
        routes.MONITOR["poll_interval"] = 0.01
        MONITOR["entries"] = {}
        MONITOR["last_poll"] = None
        MONITOR["total_seen"] = 0
        MONITOR_STOP.clear()
        yield
        MONITOR_STOP.clear()

    def _seed_db(self, monkeypatch):
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        monkeypatch.setattr("api.routes.SessionLocal", Session)
        return Session


class TestMonitorNewHost(_MonitorBase):
    def test_new_host_created_and_tracked(self, reset_monitor, monkeypatch):
        import api.routes as routes

        Session = self._seed_db(monkeypatch)

        calls = {"n": 0}

        def fake_arp():
            calls["n"] += 1
            if calls["n"] >= 2:
                MONITOR_STOP.set()
                return []
            return [
                {"ip": "10.0.0.5", "interface": "eth0", "mac": "aa:bb:cc:dd:ee:99", "state": "REACHABLE"}
            ]

        monkeypatch.setattr(routes, "list_arp_table", fake_arp)
        MONITOR["running"] = True
        routes._monitor_run()

        assert MONITOR["total_seen"] == 1
        entry = MONITOR["entries"].get("10.0.0.5")
        assert entry is not None
        assert entry["mac"] == "aa:bb:cc:dd:ee:99"

        s = Session()
        try:
            hosts = s.query(Host).filter_by(ip="10.0.0.5").all()
            assert len(hosts) == 1
            assert hosts[0].mac == "aa:bb:cc:dd:ee:99"
            assert s.query(MacHistory).filter_by(host_ip="10.0.0.5").count() == 1
            assert s.query(Alert).count() == 0
        finally:
            s.close()


class TestMonitorMacChange(_MonitorBase):
    def test_mac_change_creates_alert(self, reset_monitor, monkeypatch):
        import api.routes as routes

        Session = self._seed_db(monkeypatch)
        s = Session()
        host = Host(ip="10.0.0.6", mac="aa:bb:cc:dd:ee:11")
        s.add(host)
        s.commit()
        s.close()

        calls = {"n": 0}
        macs = ["aa:bb:cc:dd:ee:11", "ff:ee:dd:cc:bb:00"]

        def fake_arp():
            calls["n"] += 1
            if calls["n"] == 1:
                return [{"ip": "10.0.0.6", "interface": "eth0", "mac": macs[0], "state": "REACHABLE"}]
            if calls["n"] == 2:
                return [{"ip": "10.0.0.6", "interface": "eth0", "mac": macs[1], "state": "REACHABLE"}]
            MONITOR_STOP.set()
            return []

        monkeypatch.setattr(routes, "list_arp_table", fake_arp)
        MONITOR["running"] = True
        routes._monitor_run()

        s = Session()
        try:
            alerts = s.query(Alert).filter_by(host_ip=None) if False else s.query(Alert).all()
            mac_alerts = [a for a in alerts if a.type == "mac_change"]
            assert len(mac_alerts) == 1
            assert mac_alerts[0].severity == "critical"
            assert mac_alerts[0].host_id == 1
        finally:
            s.close()


class TestMonitorSkipsFailed(_MonitorBase):
    def test_failed_entries_not_tracked(self, reset_monitor, monkeypatch):
        import api.routes as routes

        Session = self._seed_db(monkeypatch)

        def fake_arp():
            MONITOR_STOP.set()
            return [
                {"ip": "10.0.0.7", "interface": "eth0", "mac": "aa:bb:cc:dd:ee:77", "state": "FAILED"},
                {"ip": "10.0.0.8", "interface": "eth0", "mac": "aa:bb:cc:dd:ee:88", "state": "REACHABLE"},
            ]

        monkeypatch.setattr(routes, "list_arp_table", fake_arp)
        MONITOR["running"] = True
        routes._monitor_run()

        assert "10.0.0.7" not in MONITOR["entries"]
        assert "10.0.0.8" in MONITOR["entries"]
        s = Session()
        try:
            assert s.query(Host).filter_by(ip="10.0.0.7").count() == 0
            assert s.query(Host).filter_by(ip="10.0.0.8").count() == 1
        finally:
            s.close()


class TestWifiInterface:
    IW_DEV_OK = (
        "Interface wlan0\n"
        "\tifindex 3\n"
        "\twdev 0x3\n"
        "\taddr AA:BB:CC:DD:EE:01\n"
        "\n"
        "Interface wlan1\n"
        "\tifindex 5\n"
        "\twdev 0x5\n"
        "\taddr FF:EE:DD:CC:BB:AA\n"
    )

    def test_lists_wifi_interfaces(self):
        from api.routes import wifi_interface

        m = MagicMock()
        m.returncode = 0
        m.stdout = self.IW_DEV_OK
        with patch("api.routes.subprocess.run", return_value=m):
            result = asyncio.run(wifi_interface())
        assert result["available"] is True
        names = list(result["interfaces"])
        assert names == ["wlan0", "wlan1"]

    def test_error_returns_unavailable(self):
        from api.routes import wifi_interface

        with patch("api.routes.subprocess.run", side_effect=OSError("iw introuvable")):
            result = asyncio.run(wifi_interface())
        assert result["interfaces"] == []
        assert result["available"] is False
        assert "error" in result


class TestWifiScanNoInterface:
    def test_no_iface_raises_500(self):
        from api.routes import wifi_scan

        m = MagicMock()
        m.returncode = 0
        m.stdout = ""
        with patch("api.routes.subprocess.run", return_value=m):
            with pytest.raises(HTTPException) as exc:
                asyncio.run(wifi_scan())
        assert exc.value.status_code == 500


class TestPortDedup:
    def test_list_hosts_dedupes_services(self, monkeypatch):
        from api.routes import list_hosts
        from db.models import ScanSession

        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        monkeypatch.setattr("api.routes.SessionLocal", Session)

        s = Session()
        sess = ScanSession(status="completed", cidr="10.0.0.0/24")
        s.add(sess)
        s.flush()
        host = Host(ip="10.0.0.1", scan_session_id=sess.id)
        s.add(host)
        s.flush()
        s.add(Service(host_id=host.id, host_ip="10.0.0.1", port=554, name="RTSP",
                      first_seen=datetime(2026, 1, 1), last_seen=datetime(2026, 1, 1)))
        s.add(Service(host_id=host.id, host_ip="10.0.0.1", port=554, name="RTSP",
                      first_seen=datetime(2026, 1, 2), last_seen=datetime(2026, 1, 2)))
        s.add(Service(host_id=host.id, host_ip="10.0.0.1", port=80, name="HTTP",
                      first_seen=datetime(2026, 1, 1), last_seen=datetime(2026, 1, 1)))
        s.commit()
        s.close()

        result = asyncio.run(list_hosts())
        assert len(result) == 1
        host_out = result[0]
        assert host_out["ip"] == "10.0.0.1"
        ports = sorted(sv["port"] for sv in host_out["services"])
        assert ports == [80, 554]
        svc554 = [sv for sv in host_out["services"] if sv["port"] == 554][0]
        assert svc554["last_seen"].startswith("2026-01-02")


# Détection passive de sniffing (ARP à IP aléatoire)


class TestSniffingModule:
    def test_get_own_mac_no_iface(self):
        from scanner.sniffing import get_own_mac

        assert get_own_mac(None) is None
        assert get_own_mac() is None

    def test_get_own_mac_reads_sysfs(self, monkeypatch):
        import builtins
        import scanner.sniffing as sniffing

        real_open = builtins.open

        class _FakeFile:
            def __init__(self, content):
                self._c = content

            def read(self):
                return self._c

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_open(path, *a, **k):
            if path.startswith("/sys/class/net/"):
                return _FakeFile("AA:BB:CC:DD:EE:FF\n")
            return real_open(path, *a, **k)

        monkeypatch.setattr(builtins, "open", fake_open)
        assert sniffing.get_own_mac("eth0") == "aa:bb:cc:dd:ee:ff"

    def test_pick_fake_ip_within_subnet(self):
        from ipaddress import ip_network, ip_address
        from scanner.sniffing import _pick_fake_ip

        for _ in range(20):
            ip = _pick_fake_ip("192.0.2.0/24")
            assert ip_address(ip) in ip_network("192.0.2.0/24")

    def test_detect_sniffers_flags_mac(self):
        import scanner.sniffing as sn

        rcv = MagicMock()
        rcv.getfieldval.return_value = "de:ad:be:ef:00:01"
        sent = MagicMock()

        with patch.object(sn, "get_own_mac", return_value="aa:bb:cc:dd:ee:ff"):
            with patch("scapy.all.srp", return_value=([(sent, rcv)], [])):
                result = sn.detect_sniffers(iface="eth0", cidr="192.0.2.0/24", probes=1)

        assert len(result) == 1
        assert result[0]["mac"] == "de:ad:be:ef:00:01"
        assert "random_ip" in result[0]
        assert "ts" in result[0]

    def test_detect_sniffers_excludes_own_mac(self):
        import scanner.sniffing as sn

        rcv = MagicMock()
        rcv.getfieldval.return_value = "AA:BB:CC:DD:EE:FF"
        sent = MagicMock()

        with patch.object(sn, "get_own_mac", return_value="aa:bb:cc:dd:ee:ff"):
            with patch("scapy.all.srp", return_value=([(sent, rcv)], [])):
                result = sn.detect_sniffers(iface="eth0", cidr="192.0.2.0/24", probes=1)

        assert result == []

    def test_parse_evidence(self):
        import json
        from scanner.sniffing import parse_evidence

        ev = [{"mac": "aa:aa:aa:aa:aa:aa", "random_ip": "1.1.1.1", "ts": "t"}]
        assert parse_evidence(None) == []
        assert parse_evidence("") == []
        assert parse_evidence(ev) == ev
        assert parse_evidence(json.dumps(ev)) == ev
        assert parse_evidence("not json") == []


class TestSniffingPersistence:
    def test_persist_scan_flags_sniffing_and_alerts(self, monkeypatch):
        from api.routes import _persist_scan
        from db.models import ScanSession

        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        monkeypatch.setattr("api.routes.SessionLocal", Session)

        hosts = [
            {
                "ip": "10.0.0.5",
                "mac": "de:ad:be:ef:00:01",
                "is_sniffing": True,
                "sniffing_evidence": [
                    {"mac": "de:ad:be:ef:00:01", "random_ip": "10.0.0.99", "ts": "x"}
                ],
            },
            {"ip": "10.0.0.6", "mac": "11:22:33:44:55:66"},
        ]

        session_id = _persist_scan(hosts, cidr="10.0.0.0/24")
        session = Session()
        try:
            flagged = session.query(Host).filter_by(ip="10.0.0.5").first()
            assert flagged.is_sniffing == 1
            assert flagged.sniffing_evidence is not None
            evidence = json.loads(flagged.sniffing_evidence)
            assert evidence[0]["random_ip"] == "10.0.0.99"

            alerts = session.query(Alert).all()
            sniff_alerts = [a for a in alerts if a.type == "sniffing_detected"]
            assert len(sniff_alerts) == 1
            assert sniff_alerts[0].severity == "high"
            assert sniff_alerts[0].host_id == flagged.id

            clean = session.query(Host).filter_by(ip="10.0.0.6").first()
            assert clean.is_sniffing == 0
            assert clean.sniffing_evidence is None
        finally:
            session.close()

    def test_run_scan_flags_host_as_sniffing(self, monkeypatch):
        from api import routes as r

        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        monkeypatch.setattr(r, "SessionLocal", Session)
        monkeypatch.setattr(
            r,
            "detect_sniffers",
            lambda **kw: [
                {"mac": "de:ad:be:ef:00:01", "random_ip": "10.0.0.77", "ts": "x"}
            ],
        )
        fake_engine = MagicMock()
        fake_engine.classify_hosts.return_value = {}
        monkeypatch.setattr(r, "create_engine_from_yaml", lambda p: fake_engine)
        monkeypatch.setattr(r, "get_own_mac", lambda iface=None: "aa:bb:cc:dd:ee:ff")

        scan_id = "test-scan-sniff"
        r.SCAN_REGISTRY.clear()
        r._set_scan_state(scan_id, "running")

        with patch.object(r, "scan_network", return_value=[
            {"ip": "10.0.0.5", "mac": "de:ad:be:ef:00:01", "hostname": "h"},
            {"ip": "10.0.0.6", "mac": "11:22:33:44:55:66"},
        ]), patch.object(r, "detect_cves", return_value=[]):
            r._run_scan(scan_id, "10.0.0.0/24", "eth0", timeout=1)

        state = r.SCAN_REGISTRY[scan_id]
        assert state["status"] == "completed"
        hosts = state.get("hosts", [])
        flagged = [h for h in hosts if h.get("is_sniffing")]
        assert len(flagged) == 1
        assert flagged[0]["ip"] == "10.0.0.5"
        assert flagged[0]["sniffing_evidence"][0]["random_ip"] == "10.0.0.77"
        assert any(
            c.get("category") == "sniffing" for c in flagged[0]["classifications"]
        )
        clean = [h for h in hosts if h["ip"] == "10.0.0.6"][0]
        assert not clean.get("is_sniffing")
