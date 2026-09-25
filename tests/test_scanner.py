"""Tests for scanner/core.py: ARP/TCP/ICMP scanning with OS fingerprinting."""

import pytest
from unittest.mock import Mock, patch, MagicMock

from scapy.all import IP, TCP

from scanner.core import (
    arp_scan,
    guess_os_by_ttl,
    os_fingerprint,
    tcp_port_scan,
    enrich_host,
    scan_network,
    DEFAULT_PORTS,
)


class TestGuessOsByTTL:
    """Test OS detection heuristic based on TTL."""

    def test_linux_ttl_64(self):
        """Linux default TTL=64."""
        assert guess_os_by_ttl(64) == "Linux/macOS/Unix (TTL=64)"

    def test_linux_ttl_60(self):
        """Linux TTL in range 1-70."""
        assert guess_os_by_ttl(60) == "Linux/macOS/Unix (TTL=64)"

    def test_windows_ttl_128(self):
        """Windows default TTL=128."""
        assert guess_os_by_ttl(128) == "Windows (TTL=128)"

    def test_windows_ttl_120(self):
        """Windows TTL in range 71-140."""
        assert guess_os_by_ttl(120) == "Windows (TTL=128)"

    def test_network_ttl_255(self):
        """Network/embedded default TTL=255."""
        assert guess_os_by_ttl(255) == "Network/embedded (TTL=255)"

    def test_network_ttl_200(self):
        """Network TTL >140."""
        assert guess_os_by_ttl(200) == "Network/embedded (TTL=255)"

    def test_none_ttl(self):
        """None TTL returns None."""
        assert guess_os_by_ttl(None) is None


class TestArpScan:
    """Test ARP scanning (mocked Scapy)."""

    @patch("scanner.core.ip_network")
    @patch("scanner.core.ARP")
    @patch("scanner.core.Ether")
    @patch("scanner.core.srp")
    def test_arp_scan_returns_list(self, mock_srp, mock_ether, mock_arp, mock_ip_net):
        """ARP scan returns list of {ip, mac} dicts."""
        mock_ip_net.return_value = MagicMock()
        mock_ip_net.return_value.__str__ = lambda self: "10.0.0.0/24"

        mock_rcv = Mock()
        mock_rcv.psrc = "10.0.0.1"
        mock_rcv.hwsrc = "aa:bb:cc:dd:ee:01"

        mock_ans = [(Mock(), mock_rcv)]
        mock_srp.return_value = (mock_ans, [])

        hosts = arp_scan("10.0.0.0/24", iface="eth0", timeout=2)

        assert len(hosts) == 1
        assert hosts[0]["ip"] == "10.0.0.1"
        assert hosts[0]["mac"] == "aa:bb:cc:dd:ee:01"

    @patch("scanner.core.ip_network")
    @patch("scanner.core.srp")
    def test_arp_scan_multiple_hosts(self, mock_srp, mock_ip_net):
        """ARP scan with multiple hosts."""
        mock_ip_net.return_value = MagicMock()
        mock_ip_net.return_value.__str__ = lambda self: "10.0.0.0/24"

        mock_rcv1 = Mock()
        mock_rcv1.psrc = "10.0.0.1"
        mock_rcv1.hwsrc = "aa:bb:cc:dd:ee:01"

        mock_rcv2 = Mock()
        mock_rcv2.psrc = "10.0.0.2"
        mock_rcv2.hwsrc = "aa:bb:cc:dd:ee:02"

        mock_ans = [(Mock(), mock_rcv1), (Mock(), mock_rcv2)]
        mock_srp.return_value = (mock_ans, [])

        hosts = arp_scan("10.0.0.0/24")

        assert len(hosts) == 2
        assert hosts[0]["ip"] == "10.0.0.1"
        assert hosts[1]["ip"] == "10.0.0.2"


class TestOsFingerprint:
    """Test OS fingerprinting (mocked Scapy)."""

    @patch("scanner.core.sr1")
    def test_os_fingerprint_icmp_success(self, mock_sr1):
        """ICMP echo returns TTL."""
        mock_ip_layer = Mock()
        mock_ip_layer.ttl = 64
    
        mock_rcv = Mock()
        mock_rcv.haslayer.return_value = True
        mock_rcv.getlayer.return_value = mock_ip_layer
    
        mock_sr1.return_value = mock_rcv
    
        os_guess, ttl, method = os_fingerprint("10.0.0.1", icmp_timeout=1.0)
    
        assert os_guess == "Linux/macOS/Unix (TTL=64)"
        assert ttl == 64
        assert method == "ICMP"

    @patch("scanner.core.sr")
    @patch("scanner.core.sr1")
    def test_os_fingerprint_icmp_none(self, mock_sr1, mock_sr):
        """No ICMP response."""
        mock_sr1.return_value = None
        mock_sr.return_value = ([], [])
    
        os_guess, ttl, method = os_fingerprint("10.0.0.1", icmp_timeout=1.0)
    
        assert os_guess is None
        assert ttl is None
        assert method == "none"

    @patch("scanner.core.sr")
    @patch("scanner.core.sr1")
    def test_os_fingerprint_tcp_success(self, mock_sr1, mock_sr):
        """TCP probe returns TTL."""
        mock_rcv = IP(ttl=128)/TCP(flags="SA")

        mock_sr1.return_value = None
        mock_sr.return_value = ([(Mock(), mock_rcv)], [])

        os_guess, ttl, method = os_fingerprint(
            "10.0.0.1", icmp_timeout=0.1, tcp_timeout=0.1, tcp_probes=(443,)
        )

        assert os_guess == "Windows (TTL=128)"
        assert ttl == 128
        assert "TCP:443" in method

    @patch("scanner.core.sr1")
    def test_os_fingerprint_exception(self, mock_sr1):
        """Exception in ICMP probe fallbacks to TCP."""
        mock_sr1.side_effect = Exception("Network error")

        mock_rcv = IP(ttl=64)/TCP(flags="SA")
        mock_sr = Mock(return_value=([(Mock(), mock_rcv)], []))

        with patch("scanner.core.sr", mock_sr):
            os_guess, ttl, method = os_fingerprint("10.0.0.1", icmp_timeout=0.1, tcp_timeout=0.1)

        assert os_guess == "Linux/macOS/Unix (TTL=64)"
        assert ttl == 64


class TestEnrichHost:
    """Test host enrichment."""

    @patch("socket.gethostbyaddr")
    def test_enrich_host_no_mac(self, mock_gethostbyaddr):
        """Enrich without MAC."""
        mock_gethostbyaddr.return_value = ("host.example.com", [], [])

        result = enrich_host("10.0.0.1", mac=None, icmp_timeout=0.1, tcp_timeout=0.1)

        assert result["ip"] == "10.0.0.1"
        assert result["mac"] is None
        assert result["hostname"] == "host.example.com"
        assert result["mac_type"] is None
        assert result["vendor"] is None

    @patch("socket.gethostbyaddr")
    @patch("scapy.all.sr1")
    @patch("scapy.all.sr")
    def test_enrich_host_with_mac(self, mock_sr, mock_sr1, mock_gethostbyaddr):
        """Enrich with MAC address."""
        mock_gethostbyaddr.return_value = (None, [], [])

        mock_ip_layer = Mock()
        mock_ip_layer.ttl = 64
        mock_rcv = Mock()
        mock_rcv.haslayer.return_value = True
        mock_rcv.getlayer.return_value = mock_ip_layer

        mock_sr1.return_value = None
        mock_sr.return_value = [(Mock(), mock_rcv)]

        with patch("scanner.core.manuf.MacParser") as mock_parser:
            mock_parser.return_value.get_manuf_long.return_value = "Cisco Systems"

            result = enrich_host("10.0.0.1", mac="aa:bb:cc:dd:ee:00", icmp_timeout=0.1, tcp_timeout=0.1)

            assert result["mac"] == "aa:bb:cc:dd:ee:00"
            assert result["mac_type"] == "unicast"
            assert result["vendor"] == "Cisco Systems"

    @patch("socket.gethostbyaddr")
    def test_enrich_host_multicast_mac(self, mock_gethostbyaddr):
        """Multicast MAC detected."""
        mock_gethostbyaddr.return_value = (None, [], [])

        result = enrich_host("10.0.0.1", mac="01:00:5e:00:00:01", icmp_timeout=0.1, tcp_timeout=0.1)

        assert result["mac_type"] == "multicast"

    @patch("socket.gethostbyaddr")
    def test_enrich_host_invalid_mac(self, mock_gethostbyaddr):
        """Invalid MAC handled gracefully."""
        mock_gethostbyaddr.return_value = (None, [], [])

        result = enrich_host("10.0.0.1", mac="invalid-mac", icmp_timeout=0.1, tcp_timeout=0.1)

        assert result["mac_type"] == "unknown"


class TestScanNetwork:
    """Test full network scan."""

    @patch("scanner.core.arp_scan")
    @patch("scanner.core.enrich_host")
    def test_scan_network_full(self, mock_enrich, mock_arp_scan):
        """Full scan returns enriched hosts."""
        mock_arp_scan.return_value = [
            {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:01"},
            {"ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:02"},
        ]

        mock_enrich.side_effect = [
            {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:01", "os_guess": "Linux"},
            {"ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:02", "os_guess": "Windows"},
        ]

        hosts = scan_network("10.0.0.0/24", iface="eth0", timeout=2, icmp_timeout=1.0, tcp_timeout=1.0)

        assert len(hosts) == 2
        assert hosts[0]["ip"] == "10.0.0.1"
        assert hosts[1]["os_guess"] == "Windows"


class TestTcpPortScan:
    """Test TCP connect-based port scanning."""

    def test_open_ports_detected(self):
        """connect_ex()==0 => port reported as open."""
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = Mock()
            mock_sock.connect_ex.return_value = 0
            mock_sock_cls.return_value = mock_sock

            result = tcp_port_scan("10.0.0.1", timeout=0.1, ports=(80, 443, 8080))

        assert result == [80, 443, 8080]

    def test_closed_ports_skipped(self):
        """non-zero connect_ex => port closed / filtered."""
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = Mock()
            mock_sock.connect_ex.return_value = 111  # ECONNREFUSED
            mock_sock_cls.return_value = mock_sock

            result = tcp_port_scan("10.0.0.1", timeout=0.1, ports=(80, 443))

        assert result == []

    def test_mixed_ports(self):
        """Some ports open, some closed."""
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = Mock()
            mock_sock.connect_ex.side_effect = [0, 111, 0]  # 80 open, 443 closed, 8080 open
            mock_sock_cls.side_effect = lambda *a, **k: mock_sock

            result = tcp_port_scan("10.0.0.1", timeout=0.1, ports=(80, 443, 8080))

        assert result == [80, 8080]

    def test_exception_handled(self):
        """Socket errors are swallowed, empty list returned."""
        with patch("socket.socket", side_effect=OSError("no permission")):
            result = tcp_port_scan("10.0.0.1", timeout=0.1, ports=(80, 443))

        assert result == []


class TestEnrichHostPortScan:
    """Test enrich_host TCP port-scan integration."""

    @patch("socket.gethostbyaddr")
    @patch("scanner.core.tcp_port_scan")
    @patch("scanner.core.os_fingerprint")
    def test_enrich_host_includes_open_ports(self, mock_os, mock_port_scan, mock_gethostbyaddr):
        """open_ports populated from tcp_port_scan when port_scan=True."""
        mock_gethostbyaddr.return_value = ("host.example.com", [], [])
        mock_os.return_value = ("Linux/macOS/Unix (TTL=64)", 64, "ICMP")
        mock_port_scan.return_value = [80, 443, 1883]

        result = enrich_host(
            "10.0.0.1", mac=None,
            port_scan=True, port_scan_ports=(80, 443, 1883), port_scan_timeout=0.5,
        )

        assert result["open_ports"] == [80, 443, 1883]
        mock_port_scan.assert_called_once_with("10.0.0.1", 0.5, (80, 443, 1883))

    @patch("socket.gethostbyaddr")
    @patch("scanner.core.tcp_port_scan")
    @patch("scanner.core.os_fingerprint")
    def test_enrich_host_port_scan_disabled(self, mock_os, mock_port_scan, mock_gethostbyaddr):
        """port_scan=False => empty open_ports and tcp_port_scan not called."""
        mock_gethostbyaddr.return_value = (None, [], [])
        mock_os.return_value = (None, None, "none")

        result = enrich_host("10.0.0.1", mac=None, port_scan=False)

        assert result["open_ports"] == []
        mock_port_scan.assert_not_called()

    @patch("socket.gethostbyaddr")
    @patch("scanner.core.tcp_port_scan")
    @patch("scanner.core.os_fingerprint")
    def test_enrich_host_default_ports(self, mock_os, mock_port_scan, mock_gethostbyaddr):
        """Default port tuple passed through to tcp_port_scan."""
        mock_gethostbyaddr.return_value = ("x", [], [])
        mock_os.return_value = (None, None, "none")
        mock_port_scan.return_value = []

        enrich_host("10.0.0.1")

        args, _ = mock_port_scan.call_args
        assert args[2] == DEFAULT_PORTS


class TestScanNetworkPortScan:
    """Test scan_network port-scan argument propagation."""

    @patch("scanner.core.arp_scan")
    @patch("scanner.core.enrich_host")
    def test_scan_network_propagates_port_scan(self, mock_enrich, mock_arp_scan):
        """scan_network forwards port_scan config to enrich_host."""
        mock_arp_scan.return_value = [{"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:01"}]
        mock_enrich.return_value = {"ip": "10.0.0.1", "open_ports": [80, 443]}

        hosts = scan_network(
            "10.0.0.0/24", iface="eth0", timeout=1,
            port_scan=True, port_scan_ports=(80, 443), port_scan_timeout=0.3,
        )

        assert len(hosts) == 1
        assert hosts[0]["open_ports"] == [80, 443]
        # enrich_host positional args: [0]ip [1]mac [2]icmp [3]tcp [4]probes [5]port_scan [6]ports [7]timeout
        args, _ = mock_enrich.call_args
        assert args[5] is True
        assert args[6] == (80, 443)
        assert args[7] == 0.3

    @patch("scanner.core.arp_scan")
    @patch("scanner.core.enrich_host")
    def test_scan_network_port_scan_disabled(self, mock_enrich, mock_arp_scan):
        """port_scan=False is forwarded with custom ports/timeout."""
        mock_arp_scan.return_value = [{"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:01"}]
        mock_enrich.return_value = {"ip": "10.0.0.1", "open_ports": []}

        scan_network("10.0.0.0/24", port_scan=False, port_scan_ports=(80,), port_scan_timeout=0.2)

        args, _ = mock_enrich.call_args
        assert args[5] is False
        assert args[6] == (80,)
        assert args[7] == 0.2
