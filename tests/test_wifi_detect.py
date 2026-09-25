"""Tests for scanner/wifi_detect.py (passive WiFi attack detection)."""

import pytest

from scanner.wifi_detect import (
    SEVERITY_RANK,
    _is_protected,
    _normalize_security,
    detect_attacks,
)


def _types(attacks):
    return sorted(a["type"] for a in attacks)


def test_is_protected_wpa2():
    assert _is_protected(["WPA2", "PSK"])
    assert _is_protected(["WPA-PSK"])
    assert _is_protected(["WPA3-802.1X"])
    assert not _is_protected(["WEP"])
    assert not _is_protected([])


def test_normalize_security():
    assert _normalize_security([" wpa2 ", "psk", "", None]) == ["WPA2", "PSK"]
    assert _normalize_security(None) == []


def test_severity_rank_ordering():
    assert SEVERITY_RANK["critique"] < SEVERITY_RANK["haute"] < SEVERITY_RANK["moyenne"] < SEVERITY_RANK["basse"]


def test_empty_input():
    assert detect_attacks([]) == []
    assert detect_attacks(None) == []


def test_clean_network_no_attacks():
    nets = [
        {"bssid": "AA:BB:CC:00:00:01", "ssid": "Home", "security": ["WPA2"]},
    ]
    baseline = [{"bssid": "AA:BB:CC:00:00:01"}]
    assert detect_attacks(nets, baseline) == []


def test_evil_twin_detected():
    # protected SSID + open clone of same SSID -> EVIL_TWIN (critique)
    nets = [
        {"bssid": "AA:BB:CC:00:00:01", "ssid": "Home", "security": ["WPA2"]},
        {"bssid": "AA:BB:CC:00:00:02", "ssid": "Home", "security": []},
    ]
    attacks = detect_attacks(nets)
    twins = [a for a in attacks if a["type"] == "EVIL_TWIN"]
    assert len(twins) == 1
    assert twins[0]["severity"] == "critique"
    assert twins[0]["bssid"] == "AA:BB:CC:00:00:02"


def test_evil_twin_requires_protected_sibling():
    # open SSID with no protected sibling -> not an evil twin
    nets = [
        {"bssid": "AA:BB:CC:00:00:01", "ssid": "OpenNet", "security": []},
        {"bssid": "AA:BB:CC:00:00:02", "ssid": "OpenNet", "security": []},
    ]
    attacks = detect_attacks(nets)
    assert "EVIL_TWIN" not in _types(attacks)


def test_rogue_ap_two_bssid():
    nets = [
        {"bssid": "AA:BB:CC:00:00:01", "ssid": "Corp", "security": ["WPA2"]},
        {"bssid": "AA:BB:CC:00:00:02", "ssid": "Corp", "security": ["WPA2"]},
    ]
    attacks = detect_attacks(nets)
    rogue = [a for a in attacks if a["type"] == "ROGUE_AP"]
    assert len(rogue) == 2
    assert all(a["severity"] == "haute" for a in rogue)


def test_rogue_ap_single_bssid_not_flagged():
    nets = [
        {"bssid": "AA:BB:CC:00:00:01", "ssid": "Corp", "security": ["WPA2"]},
    ]
    attacks = detect_attacks(nets)
    assert "ROGUE_AP" not in _types(attacks)


def test_weak_crypt_wep_critique():
    nets = [{"bssid": "AA:BB:CC:00:00:01", "ssid": "Old", "security": ["WEP"]}]
    attacks = detect_attacks(nets)
    weak = [a for a in attacks if a["type"] == "WEAK_CRYPT"]
    assert len(weak) == 1
    assert weak[0]["severity"] == "critique"


def test_weak_crypt_tkip_haute():
    nets = [{"bssid": "AA:BB:CC:00:00:01", "ssid": "Old", "security": ["TKIP"]}]
    attacks = detect_attacks(nets)
    weak = [a for a in attacks if a["type"] == "WEAK_CRYPT"]
    assert len(weak) == 1
    assert weak[0]["severity"] == "haute"


def test_weak_crypt_open_moyenne():
    nets = [{"bssid": "AA:BB:CC:00:00:01", "ssid": "Cafe", "security": []}]
    attacks = detect_attacks(nets)
    weak = [a for a in attacks if a["type"] == "WEAK_CRYPT"]
    assert len(weak) == 1
    assert weak[0]["severity"] == "moyenne"


def test_ad_hoc_detected():
    nets = [{"bssid": "AA:BB:CC:00:00:01", "ssid": "AdHoc", "mode": "Ad-Hoc", "security": []}]
    attacks = detect_attacks(nets)
    assert any(a["type"] == "AD_HOC" and a["severity"] == "moyenne" for a in attacks)


def test_ad_hoc_not_detected_other_mode():
    nets = [{"bssid": "AA:BB:CC:00:00:01", "ssid": "Infra", "mode": "Infra", "security": []}]
    attacks = detect_attacks(nets)
    assert "AD_HOC" not in _types(attacks)


def test_new_ap_with_baseline():
    nets = [{"bssid": "AA:BB:CC:00:99:99", "ssid": "New", "security": ["WPA2"]}]
    baseline = [{"bssid": "AA:BB:CC:00:00:01"}]
    attacks = detect_attacks(nets, baseline)
    assert any(a["type"] == "NEW_AP" and a["severity"] == "basse" for a in attacks)


def test_new_ap_suppressed_when_in_baseline():
    nets = [{"bssid": "AA:BB:CC:00:00:01", "ssid": "Known", "security": ["WPA2"]}]
    baseline = [{"bssid": "AA:BB:CC:00:00:01"}]
    attacks = detect_attacks(nets, baseline)
    assert "NEW_AP" not in _types(attacks)


def test_new_ap_suppressed_without_baseline():
    # empty baseline -> NEW_AP should not fire
    nets = [{"bssid": "AA:BB:CC:00:00:01", "ssid": "X", "security": ["WPA2"]}]
    attacks = detect_attacks(nets, baseline=[])
    assert "NEW_AP" not in _types(attacks)


def test_caché_ssid_ignored_for_rogue():
    nets = [
        {"bssid": "AA:BB:CC:00:00:01", "ssid": "(caché)", "security": ["WPA2"]},
        {"bssid": "AA:BB:CC:00:00:02", "ssid": "(caché)", "security": ["WPA2"]},
    ]
    attacks = detect_attacks(nets)
    assert "EVIL_TWIN" not in _types(attacks)


def test_dedup_keeps_highest_severity():
    # single network that is both WEP (critique) and TKIP can't coexist; test
    # dedup behaviour: two emissions for same (bssid, type) keep the strongest.
    nets = [{"bssid": "AA:BB:CC:00:00:01", "ssid": "W", "security": ["WEP"]}]
    attacks = detect_attacks(nets)
    weak = [a for a in attacks if a["type"] == "WEAK_CRYPT"]
    assert len(weak) == 1  # only one result per (bssid, type)


def test_hidden_ssid_uses_placeholder_in_description():
    nets = [{"bssid": "AA:BB:CC:00:00:01", "ssid": None, "security": ["WEP"]}]
    attacks = detect_attacks(nets)
    weak = [a for a in attacks if a["type"] == "WEAK_CRYPT"]
    assert weak and "(caché)" in weak[0]["description"]


def test_network_without_bssid_skipped_for_per_net_checks():
    nets = [{"ssid": "NoBSSID", "security": ["WEP"]}]
    attacks = detect_attacks(nets)
    assert attacks == []
