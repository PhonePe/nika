import base64

from engines.astrail import server as server_mod
from engines.astrail.server import AstrailServer


def test_get_auth_none_before_start():
    s = AstrailServer()
    assert s.get_auth() is None
    assert s._auth_header() == {}


def test_auth_header_is_correct_basic_token():
    s = AstrailServer()
    s._AstrailServer__auth_username = "nika"
    s._AstrailServer__auth_password = "secret"
    assert s.get_auth() == ("nika", "secret")
    expected = "Basic " + base64.b64encode(b"nika:secret").decode("ascii")
    assert s._auth_header() == {"Authorization": expected}


def test_connect_host_defaults_to_loopback(monkeypatch):
    monkeypatch.setattr(server_mod, "_get_astrail_config", lambda: {})
    assert AstrailServer()._get_connect_host() == "127.0.0.1"


def test_connect_host_rewrites_all_interfaces_to_loopback(monkeypatch):
    monkeypatch.setattr(server_mod, "_get_astrail_config", lambda: {"host": "0.0.0.0"})
    assert AstrailServer()._get_connect_host() == "127.0.0.1"


def test_connect_host_respects_explicit_host(monkeypatch):
    monkeypatch.setattr(server_mod, "_get_astrail_config", lambda: {"host": "10.0.0.5"})
    assert AstrailServer()._get_connect_host() == "10.0.0.5"
