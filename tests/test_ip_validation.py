"""
第一階過濾：RFC 合規與 Bogon 清洗（is_valid_public_ip()）。
"""
import pipeline as p


def test_valid_public_ip_accepted():
    assert p.is_valid_public_ip("8.8.8.8") is True
    assert p.is_valid_public_ip("185.220.101.44") is True


def test_private_rfc1918_rejected():
    assert p.is_valid_public_ip("192.168.1.1") is False
    assert p.is_valid_public_ip("10.0.0.1") is False
    assert p.is_valid_public_ip("172.16.0.1") is False


def test_loopback_rejected():
    assert p.is_valid_public_ip("127.0.0.1") is False


def test_multicast_rejected():
    assert p.is_valid_public_ip("224.0.0.1") is False


def test_reserved_rejected():
    # 240.0.0.0/4 是 IANA 保留的「未來用途」區段，不具路由效力
    assert p.is_valid_public_ip("240.1.2.3") is False


def test_malformed_string_rejected_not_raised():
    # 不合法字串不應該讓函式拋例外，而是乾淨回傳 False
    assert p.is_valid_public_ip("not-an-ip") is False
    assert p.is_valid_public_ip("") is False
    assert p.is_valid_public_ip("999.999.999.999") is False


def test_whitespace_is_stripped():
    assert p.is_valid_public_ip("  8.8.8.8  ") is True
