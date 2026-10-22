"""
ASN 節流（throttle_by_asn()）：同一ASN最多保留分數最高、最後活躍最新
的前N筆，通道A完全豁免。
"""
import pipeline as p


def _entry(ip, score, last_seen, tier, asn, members=None):
    return (ip, score, last_seen, tier, asn, members or [ip])


def test_keeps_top_n_per_asn_by_score():
    candidates = [
        _entry(f"203.0.113.{i}", 100 - i, "2026-10-21T00:00:00Z", "C", "AS64500")
        for i in range(p.ASN_THROTTLE_MAX_PER_ASN + 3)
    ]
    kept = p.throttle_by_asn(candidates)
    assert len(kept) == p.ASN_THROTTLE_MAX_PER_ASN
    kept_ips = {item[0] for item in kept}
    # 分數最高的前N筆（score = 100 - i，i越小分數越高）應該被保留
    expected = {f"203.0.113.{i}" for i in range(p.ASN_THROTTLE_MAX_PER_ASN)}
    assert kept_ips == expected


def test_ties_broken_by_most_recent_last_seen():
    candidates = [
        _entry("203.0.113.1", 90, "2026-10-21T00:00:00Z", "C", "AS64500"),
        _entry("203.0.113.2", 90, "2026-10-20T00:00:00Z", "C", "AS64500"),
    ]
    kept = p.throttle_by_asn(candidates, max_per_asn=1)
    assert kept[0][0] == "203.0.113.1"


def test_channel_a_exempt_from_throttling():
    """同一ASN下通道A成員即使超過上限也全數保留，不受節流影響。"""
    candidates = [
        _entry(f"203.0.113.{i}", 90, "2026-10-21T00:00:00Z", "A", "AS64500")
        for i in range(p.ASN_THROTTLE_MAX_PER_ASN + 5)
    ]
    kept = p.throttle_by_asn(candidates)
    assert len(kept) == len(candidates)


def test_different_asns_throttled_independently():
    candidates = [
        _entry(f"203.0.113.{i}", 90, "2026-10-21T00:00:00Z", "C", "AS64500")
        for i in range(p.ASN_THROTTLE_MAX_PER_ASN + 2)
    ] + [
        _entry(f"198.51.100.{i}", 90, "2026-10-21T00:00:00Z", "C", "AS64501")
        for i in range(p.ASN_THROTTLE_MAX_PER_ASN + 2)
    ]
    kept = p.throttle_by_asn(candidates)
    assert len(kept) == p.ASN_THROTTLE_MAX_PER_ASN * 2


def test_cidr_entry_occupies_single_slot_regardless_of_member_count():
    """一個聚合後的CIDR條目只占用1個節流名額，不論背後涵蓋多少個別IP。"""
    cidr_entry = _entry(
        "203.0.113.0/24", 100, "2026-10-21T00:00:00Z", "C", "AS64500",
        members=[f"203.0.113.{i}" for i in range(20)],
    )
    others = [
        _entry(f"198.51.100.{i}", 90, "2026-10-21T00:00:00Z", "C", "AS64500")
        for i in range(p.ASN_THROTTLE_MAX_PER_ASN - 1)
    ]
    kept = p.throttle_by_asn([cidr_entry] + others)
    assert len(kept) == p.ASN_THROTTLE_MAX_PER_ASN  # CIDR(1) + 其餘(max-1) 剛好打滿


def test_missing_asn_always_kept():
    candidates = [
        _entry(f"203.0.113.{i}", 90, "2026-10-21T00:00:00Z", "C", None)
        for i in range(p.ASN_THROTTLE_MAX_PER_ASN + 5)
    ]
    kept = p.throttle_by_asn(candidates)
    assert len(kept) == len(candidates)
