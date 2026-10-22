"""
任務一回歸測試（2026-10-22安全性修正）：命中公用雲端/CDN白名單的IP，
不論通道A/B/C判定出什麼結果，一律不得輸出到正式EDL（selected /
blocklist_edl.txt），但要保留排除原因、命中規則及原始通道等可稽核
資訊；也要確保CIDR聚合不會讓白名單IP重新混進最終輸出。

這裡用 unittest.mock.patch 直接替換 pipeline.load_public_infra_matcher
/ load_public_infra_cidr_ranges，讓 select_edl_candidates() 在測試中
使用我們指定的白名單判斷邏輯，而不是依賴正式的
docs/data/public_infra_rules.json 內容——確保測試結果不受那份檔案
之後的實際編輯影響。
"""
from datetime import timedelta
from unittest.mock import patch

import pipeline as p


def _iso(now, days_ago=0, hours_ago=0):
    return (now - timedelta(days=days_ago, hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_with_whitelist(base, now, whitelisted_ips):
    """用指定的IP集合當白名單命中名單，執行一次select_edl_candidates()。"""
    def fake_matcher():
        return lambda ip, asn: ip in whitelisted_ips

    with patch.object(p, "load_public_infra_matcher", fake_matcher), \
         patch.object(p, "load_public_infra_cidr_ranges", lambda: []):
        return p.select_edl_candidates(base, now)


# ---------------------------------------------------------- 通道A/B/C各自命中白名單
def test_channel_a_whitelist_hit_excluded_from_edl(make_record, now):
    base = {
        "1.2.3.4": make_record(labels=["c2"], threat_score=95, confidence=90,
                                last_seen=_iso(now, hours_ago=1)),
    }
    selected, stats, _export, _retired = _run_with_whitelist(base, now, {"1.2.3.4"})

    assert "1.2.3.4" not in selected
    assert stats["condition_a"] == 0  # 不計入命中統計，因為沒有真的輸出
    assert stats["whitelist_excluded"] == 1
    assert base["1.2.3.4"]["edl_tier"] is None
    # 可稽核資訊：命中規則(whitelist_match)跟原始通道(excluded_tier)要保留
    assert base["1.2.3.4"]["edl_whitelist_match"] is True
    assert base["1.2.3.4"]["edl_whitelist_excluded_tier"] == "A"


def test_channel_b_whitelist_hit_excluded_from_edl(make_record, now):
    base = {
        "1.2.3.4": make_record(
            labels=[], threat_score=90, confidence=85, last_seen=_iso(now, days_ago=2),
            seen_history=[_iso(now, d) for d in [1, 3, 6, 9, 12]],
        ),
    }
    selected, stats, _export, _retired = _run_with_whitelist(base, now, {"1.2.3.4"})

    assert "1.2.3.4" not in selected
    assert stats["condition_b"] == 0
    assert stats["whitelist_excluded"] == 1
    assert base["1.2.3.4"]["edl_tier"] is None
    assert base["1.2.3.4"]["edl_whitelist_excluded_tier"] == "B"


def test_channel_c_whitelist_hit_excluded_from_edl(make_record, now):
    base = {
        "1.2.3.4": make_record(
            labels=[], threat_score=99, confidence=95, last_seen=_iso(now, hours_ago=2),
            seen_history=[_iso(now, d) for d in [0, 2, 5]],
        ),
    }
    selected, stats, _export, _retired = _run_with_whitelist(base, now, {"1.2.3.4"})

    assert "1.2.3.4" not in selected
    assert stats["condition_c"] == 0
    assert stats["whitelist_excluded"] == 1
    assert base["1.2.3.4"]["edl_tier"] is None
    assert base["1.2.3.4"]["edl_whitelist_excluded_tier"] == "C"


def test_non_whitelisted_record_in_same_run_still_included(make_record, now):
    """確保白名單排除只影響命中的那一筆，不會誤傷同一輪其他正常候選。"""
    base = {
        "1.2.3.4": make_record(labels=["c2"], threat_score=95, last_seen=_iso(now, hours_ago=1)),
        "5.6.7.8": make_record(labels=["c2"], threat_score=95, last_seen=_iso(now, hours_ago=1)),
    }
    selected, stats, _export, _retired = _run_with_whitelist(base, now, {"1.2.3.4"})

    assert "1.2.3.4" not in selected
    assert "5.6.7.8" in selected
    assert stats["condition_a"] == 1
    assert stats["whitelist_excluded"] == 1


def test_whitelist_match_recorded_even_when_not_excluded(make_record, now):
    """即使這筆IP本來就不符合任何通道門檻，只要命中白名單，
    edl_whitelist_match仍要誠實記錄True；但因為沒有tier可排除，
    edl_whitelist_excluded_tier應該是None（沒有東西被排除）。"""
    base = {
        "1.2.3.4": make_record(labels=[], threat_score=10, confidence=10),
    }
    _selected, stats, _export, _retired = _run_with_whitelist(base, now, {"1.2.3.4"})
    assert base["1.2.3.4"]["edl_whitelist_match"] is True
    assert base["1.2.3.4"]["edl_whitelist_excluded_tier"] is None
    assert stats["whitelist_excluded"] == 0  # 沒有tier可排除，不計入排除統計


# -------------------------------------------------------- 白名單IP退場審計
def test_previously_included_whitelisted_ip_marked_retired_with_correct_reason(make_record, now):
    """情境：上一輪還沒套用這次安全修正時，這筆IP已經在EDL榜上
    （edl_tier="A"）；這一輪套用修正後，即使通道門檻依然命中，也應該
    被判定為退場，且retired_reason要正確標示REVOKED_WHITELIST_MATCH
    （classify_retired_reason()本來就會優先檢查白名單命中）。"""
    base = {
        "1.2.3.4": make_record(
            labels=["c2"], threat_score=95, confidence=90, last_seen=_iso(now, hours_ago=1),
            edl_tier="A",  # 上一輪的結果
        ),
    }
    _selected, _stats, _export, retired_entries = _run_with_whitelist(base, now, {"1.2.3.4"})
    assert retired_entries == [("1.2.3.4", "A")]

    asn_dict = {}
    with patch.object(p, "load_public_infra_matcher", lambda: (lambda ip, asn: ip == "1.2.3.4")):
        rows = p.build_edl_retired_rows(retired_entries, base, asn_dict, now)
    assert len(rows) == 1
    assert rows[0]["retired_reason"].startswith("REVOKED_WHITELIST_MATCH")


# -------------------------------------------------------- CIDR聚合不會讓白名單IP重新進入EDL
def test_whitelisted_ips_do_not_sneak_back_in_via_cidr_aggregation(make_record, now):
    """任務一要求五：即使白名單命中的IP數量在同一/24裡達到CIDR聚合
    門檻，也不應該被聚合成一個CIDR條目重新出現在EDL裡——因為它們在
    進入候選名單階段就已經被排除，根本不會被納入CIDR分組的候選
    清單。"""
    base = {}
    whitelisted_ips = set()
    for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 2):
        ip = f"45.33.200.{i}"
        whitelisted_ips.add(ip)
        base[ip] = make_record(
            labels=["c2"], threat_score=95, confidence=90, last_seen=_iso(now, hours_ago=1),
        )

    selected, stats, _export, _retired = _run_with_whitelist(base, now, whitelisted_ips)

    assert selected == []
    assert "45.33.200.0/24" not in selected
    assert stats["whitelist_excluded"] == p.CIDR_ROLLUP_THRESHOLD + 1
    assert stats["cidr_rollup_subnets"] == 0
    for ip in whitelisted_ips:
        assert base[ip]["edl_tier"] is None


def test_mixed_whitelisted_and_normal_ips_in_same_subnet(make_record, now):
    """同一個/24裡混合白名單IP跟正常候選IP：白名單IP要被排除在候選
    名單之外，不會混進最終聚合出的CIDR條目背後的member_ips；若扣掉
    白名單IP後，剩下的正常候選IP數仍達聚合門檻，照常聚合（因為CIDR
    分組是在白名單排除『之後』才進行，候選名單裡根本沒有白名單IP）。"""
    base = {}
    whitelisted_ips = set()
    normal_ips = set()
    for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1):
        wip = f"45.33.201.{i}"
        whitelisted_ips.add(wip)
        base[wip] = make_record(labels=["c2"], threat_score=95, last_seen=_iso(now, hours_ago=1))
    for i in range(p.CIDR_ROLLUP_THRESHOLD + 1, p.CIDR_ROLLUP_THRESHOLD * 2 + 1):
        nip = f"45.33.201.{i}"
        normal_ips.add(nip)
        base[nip] = make_record(labels=["c2"], threat_score=95, last_seen=_iso(now, hours_ago=1))

    selected, stats, export_entries, _retired = _run_with_whitelist(base, now, whitelisted_ips)

    assert stats["whitelist_excluded"] == p.CIDR_ROLLUP_THRESHOLD
    assert "45.33.201.0/24" in selected  # 剩下的正常候選仍達門檻，照常聚合
    cidr_entry = next(e for e in export_entries if e[0] == "45.33.201.0/24")
    member_ips = set(cidr_entry[5])
    assert member_ips == normal_ips  # 聚合背後的成員絕對不包含白名單IP
    for ip in whitelisted_ips:
        assert ip not in selected
        assert ip not in member_ips
