"""
整合測試：select_edl_candidates() 完整跑一次四階漏斗，驗證通道統計、
「今日/本次新增」差集判定、「退場」差集判定三者在同一次執行裡都正確
運作。情資庫刻意只放少量合成IP，不聚合進CIDR、不觸發ASN節流，單純
驗證決策樹跟兩種差集判定的串接邏輯本身。
"""
from datetime import timedelta

import pipeline as p


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_full_funnel_classifies_each_channel_correctly(now):
    base = {
        "1.2.3.4": {  # 通道A：命中must-have標籤、1小時前活躍
            "labels": ["c2"], "threat_score": 95, "confidence": 90,
            "last_seen": _iso(now - timedelta(hours=1)),
            "seen_count": 1, "seen_history": [_iso(now - timedelta(hours=1))],
            "history_tracking_since": _iso(now - timedelta(days=60)),
        },
        "2.3.4.5": {  # 通道C：2小時前活躍、7天內3次、高分高信心
            "labels": [], "threat_score": 99, "confidence": 95,
            "last_seen": _iso(now - timedelta(hours=2)),
            "seen_count": 3,
            "seen_history": [_iso(now - timedelta(days=d)) for d in [0, 2, 5]],
            "history_tracking_since": _iso(now - timedelta(days=60)),
        },
        "3.4.5.6": {  # 通道B：3天前活躍、14天內5次、中高分
            "labels": [], "threat_score": 90, "confidence": 85,
            "last_seen": _iso(now - timedelta(days=3)),
            "seen_count": 5,
            "seen_history": [_iso(now - timedelta(days=d)) for d in [1, 3, 6, 9, 12]],
            "history_tracking_since": _iso(now - timedelta(days=60)),
        },
        "4.5.6.7": {  # 不符合任何通道
            "labels": [], "threat_score": 50, "confidence": 50,
            "last_seen": _iso(now - timedelta(hours=1)),
            "seen_count": 1, "seen_history": [_iso(now - timedelta(hours=1))],
            "history_tracking_since": _iso(now - timedelta(days=60)),
        },
        "10.0.0.1": {  # 私有網段，第一階就該被剔除
            "labels": ["c2"], "threat_score": 100, "confidence": 100,
            "last_seen": _iso(now), "seen_count": 1, "seen_history": [_iso(now)],
            "history_tracking_since": _iso(now - timedelta(days=60)),
        },
    }

    selected, stats, export_entries, retired_entries = p.select_edl_candidates(base, now)

    assert set(selected) == {"1.2.3.4", "2.3.4.5", "3.4.5.6"}
    assert stats["condition_a"] == 1
    assert stats["condition_b"] == 1
    assert stats["condition_c"] == 1
    assert stats["excluded_non_routable"] == 1

    assert base["1.2.3.4"]["edl_tier"] == "A"
    assert base["2.3.4.5"]["edl_tier"] == "C"
    assert base["3.4.5.6"]["edl_tier"] == "B"
    assert base["4.5.6.7"]["edl_tier"] is None
    assert base["10.0.0.1"]["edl_tier"] is None


def test_today_new_detection_on_fresh_entry(now):
    """上一輪不在榜上（edl_tier缺省）、這一輪收錄 -> 應標記為今日新增；
    today_str比對用的是真實當下日期（taipei_today_str()不吃注入的
    now），所以這裡跟著呼叫同一個函式算期望值，而不是寫死日期。"""
    base = {
        "1.2.3.4": {
            "labels": ["c2"], "threat_score": 95, "confidence": 90,
            "last_seen": _iso(now - timedelta(hours=1)),
            "seen_count": 1, "seen_history": [_iso(now - timedelta(hours=1))],
            "history_tracking_since": _iso(now - timedelta(days=60)),
        },
    }
    p.select_edl_candidates(base, now)
    assert base["1.2.3.4"]["is_today_new"] is True
    assert base["1.2.3.4"]["edl_first_added_date"] == p.taipei_today_str()


def test_today_new_flag_not_reset_on_subsequent_runs(now):
    """持續留在榜上的IP，edl_first_added_date只在最初那次入榜蓋一次，
    之後每輪重跑不應該被覆寫成新的日期。"""
    base = {
        "1.2.3.4": {
            "labels": ["c2"], "threat_score": 95, "confidence": 90,
            "last_seen": _iso(now - timedelta(hours=1)),
            "seen_count": 1, "seen_history": [_iso(now - timedelta(hours=1))],
            "history_tracking_since": _iso(now - timedelta(days=60)),
            "edl_tier": "A",
            "edl_first_added_date": "2026-01-01",
            "is_today_new": False,
        },
    }
    p.select_edl_candidates(base, now)
    assert base["1.2.3.4"]["edl_first_added_date"] == "2026-01-01"
    assert base["1.2.3.4"]["is_today_new"] is False


def test_retired_detection_when_ip_drops_out(now):
    """上一輪有tier、這一輪不再符合任何通道門檻 -> 應出現在
    retired_entries，且標記正確清空。"""
    base = {
        "9.9.9.9": {
            "labels": [], "threat_score": 50, "confidence": 50,  # 這輪已經不夠格
            "last_seen": _iso(now - timedelta(hours=1)),
            "seen_count": 1, "seen_history": [_iso(now - timedelta(hours=1))],
            "history_tracking_since": _iso(now - timedelta(days=60)),
            "edl_tier": "C",  # 上一輪的結果
            "edl_first_added_date": "2026-01-01",
            "is_today_new": False,
        },
    }
    _selected, _stats, _export_entries, retired_entries = p.select_edl_candidates(base, now)
    assert retired_entries == [("9.9.9.9", "C")]
    assert base["9.9.9.9"]["edl_tier"] is None
    assert base["9.9.9.9"]["edl_first_added_date"] is None


def test_no_retirement_when_ip_still_qualifies(now):
    base = {
        "1.2.3.4": {
            "labels": ["c2"], "threat_score": 95, "confidence": 90,
            "last_seen": _iso(now - timedelta(hours=1)),
            "seen_count": 1, "seen_history": [_iso(now - timedelta(hours=1))],
            "history_tracking_since": _iso(now - timedelta(days=60)),
            "edl_tier": "A",
        },
    }
    _selected, _stats, _export_entries, retired_entries = p.select_edl_candidates(base, now)
    assert retired_entries == []


def test_export_entries_align_with_selected(now):
    base = {
        "1.2.3.4": {
            "labels": ["c2"], "threat_score": 95, "confidence": 90,
            "last_seen": _iso(now - timedelta(hours=1)),
            "seen_count": 1, "seen_history": [_iso(now - timedelta(hours=1))],
            "history_tracking_since": _iso(now - timedelta(days=60)),
        },
    }
    selected, _stats, export_entries, _retired = p.select_edl_candidates(base, now)
    assert [e[0] for e in export_entries] == selected
