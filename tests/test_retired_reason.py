"""
退場原因分類（classify_retired_reason()）：偵測順序刻意是白名單命中
-> 時效過期 -> 頻次不足 -> 分數/信心值衰退 -> 其餘歸類為ASN節流擠出。
"""
from datetime import timedelta

import pipeline as p

NOT_WHITELISTED = lambda ip, asn: False  # noqa: E731
ALWAYS_WHITELISTED = lambda ip, asn: True  # noqa: E731


def test_whitelist_match_takes_top_priority(make_record, now):
    """即使同時也符合時效過期等其他條件，白名單命中都應該優先回報。"""
    record = make_record(last_seen=(now - timedelta(days=99)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    reason = p.classify_retired_reason("8.8.8.8", "A", record, now, ALWAYS_WHITELISTED)
    assert reason.startswith("REVOKED_WHITELIST_MATCH")


def test_missing_last_seen_reports_expired_inactivity(make_record, now):
    record = make_record(last_seen=None)
    reason = p.classify_retired_reason("1.2.3.4", "A", record, now, NOT_WHITELISTED)
    assert reason.startswith("EXPIRED_INACTIVITY")


def test_channel_a_expired_inactivity(make_record, now):
    stale = (now - timedelta(hours=p.STRICT_WINDOW_HOURS + 1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    record = make_record(last_seen=stale, threat_score=100)
    reason = p.classify_retired_reason("1.2.3.4", "A", record, now, NOT_WHITELISTED)
    assert reason.startswith("EXPIRED_INACTIVITY")


def test_channel_a_score_degraded(make_record, now):
    record = make_record(
        last_seen=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        threat_score=p.MUST_HAVE_MIN_SCORE - 1,
    )
    reason = p.classify_retired_reason("1.2.3.4", "A", record, now, NOT_WHITELISTED)
    assert reason.startswith("DROP_SCORE_DEGRADED")


def test_channel_a_tag_no_longer_matches_fallback(make_record, now):
    """時效/分數都還OK，純粹標籤不再命中must_have_tags的情況，歸類為
    DROP_SCORE_DEGRADED（既定5+1代碼裡沒有更貼切的選項）。"""
    record = make_record(last_seen=now.strftime("%Y-%m-%dT%H:%M:%SZ"), threat_score=100)
    reason = p.classify_retired_reason("1.2.3.4", "A", record, now, NOT_WHITELISTED)
    assert reason.startswith("DROP_SCORE_DEGRADED")
    assert "tag criteria" in reason


def test_channel_b_expired_inactivity_uses_7day_recency_window(make_record, now):
    """退場原因判斷要用新的7天時效窗口，不是舊的14天——跟通道B規則
    調整保持一致，避免兩邊各用各的門檻互相矛盾。"""
    stale = (now - timedelta(days=p.PERSISTENCE_RECENCY_WINDOW_DAYS + 1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    record = make_record(last_seen=stale, edl_recent_seen_count_b=p.PERSISTENCE_MIN_SEEN_COUNT)
    reason = p.classify_retired_reason("1.2.3.4", "B", record, now, NOT_WHITELISTED)
    assert reason.startswith("EXPIRED_INACTIVITY")
    assert f"{p.PERSISTENCE_RECENCY_WINDOW_DAYS}d" in reason


def test_channel_b_frequency_insufficient(make_record, now):
    record = make_record(
        last_seen=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        edl_recent_seen_count_b=p.PERSISTENCE_MIN_SEEN_COUNT - 1,
    )
    reason = p.classify_retired_reason("1.2.3.4", "B", record, now, NOT_WHITELISTED)
    assert reason.startswith("DROP_FREQUENCY_INSUFFICIENT")


def test_channel_b_score_degraded(make_record, now):
    record = make_record(
        last_seen=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        edl_recent_seen_count_b=p.PERSISTENCE_MIN_SEEN_COUNT,
        threat_score=p.PERSISTENCE_MIN_SCORE - 1,
    )
    reason = p.classify_retired_reason("1.2.3.4", "B", record, now, NOT_WHITELISTED)
    assert reason.startswith("DROP_SCORE_DEGRADED")


def test_channel_b_falls_back_to_asn_throttled(make_record, now):
    """時效、頻次、分數、信心值全部仍符合舊通道門檻時，唯一剩下的解釋
    就是被同ASN節流擠出。"""
    record = make_record(
        last_seen=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        edl_recent_seen_count_b=p.PERSISTENCE_MIN_SEEN_COUNT,
        threat_score=p.PERSISTENCE_MIN_SCORE,
        confidence=p.PERSISTENCE_MIN_CONFIDENCE,
    )
    reason = p.classify_retired_reason("1.2.3.4", "B", record, now, NOT_WHITELISTED)
    assert reason.startswith("DROP_ASN_THROTTLED")


def test_channel_c_expired_inactivity(make_record, now):
    stale = (now - timedelta(hours=p.FALLBACK_WINDOW_HOURS + 1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    record = make_record(last_seen=stale, edl_recent_seen_count_c=p.FALLBACK_MIN_SEEN_COUNT)
    reason = p.classify_retired_reason("1.2.3.4", "C", record, now, NOT_WHITELISTED)
    assert reason.startswith("EXPIRED_INACTIVITY")


def test_channel_c_frequency_insufficient(make_record, now):
    record = make_record(
        last_seen=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        edl_recent_seen_count_c=p.FALLBACK_MIN_SEEN_COUNT - 1,
    )
    reason = p.classify_retired_reason("1.2.3.4", "C", record, now, NOT_WHITELISTED)
    assert reason.startswith("DROP_FREQUENCY_INSUFFICIENT")


def test_channel_c_falls_back_to_asn_throttled(make_record, now):
    record = make_record(
        last_seen=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        edl_recent_seen_count_c=p.FALLBACK_MIN_SEEN_COUNT,
        threat_score=p.FALLBACK_MIN_SCORE,
        confidence=p.FALLBACK_MIN_CONFIDENCE,
    )
    reason = p.classify_retired_reason("1.2.3.4", "C", record, now, NOT_WHITELISTED)
    assert reason.startswith("DROP_ASN_THROTTLED")
