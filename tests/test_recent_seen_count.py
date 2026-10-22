"""
滾動視窗出現次數計算（compute_recent_seen_count()），含過渡期保底
機制。
"""
from datetime import timedelta

import pipeline as p


def _iso(now, days_ago):
    return (now - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_counts_only_entries_within_window(make_record, now):
    record = make_record(
        seen_history=[_iso(now, d) for d in [1, 3, 6, 8, 10, 20]],
        history_tracking_since=_iso(now, 60),  # 早就過了過渡期
    )
    # 7天窗口：只有 1/3/6 天前的 3 筆落在窗口內
    assert p.compute_recent_seen_count(record, now, window_days=7) == 3
    # 14天窗口：再多算進 8/10 天前的 2 筆，共 5 筆
    assert p.compute_recent_seen_count(record, now, window_days=14) == 5


def test_channel_b_and_c_windows_are_independent(make_record, now):
    """同一筆紀錄，通道C(7天)跟通道B(14天)的次數應該各自獨立計算，
    不能共用同一個數字——這是本次會話多次修過的真實bug，用測試鎖住
    不能再回歸。"""
    record = make_record(
        seen_history=[_iso(now, d) for d in [2, 2, 9, 9, 9]],
        history_tracking_since=_iso(now, 60),
    )
    freq_c = p.compute_recent_seen_count(record, now, window_days=p.RECENT_WINDOW_DAYS)
    freq_b = p.compute_recent_seen_count(record, now, window_days=p.PERSISTENCE_WINDOW_DAYS)
    assert freq_c == 2
    assert freq_b == 5
    assert freq_c != freq_b


def test_transition_period_uses_legacy_count_as_floor(make_record, now):
    """過渡期（history_tracking_since 距今不滿 TRANSITION_PERIOD_DAYS）
    內，若滾動視窗次數比全時累計 seen_count 低，應該取較大值當下限，
    避免機制切換當下讓次數瞬間歸零。"""
    record = make_record(
        seen_history=[_iso(now, 0)],  # 滾動視窗只會算到 1 筆
        history_tracking_since=_iso(now, 2),  # 2天前才開始追蹤，還在過渡期
        seen_count=8,  # 舊的全時累計次數很高
    )
    assert p.compute_recent_seen_count(record, now, window_days=7) == 8


def test_after_transition_period_uses_pure_rolling_count(make_record, now):
    """過渡期(7天)結束後，即使全時累計次數很高，也應該改回純粹的滾動
    視窗計數，不再使用全時累計當下限——這正是這套機制存在的目的：長期
    掛網但近期不活躍的IP要能自然淡出。"""
    record = make_record(
        seen_history=[_iso(now, 0)],
        history_tracking_since=_iso(now, 30),  # 遠超過7天過渡期
        seen_count=8,
    )
    assert p.compute_recent_seen_count(record, now, window_days=7) == 1


def test_missing_history_tracking_since_treated_as_transition(make_record, now):
    """缺少 history_tracking_since（例如機制上線前就存在的舊紀錄）時，
    視同還在過渡期，一樣套用保底機制。"""
    record = make_record(
        seen_history=[_iso(now, 0)],
        history_tracking_since=None,
        seen_count=5,
    )
    assert p.compute_recent_seen_count(record, now, window_days=7) == 5


def test_empty_seen_history(make_record, now):
    record = make_record(seen_history=[], history_tracking_since=_iso(now, 60), seen_count=1)
    assert p.compute_recent_seen_count(record, now, window_days=7) == 0
