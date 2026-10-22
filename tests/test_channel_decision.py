"""
三通道決策樹（is_edl_candidate()）—— 整套 EDL 判定邏輯的核心，涵蓋
通道A/B/C各自的收錄條件、雜訊攔截閥、以及2026-10-20/10-22兩次真實
發生過的架構性bug（B/C死代碼、通道B時效窗口收緊）的回歸保護。
"""
from datetime import timedelta

import pipeline as p


def test_no_last_seen_always_excluded(now):
    assert p.is_edl_candidate(set(), 100, 100, None, 10, 10, now) is None


# ---------------------------------------------------------------- 通道 A
def test_channel_a_matched_tag_and_sufficient_score(now):
    labels = {"c2"}
    tier = p.is_edl_candidate(labels, p.MUST_HAVE_MIN_SCORE, 0, now, 0, 0, now)
    assert tier == "A"


def test_channel_a_single_occurrence_is_enough(now):
    """通道A出現1次就算數，不看頻次。"""
    tier = p.is_edl_candidate({"trojan"}, 99, 0, now, 0, 0, now)
    assert tier == "A"


def test_channel_a_rejected_when_score_too_low(now):
    tier = p.is_edl_candidate({"c2"}, p.MUST_HAVE_MIN_SCORE - 1, 0, now, 0, 0, now)
    assert tier is None


def test_channel_a_rejected_when_outside_24h_window(now):
    stale = now - timedelta(hours=p.STRICT_WINDOW_HOURS + 1)
    tier = p.is_edl_candidate({"c2"}, 100, 100, stale, 0, 0, now)
    assert tier is None


def test_channel_a_tag_match_never_falls_through_to_b_or_c(now):
    """命中MUST_HAVE_TAGS但不滿足A本身門檻時，直接回傳None，不會往下
    嘗試通道B/C——即使同時滿足C的所有數值門檻也一樣。這是容易被誤解
    成bug而「修正」掉的既有行為，必須鎖住。"""
    stale = now - timedelta(hours=p.STRICT_WINDOW_HOURS + 1)
    tier = p.is_edl_candidate(
        {"c2"}, p.FALLBACK_MIN_SCORE, p.FALLBACK_MIN_CONFIDENCE, stale,
        p.FALLBACK_MIN_SEEN_COUNT, p.PERSISTENCE_MIN_SEEN_COUNT, now,
    )
    assert tier is None


# ---------------------------------------------------------- 雜訊攔截閥
def test_scanner_noise_tag_excluded_even_with_high_score(now):
    tier = p.is_edl_candidate({"shodan"}, 100, 100, now, 100, 100, now)
    assert tier is None


def test_scanner_noise_combined_with_must_have_tag_still_goes_to_a(now):
    """同時命中must-have跟雜訊標籤時，must-have豁免優先，不會被雜訊
    標籤剃除。"""
    tier = p.is_edl_candidate({"c2", "scanner"}, 100, 100, now, 0, 0, now)
    assert tier == "A"


# ---------------------------------------------------------------- 通道 C
def test_channel_c_full_match(now):
    tier = p.is_edl_candidate(
        set(), p.FALLBACK_MIN_SCORE, p.FALLBACK_MIN_CONFIDENCE, now,
        p.FALLBACK_MIN_SEEN_COUNT, 0, now,
    )
    assert tier == "C"


def test_channel_c_rejected_when_frequency_insufficient(now):
    tier = p.is_edl_candidate(
        set(), p.FALLBACK_MIN_SCORE, p.FALLBACK_MIN_CONFIDENCE, now,
        p.FALLBACK_MIN_SEEN_COUNT - 1, 0, now,
    )
    assert tier is None


def test_channel_c_rejected_outside_24h_window(now):
    stale = now - timedelta(hours=p.FALLBACK_WINDOW_HOURS + 1)
    tier = p.is_edl_candidate(
        set(), p.FALLBACK_MIN_SCORE, p.FALLBACK_MIN_CONFIDENCE, stale,
        p.FALLBACK_MIN_SEEN_COUNT, 0, now,
    )
    assert tier is None


def test_channel_c_takes_priority_over_b_when_both_qualify(now):
    """2026-10-20真實發現的bug：B/C次數門檻一度被調到相等，若B先判定
    會讓C變成死代碼。這裡刻意構造『同時滿足B跟C』的數值，鎖住C必須
    優先命中。"""
    tier = p.is_edl_candidate(
        set(), p.FALLBACK_MIN_SCORE, p.FALLBACK_MIN_CONFIDENCE, now,
        seen_count_c=p.FALLBACK_MIN_SEEN_COUNT,
        seen_count_b=p.PERSISTENCE_MIN_SEEN_COUNT,
        now=now,
    )
    assert tier == "C"


# ---------------------------------------------------------------- 通道 B
def test_channel_b_full_match(now):
    tier = p.is_edl_candidate(
        set(), p.PERSISTENCE_MIN_SCORE, p.PERSISTENCE_MIN_CONFIDENCE, now,
        seen_count_c=0, seen_count_b=p.PERSISTENCE_MIN_SEEN_COUNT, now=now,
    )
    assert tier == "B"


def test_channel_b_rejected_when_frequency_insufficient(now):
    tier = p.is_edl_candidate(
        set(), p.PERSISTENCE_MIN_SCORE, p.PERSISTENCE_MIN_CONFIDENCE, now,
        seen_count_c=0, seen_count_b=p.PERSISTENCE_MIN_SEEN_COUNT - 1, now=now,
    )
    assert tier is None


def test_channel_b_rejected_when_score_or_confidence_too_low(now):
    assert p.is_edl_candidate(
        set(), p.PERSISTENCE_MIN_SCORE - 1, p.PERSISTENCE_MIN_CONFIDENCE, now,
        0, p.PERSISTENCE_MIN_SEEN_COUNT, now,
    ) is None
    assert p.is_edl_candidate(
        set(), p.PERSISTENCE_MIN_SCORE, p.PERSISTENCE_MIN_CONFIDENCE - 1, now,
        0, p.PERSISTENCE_MIN_SEEN_COUNT, now,
    ) is None


def test_channel_b_has_no_upper_score_cap(now):
    """2026-10-22調整：通道B的分數上限只是文件/文字描述，程式邏輯從
    未真的封頂98分，滿分100一樣要能收錄進通道B（前提是沒有同時命中
    通道A/C）。"""
    tier = p.is_edl_candidate(
        set(), 100, p.PERSISTENCE_MIN_CONFIDENCE, now,
        seen_count_c=0, seen_count_b=p.PERSISTENCE_MIN_SEEN_COUNT, now=now,
    )
    assert tier == "B"


def test_channel_b_accepted_within_new_7day_recency_window(now):
    recent = now - timedelta(days=p.PERSISTENCE_RECENCY_WINDOW_DAYS - 1)
    tier = p.is_edl_candidate(
        set(), p.PERSISTENCE_MIN_SCORE, p.PERSISTENCE_MIN_CONFIDENCE, recent,
        seen_count_c=0, seen_count_b=p.PERSISTENCE_MIN_SEEN_COUNT, now=now,
    )
    assert tier == "B"


def test_channel_b_rejected_when_stale_beyond_7days_even_with_enough_14day_frequency(now):
    """2026-10-22真實規則調整的核心回歸測試：最後活躍已經超過7天的
    『死魚級』頑固IP，即使14天內仍累積到5次以上，也不該再被通道B
    收錄——這是本次調整要修正的真實行為，必須鎖住不能倒退回舊規則。"""
    stale = now - timedelta(days=p.PERSISTENCE_RECENCY_WINDOW_DAYS + 1)
    tier = p.is_edl_candidate(
        set(), p.PERSISTENCE_MIN_SCORE, p.PERSISTENCE_MIN_CONFIDENCE, stale,
        seen_count_c=0, seen_count_b=p.PERSISTENCE_MIN_SEEN_COUNT, now=now,
    )
    assert tier is None


def test_channel_b_recency_window_is_independent_from_frequency_window(now):
    """確保時效窗口(7天)真的跟頻次窗口(14天)分開判斷，不是同一個數字
    改兩個名字——用剛好落在『7天外、14天內』這個只有拆開後才會出現
    差異的區間來驗證。"""
    just_outside_recency = now - timedelta(days=p.PERSISTENCE_RECENCY_WINDOW_DAYS + 1)
    assert just_outside_recency >= now - timedelta(days=p.PERSISTENCE_WINDOW_DAYS)
    tier = p.is_edl_candidate(
        set(), p.PERSISTENCE_MIN_SCORE, p.PERSISTENCE_MIN_CONFIDENCE,
        just_outside_recency, seen_count_c=0, seen_count_b=p.PERSISTENCE_MIN_SEEN_COUNT, now=now,
    )
    assert tier is None, "last_seen落在7~14天區間時應被新規則排除"


def test_nothing_qualifies_returns_none(now):
    tier = p.is_edl_candidate(set(), 10, 10, now, 0, 0, now)
    assert tier is None
