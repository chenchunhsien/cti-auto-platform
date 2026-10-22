"""
入榜判定說明文字（build_trigger_reason()）：純英文、無大寫代碼前綴、
無靜態門檻括號；複合命中以 " | " 串接各通道真實觀測數值。
"""
import re

import pipeline as p

NO_CODE_PREFIX = re.compile(r"CHANNEL_|CRITICAL_THREAT:|PERSISTENT_PROBE:|HIGH_CONFIDENCE:")
NO_THRESHOLD_PAREN = re.compile(r"\(>=|\(\d+-\d+\)")


def test_channel_a_format():
    text = p.build_trigger_reason("A", False, 92, 95, freq_b=0, freq_c=0, label_union={"trojan"})
    assert text == "Matched tag [trojan] with score 92"


def test_channel_a_multiple_matched_tags_sorted_and_comma_joined():
    text = p.build_trigger_reason("A", False, 100, 99, 0, 0, {"cnc", "c2"})
    assert text == "Matched tag [c2, cnc] with score 100"


def test_channel_a_unknown_tag_fallback():
    """命中MUST_HAVE_TAGS以外標籤的情況理論上不會發生在tier=A的資料上，
    但函式本身要能處理空交集而不崩潰。"""
    text = p.build_trigger_reason("A", False, 90, 90, 0, 0, set())
    assert text == "Matched tag [unknown] with score 90"


def test_channel_b_format():
    text = p.build_trigger_reason("B", False, 98, 95, freq_b=5, freq_c=0, label_union=set())
    assert text == f"Observed 5 hits within {p.PERSISTENCE_WINDOW_DAYS}d, score 98, conf 95"


def test_channel_c_format():
    text = p.build_trigger_reason("C", False, 99, 99, freq_b=0, freq_c=3, label_union=set())
    assert text == f"Score 99 with 3 hits in {p.RECENT_WINDOW_DAYS}d, conf 99"


def test_cidr_format():
    text = p.build_trigger_reason("A", True, 100, 99, 0, 0, set())
    assert text == "Subnet rollup triggered by malicious entries in /24 block (representative_channel=A)"


def test_composite_a_and_c():
    text = p.build_trigger_reason(
        "A", False, 100, 99,
        freq_b=0, freq_c=p.FALLBACK_MIN_SEEN_COUNT, label_union={"cnc"},
    )
    assert text == (
        "Matched tag [cnc] with score 100 | "
        f"Score 100 with {p.FALLBACK_MIN_SEEN_COUNT} hits in {p.RECENT_WINDOW_DAYS}d, conf 99"
    )


def test_composite_a_and_b():
    text = p.build_trigger_reason(
        "A", False, 100, 95,
        freq_b=p.PERSISTENCE_MIN_SEEN_COUNT, freq_c=0, label_union={"bruteforce"},
    )
    assert text == (
        "Matched tag [bruteforce] with score 100 | "
        f"Observed {p.PERSISTENCE_MIN_SEEN_COUNT} hits within {p.PERSISTENCE_WINDOW_DAYS}d, score 100, conf 95"
    )


def test_composite_a_and_c_and_b_ordered_a_c_b():
    """三者同時命中時，依 A -> C -> B 的既定優先序串接。"""
    text = p.build_trigger_reason(
        "A", False, 100, 99,
        freq_b=p.PERSISTENCE_MIN_SEEN_COUNT, freq_c=p.FALLBACK_MIN_SEEN_COUNT, label_union={"cnc"},
    )
    parts = text.split(" | ")
    assert len(parts) == 3
    assert parts[0].startswith("Matched tag")
    assert parts[1].startswith("Score")  # 通道C的格式
    assert parts[2].startswith("Observed")  # 通道B的格式


def test_no_composite_when_not_fully_qualified():
    """只滿足部分數值（例如只有頻次夠、分數不夠）不該被判定為複合命中。"""
    text = p.build_trigger_reason(
        "A", False, 50, 50,  # 分數/信心值都太低，不足以滿足B或C
        freq_b=p.PERSISTENCE_MIN_SEEN_COUNT, freq_c=p.FALLBACK_MIN_SEEN_COUNT,
        label_union={"cnc"},
    )
    assert " | " not in text


def test_no_uppercase_code_prefix_or_threshold_parens_anywhere():
    samples = [
        p.build_trigger_reason("A", False, 100, 99, 5, 3, {"cnc"}),
        p.build_trigger_reason("B", False, 98, 95, 5, 0, set()),
        p.build_trigger_reason("C", False, 99, 99, 0, 3, set()),
        p.build_trigger_reason("A", True, 100, 99, 0, 0, set()),
    ]
    for text in samples:
        assert not NO_CODE_PREFIX.search(text), text
        assert not NO_THRESHOLD_PAREN.search(text), text
