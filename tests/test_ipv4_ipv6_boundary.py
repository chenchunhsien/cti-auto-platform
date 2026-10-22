"""
IPv4/IPv6 邊界回歸測試（審查後新增，2026-10-22）。

背景：/24 CIDR聚合（aggregate_to_cidr()）用 f"{ip}/24" 字串組合建構子網
——對IPv6位址而言，ipaddress.ip_network()仍會「成功」解析成一個
IPv6Network（/24是合法的IPv6前綴長度，但涵蓋範圍跟IPv4的/24完全不是
一回事）。實測確認過（不是理論推測）：這不會讓verify_cidr_safe_for_
aggregation()拋出例外——Python的ipaddress模組對不同版本的網段呼叫
.overlaps()一律回傳False、不會報錯——真正的風險是「靜默產生一個像
`2001:d00::/24`這種對防火牆毫無意義的假CIDR聚合條目」；真正會crash的
地方在更下游：select_edl_candidates()最終排序selected清單時假設每個
字串都能拆成IPv4四段式數字，遇到IPv6字串會丟ValueError，讓整次排程
中斷。

is_valid_public_ip() 本身對IPv4/IPv6一視同仁（用ipaddress.ip_address()
判斷是否為合法可路由公網位址），之所以過去沒出過事，純粹是因為STIX
解析正規表達式只匹配ipv4-addr:value，IPv6字串根本進不了base_iocs.json
——這是意外的保護，不是刻意設計的邊界。本檔案測試修正後的明確邊界：
候選蒐集階段（select_edl_candidates() / rule_analysis.py 的候選迴圈）
會主動排除IPv6，aggregate_to_cidr() 本身也有一道不依賴呼叫端自律的
防線。

tests/test_cidr_aggregation.py 已經涵蓋 aggregate_to_cidr() 本身的IPv6
邊界（不轉換成/24、不產生無意義的假聚合條目、混合輸入不中斷IPv4處理）；
這裡測試更上層、串接完整候選蒐集流程的 select_edl_candidates() 與
rule_analysis.py——包含驗證修正前實際會在排序階段丟出ValueError崩潰。
"""
from datetime import timedelta
from unittest.mock import patch

import pipeline as p
import rule_analysis as ra


def _iso(now, days_ago=0, hours_ago=0):
    return (now - timedelta(days=days_ago, hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


# 真實、全域可路由的IPv6位址（Cloudflare/Google公用DNS），確保
# is_valid_public_ip() 判定為routable=True——用來驗證「routable但非
# IPv4」這個新邊界本身的行為，而不是被is_valid_public_ip()既有的
# 組播/私有/保留規則連帶擋掉。
ROUTABLE_IPV6 = "2606:4700:4700::1111"
ROUTABLE_IPV6_2 = "2001:4860:4860::8888"


def _run_select(base, now):
    with patch.object(p, "load_public_infra_matcher", lambda: (lambda ip, asn: False)), \
         patch.object(p, "load_public_infra_cidr_ranges", lambda: []):
        return p.select_edl_candidates(base, now)


# --------------------------------------------------------------------------- #
# select_edl_candidates()：候選入口的IPv4守門
# --------------------------------------------------------------------------- #
def test_routable_ipv6_excluded_with_dedicated_stat(make_record, now):
    """即使是真實可路由的IPv6位址、且標籤/分數都滿足通道A條件，也必須
    被排除於EDL之外，且要有專屬的excluded_non_ipv4統計（不能跟『非公開
    路由』的excluded_non_routable混在一起，因為is_valid_public_ip()本來
    就會判定它是routable的）。"""
    base = {
        ROUTABLE_IPV6: make_record(
            labels=["c2"], threat_score=95, confidence=90, last_seen=_iso(now, hours_ago=1)
        ),
    }
    selected, stats, _export, _retired = _run_select(base, now)

    assert ROUTABLE_IPV6 not in selected
    assert stats["excluded_non_ipv4"] == 1
    assert stats["excluded_non_routable"] == 0  # 不應該被誤算進這個桶
    assert stats["condition_a"] == 0
    assert base[ROUTABLE_IPV6]["edl_tier"] is None


def test_mixed_ipv4_ipv6_candidates_ipv4_still_selected_normally(make_record, now):
    """混合輸入：IPv4候選（符合通道A）與IPv6候選並存時，IPv4候選的
    判定與輸出必須完全不受影響——驗證IPv6排除邏輯不會意外中斷或跳過
    其他候選的處理（例如迴圈提前return、或共用變數被污染）。"""
    base = {
        "45.33.1.1": make_record(
            labels=["c2"], threat_score=95, confidence=90, last_seen=_iso(now, hours_ago=1)
        ),
        ROUTABLE_IPV6: make_record(
            labels=["c2"], threat_score=95, confidence=90, last_seen=_iso(now, hours_ago=1)
        ),
        ROUTABLE_IPV6_2: make_record(
            labels=["c2"], threat_score=95, confidence=90, last_seen=_iso(now, hours_ago=1)
        ),
    }
    selected, stats, _export, _retired = _run_select(base, now)

    assert "45.33.1.1" in selected
    assert ROUTABLE_IPV6 not in selected
    assert ROUTABLE_IPV6_2 not in selected
    assert stats["condition_a"] == 1
    assert stats["excluded_non_ipv4"] == 2


def test_pure_ipv4_regression_unchanged(make_record, now):
    """迴歸測試：純IPv4情境下，三通道各自命中一筆的結果必須跟加入IPv4
    守門前完全一致（不多也不少）。"""
    base = {
        "45.33.1.1": make_record(  # 通道A
            labels=["c2"], threat_score=95, confidence=90, last_seen=_iso(now, hours_ago=1)
        ),
        "45.33.1.2": make_record(  # 通道B：7天內活躍、14天內>=5次、score>=88、confidence>=80
            labels=[], threat_score=90, confidence=85, last_seen=_iso(now, days_ago=2),
            seen_history=[_iso(now, d) for d in [1, 3, 6, 9, 12]],
        ),
        "45.33.1.3": make_record(  # 通道C：24小時內、7天內>=3次、score>=99、confidence>=90
            labels=[], threat_score=99, confidence=95, last_seen=_iso(now, hours_ago=1),
            seen_history=[_iso(now, hours_ago=h) for h in [1, 30, 60]],
        ),
    }
    selected, stats, _export, _retired = _run_select(base, now)

    assert set(selected) == {"45.33.1.1", "45.33.1.2", "45.33.1.3"}
    assert stats["condition_a"] == 1
    assert stats["condition_b"] == 1
    assert stats["condition_c"] == 1
    assert stats["excluded_non_ipv4"] == 0


# --------------------------------------------------------------------------- #
# rule_analysis.py：候選蒐集迴圈與decision detail的IPv4守門
# --------------------------------------------------------------------------- #
def test_evaluate_ip_decision_marks_ipv6_as_unsupported(make_record, now):
    """routable=True（真實可路由IPv6）但is_ipv4=False時，exclusion_reason
    必須明確標示為UNSUPPORTED_IP_VERSION，不能落入channel_match_tier
    被計算出非None值、卻又沒被任何既有分類涵蓋的灰色地帶。"""
    record = make_record(
        labels=["c2"], threat_score=95, confidence=90, last_seen=_iso(now, hours_ago=1)
    )
    row = ra.evaluate_ip_decision(
        ROUTABLE_IPV6, record, now, is_public_cloud=lambda ip, asn: False
    )

    assert row["routable"] is True
    assert row["is_ipv4"] is False
    assert row["channel_match_tier"] is None
    assert row["final_tier"] is None
    assert row["exclusion_reason"] == ra.EXCLUSION_UNSUPPORTED_IP_VERSION


def test_build_decision_detail_rows_does_not_crash_on_ipv6(make_record, now):
    """串接完整流程（含aggregate_to_cidr()）：base裡混有IPv6紀錄時，
    build_decision_detail_rows()不應拋出例外，且IPv6那筆不會被排進
    candidates、不會出現在聚合/節流結果裡。"""
    base = {
        "45.33.1.1": make_record(
            labels=["c2"], threat_score=95, confidence=90, last_seen=_iso(now, hours_ago=1)
        ),
        ROUTABLE_IPV6: make_record(
            labels=["c2"], threat_score=95, confidence=90, last_seen=_iso(now, hours_ago=1)
        ),
    }
    with patch.object(p, "load_public_infra_matcher", lambda: (lambda ip, asn: False)), \
         patch.object(p, "load_public_infra_cidr_ranges", lambda: []):
        rows = ra.build_decision_detail_rows(base, now)

    rows_by_ip = {r["ip"]: r for r in rows}
    assert rows_by_ip["45.33.1.1"]["final_tier"] == "A"
    assert rows_by_ip[ROUTABLE_IPV6]["final_tier"] is None
    assert rows_by_ip[ROUTABLE_IPV6]["exclusion_reason"] == ra.EXCLUSION_UNSUPPORTED_IP_VERSION


# --------------------------------------------------------------------------- #
# rule_analysis.run_ruleset()：回測模式的IPv4守門
# --------------------------------------------------------------------------- #
def test_run_ruleset_excludes_ipv6_with_dedicated_stat(make_record, now):
    base = {
        "45.33.1.1": make_record(
            labels=["c2"], threat_score=95, confidence=90, last_seen=_iso(now, hours_ago=1)
        ),
        ROUTABLE_IPV6: make_record(
            labels=["c2"], threat_score=95, confidence=90, last_seen=_iso(now, hours_ago=1)
        ),
    }
    with patch.object(p, "load_public_infra_matcher", lambda: (lambda ip, asn: False)), \
         patch.object(p, "load_public_infra_cidr_ranges", lambda: []):
        edl_ips, stats = ra.run_ruleset(base, now, ra.DEFAULT_THRESHOLDS)

    assert "45.33.1.1" in edl_ips
    assert ROUTABLE_IPV6 not in edl_ips
    assert stats["excluded_non_ipv4"] == 1
    assert stats["condition_a"] == 1
