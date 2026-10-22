"""
IOC 收斂可觀測性分析（rule_analysis.py）：判定明細分類、CIDR評估報表，
以及「白名單命中不等於被排除在EDL外」這個現行架構的關鍵風險點。
"""
from datetime import timedelta

import pipeline as p
import rule_analysis as ra

NOT_WHITELISTED = lambda ip, asn: False  # noqa: E731
ALWAYS_WHITELISTED = lambda ip, asn: True  # noqa: E731


def _iso(now, days_ago=0, hours_ago=0):
    return (now - timedelta(days=days_ago, hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------- evaluate_ip_decision
def test_included_record_has_no_exclusion_reason(make_record, now):
    record = make_record(labels=["c2"], threat_score=95, last_seen=_iso(now, hours_ago=1))
    row = ra.evaluate_ip_decision("1.2.3.4", record, now, NOT_WHITELISTED)
    assert row["final_tier"] == "A"
    assert row["exclusion_reason"] is None


def test_scanner_noise_excluded(make_record, now):
    record = make_record(labels=["shodan"], threat_score=100, confidence=100)
    row = ra.evaluate_ip_decision("1.2.3.4", record, now, NOT_WHITELISTED)
    assert row["final_tier"] is None
    assert row["exclusion_reason"] == ra.EXCLUSION_SCANNER_NOISE


def test_not_ioc_worthy(make_record, now):
    record = make_record(labels=[], threat_score=10, confidence=10)
    row = ra.evaluate_ip_decision("1.2.3.4", record, now, NOT_WHITELISTED)
    assert row["final_tier"] is None
    assert row["exclusion_reason"] == ra.EXCLUSION_NOT_IOC_WORTHY


def test_non_routable_ip_reports_other_format_reason(make_record, now):
    record = make_record(threat_score=100, confidence=100, labels=["c2"])
    row = ra.evaluate_ip_decision("192.168.1.1", record, now, NOT_WHITELISTED)
    assert row["routable"] is False
    assert row["exclusion_reason"] == ra.EXCLUSION_OTHER_FORMAT_OR_SAFETY


def test_missing_last_seen_reports_other_format_reason(make_record, now):
    record = make_record(last_seen=None)
    row = ra.evaluate_ip_decision("1.2.3.4", record, now, NOT_WHITELISTED)
    assert row["exclusion_reason"] == ra.EXCLUSION_OTHER_FORMAT_OR_SAFETY


def test_channel_breakdown_explains_miss_reasons(make_record, now):
    """即使最終沒有命中任何通道，報表仍要能說明『差在哪裡』，不是只有
    一個布林值。"""
    record = make_record(labels=[], threat_score=50, confidence=50)
    row = ra.evaluate_ip_decision("1.2.3.4", record, now, NOT_WHITELISTED)
    assert row["channel_c"]["matched"] is False
    assert "score_below_99" in row["channel_c"]["miss_reasons"]
    assert row["channel_b"]["matched"] is False
    assert "score_below_88" in row["channel_b"]["miss_reasons"]


def test_intel_source_count_honestly_reported_as_unavailable(make_record, now):
    """資料模型沒有獨立的情報來源欄位，必須誠實回報None，不能捏造。"""
    record = make_record()
    row = ra.evaluate_ip_decision("1.2.3.4", record, now, NOT_WHITELISTED)
    assert row["intel_source_count"] is None


def test_whitelist_match_now_excludes_from_edl(make_record, now):
    """2026-10-22安全性修正的回歸測試：命中白名單時，即使通道門檻有
    命中，final_tier也必須被強制壓成None（不會被收錄進正式EDL），
    exclusion_reason正確標示為WHITELIST_OR_PUBLIC_INFRA_PROTECTED；
    channel_match_tier仍保留『假設沒有白名單時』的原始通道，供稽核。"""
    record = make_record(labels=["c2"], threat_score=95, last_seen=_iso(now, hours_ago=1))
    row = ra.evaluate_ip_decision("1.2.3.4", record, now, ALWAYS_WHITELISTED)
    assert row["whitelist_match"] is True
    assert row["channel_match_tier"] == "A"
    assert row["final_tier"] is None
    assert row["exclusion_reason"] == ra.EXCLUSION_WHITELIST_PROTECTED


def test_non_whitelisted_record_unaffected(make_record, now):
    """對照組：沒有命中白名單時，channel_match_tier跟final_tier應該
    完全一致，不受這次修正影響。"""
    record = make_record(labels=["c2"], threat_score=95, last_seen=_iso(now, hours_ago=1))
    row = ra.evaluate_ip_decision("1.2.3.4", record, now, NOT_WHITELISTED)
    assert row["whitelist_match"] is False
    assert row["channel_match_tier"] == "A"
    assert row["final_tier"] == "A"
    assert row["exclusion_reason"] is None


# ------------------------------------------------------ build_decision_detail_rows
def test_decision_detail_does_not_mutate_base(make_record, now):
    base = {
        "1.2.3.4": make_record(labels=["c2"], threat_score=95, last_seen=_iso(now, hours_ago=1)),
    }
    import copy
    before = copy.deepcopy(base)
    ra.build_decision_detail_rows(base, now)
    assert base == before


def test_cidr_members_marked_aggregated_not_individually_included(make_record, now):
    base = {}
    for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1):
        ip = f"45.33.100.{i}"
        base[ip] = make_record(
            labels=[], threat_score=99, confidence=99, last_seen=_iso(now),
            seen_history=[_iso(now, d) for d in range(3)],
            seen_count=3, asn="AS64500 Example",
        )
    rows = ra.build_decision_detail_rows(base, now)
    by_ip = {r["ip"]: r for r in rows}
    assert all(r["exclusion_reason"] == ra.EXCLUSION_AGGREGATED_INTO_CIDR for r in by_ip.values())
    assert all(r["cidr_aggregated"] for r in by_ip.values())


def test_asn_throttled_members_marked_correctly(make_record, now):
    base = {}
    for i in range(1, p.ASN_THROTTLE_MAX_PER_ASN + 3):
        ip = f"45.33.{i}.1"  # 不同/24網段，不會被CIDR聚合，單純測ASN節流
        base[ip] = make_record(
            labels=[], threat_score=99, confidence=99, last_seen=_iso(now, hours_ago=i),
            seen_history=[_iso(now, d) for d in range(3)],
            seen_count=3, asn="AS64500 Example",
        )
    rows = ra.build_decision_detail_rows(base, now)
    throttled = [r for r in rows if r["exclusion_reason"] == ra.EXCLUSION_ASN_THROTTLED]
    assert len(throttled) == 2  # ASN_THROTTLE_MAX_PER_ASN+3 候選 - 上限5 = 2筆被節流


# -------------------------------------------------------- build_cidr_aggregation_report
def test_cidr_report_fields_and_collateral_calculation(make_record, now):
    base = {}
    for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1):
        ip = f"45.33.100.{i}"
        base[ip] = make_record(
            labels=[], threat_score=99, confidence=99, last_seen=_iso(now),
            seen_history=[_iso(now, d) for d in range(3)],
            seen_count=3, asn="AS64500 Example",
        )
    report = ra.build_cidr_aggregation_report(base, now, is_public_cloud=NOT_WHITELISTED, protected_ranges=[])
    assert len(report) == 1
    entry = report[0]
    assert entry["cidr"] == "45.33.100.0/24"
    assert entry["candidate_count"] == p.CIDR_ROLLUP_THRESHOLD
    assert entry["would_aggregate"] is True
    assert entry["edl_entries_before"] == p.CIDR_ROLLUP_THRESHOLD
    assert entry["edl_entries_after"] == 1
    assert entry["entries_saved"] == p.CIDR_ROLLUP_THRESHOLD - 1
    assert entry["collateral_ips_if_aggregated"] == 256 - p.CIDR_ROLLUP_THRESHOLD
    assert entry["distinct_intel_source_count"] is None


def test_cidr_report_below_threshold_subnet_not_aggregated(make_record, now):
    base = {
        "45.33.100.1": make_record(
            labels=[], threat_score=99, confidence=99, last_seen=_iso(now),
            seen_history=[_iso(now, d) for d in range(3)], seen_count=3,
        ),
    }
    report = ra.build_cidr_aggregation_report(base, now, is_public_cloud=NOT_WHITELISTED, protected_ranges=[])
    assert len(report) == 1
    assert report[0]["would_aggregate"] is False
    assert report[0]["collateral_ips_if_aggregated"] == 0


def test_cidr_report_member_whitelist_hit_excludes_before_grouping(make_record, now):
    """候選成員本身就命中白名單時，2026-10-22修正後這些IP在
    evaluate_ip_decision()階段final_tier就已經被壓成None，根本不會
    進入CIDR分組候選名單——報表正確顯示這個網段『不存在』候選群組，
    而不是『存在但would_aggregate=False』，因為它們一開始就不會被
    當成EDL候選。"""
    base = {}
    for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1):
        ip = f"45.33.100.{i}"
        base[ip] = make_record(
            labels=[], threat_score=99, confidence=99, last_seen=_iso(now),
            seen_history=[_iso(now, d) for d in range(3)], seen_count=3,
        )
    report = ra.build_cidr_aggregation_report(
        base, now, is_public_cloud=ALWAYS_WHITELISTED, protected_ranges=[]
    )
    assert report == []


def test_cidr_report_range_overlap_rejects_without_member_whitelist_hit(make_record, now):
    """候選成員本身都沒有個別命中白名單，但整個/24網段跟已知保護網段
    重疊時，報表要正確標示 would_aggregate=False、
    whitelist_protected=False（成員本身沒有命中，這點誠實反映），
    safety_check_reason 說明是網段重疊，不是成員命中。"""
    base = {}
    for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1):
        ip = f"45.33.100.{i}"
        base[ip] = make_record(
            labels=[], threat_score=99, confidence=99, last_seen=_iso(now),
            seen_history=[_iso(now, d) for d in range(3)], seen_count=3,
        )
    import ipaddress
    protected = [ipaddress.ip_network("45.33.100.0/24")]
    report = ra.build_cidr_aggregation_report(
        base, now, is_public_cloud=NOT_WHITELISTED, protected_ranges=protected
    )
    assert len(report) == 1
    assert report[0]["whitelist_protected"] is False
    assert report[0]["would_aggregate"] is False
    assert "重疊" in report[0]["safety_check_reason"]
    assert report[0]["collateral_ips_if_aggregated"] == 0
