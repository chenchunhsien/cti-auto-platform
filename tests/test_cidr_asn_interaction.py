"""
「CIDR安全拒絕 × ASN節流」互動情境（合併前審查發現的中等風險項）。

本檔案純粹是「釐清現行行為 + 鎖住現狀」的分析用測試，不代表任何政策
決定——throttle_by_asn()按『輸出條目數』（不是『個別IP數』）計算ASN
上限是現行程式碼明確且刻意的設計（見其docstring），這份測試證明：
當 aggregate_to_cidr() 因安全檢查拒絕聚合、把一個本來只會占用1個條目
的候選網段拆回N個個別IP條目時，這N個條目會各自競爭同一個ASN節流
上限的名額，可能排擠掉『跟這個被拒絕網段完全無關』的其他候選IP。

這不是bug（程式碼確實是照文件說的方式運作），而是這次新增的CIDR安全
檢查功能，跟既有的ASN節流政策疊加後才會出現的全新情境——原本的節流
政策從未預期過『一個候選網段從1條目變成N條目』這種情況。要不要調整
這個互動行為，是政策選擇題，這份測試不替未來的決策預設答案，只負責
把現狀用可重現的方式鎖住。
"""
import ipaddress

import pipeline as p


def _candidate(ip, score, tier="C", last_seen="2026-10-21T00:00:00Z"):
    return (ip, score, last_seen, tier)


NOT_WHITELISTED = lambda ip, asn: False  # noqa: E731


def _base_for(ips, asn="AS64500 Example"):
    return {ip: {"asn": asn} for ip in ips}


# --------------------------------------------------------------------------- #
# 1. 釐清行為：ASN節流上限到底限制什麼
# --------------------------------------------------------------------------- #
def test_asn_cap_limits_output_entries_not_underlying_ip_count():
    """直接證明 ASN_THROTTLE_MAX_PER_ASN(=5) 限制的是『輸出條目數』，
    不是『個別IP數』：一個聚合後的CIDR條目（背後涵蓋20個IP）跟4個
    個別IP條目同屬一個ASN，總共5個『條目』剛好打滿上限，全部保留——
    代表上限只數entries，不會因為CIDR背後藏了20個IP就多扣額度。"""
    cidr_entry = ("45.33.0.0/24", 100, "2026-10-21T00:00:00Z", "C", "AS64500",
                  [f"45.33.0.{i}" for i in range(20)])
    individual_entries = [
        (f"198.51.100.{i}", 90, "2026-10-21T00:00:00Z", "C", "AS64500", [f"198.51.100.{i}"])
        for i in range(1, 5)
    ]
    kept = p.throttle_by_asn([cidr_entry] + individual_entries)
    assert len(kept) == 5  # 1個CIDR條目 + 4個個別條目 = 5個『條目』，全部在上限內保留
    assert cidr_entry in kept


def test_asn_cap_does_not_count_member_ips_towards_limit():
    """同一個ASN下，只要輸出『條目數』不超過上限，背後涵蓋再多個別IP
    都不會觸發節流——反證上限單位確實是條目而非IP。"""
    big_cidr = ("45.33.0.0/24", 100, "2026-10-21T00:00:00Z", "C", "AS64500",
                [f"45.33.0.{i}" for i in range(50)])
    kept = p.throttle_by_asn([big_cidr])
    assert kept == [big_cidr]


# --------------------------------------------------------------------------- #
# 2. CIDR安全拒絕 x ASN節流互動：核心示範測試
# --------------------------------------------------------------------------- #
def test_cidr_rejection_converts_one_slot_into_many_and_can_starve_unrelated_asn_peers():
    """核心示範（對照組 vs 實驗組），完整重現審查發現的互動情境：

    同一個ASN(AS64500)下有兩個/24候選網段：
      - 網段A（203.0.113.x）：5筆候選，分數全部是96~100（全部最高分）。
      - 網段B（198.51.100.x）：3筆候選，分數93~95（比網段A低，但各自
        都還是正常合格的候選）。

    對照組（網段A聚合成功，protected_ranges=[]）：
      網段A收斂成1個CIDR條目，加上網段B的3個個別條目，同一ASN總共
      只有4個『條目』競爭5個名額 -> 全部保留，0筆被節流。

    實驗組（網段A因與保護網段重疊被拒絕聚合，protected_ranges涵蓋
    203.0.113.0/24）：
      網段A退回5個個別IP條目，加上網段B的3個，同一ASN總共8個『條目』
      競爭5個名額；因為網段A的5筆分數全部高於網段B的3筆，排序後網段A
      獨自佔滿全部5個名額 -> 網段B的3筆『完全跟網段A無關』的候選，
      全數被節流排除，即使它們本身完全合格、也沒有命中任何白名單。

    這就是審查報告指出的『CIDR安全拒絕會把1個節流名額膨脹成N個，排擠
    同ASN其他無關候選』的具體重現，證明是現行政策的邏輯後果，不是
    程式寫錯。
    """
    subnet_a_ips = [f"203.0.113.{i}" for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1)]
    subnet_a_scores = [100, 99, 98, 97, 96]
    subnet_b_ips = [f"198.51.100.{i}" for i in range(1, 4)]
    subnet_b_scores = [95, 94, 93]

    candidates = (
        [_candidate(ip, score) for ip, score in zip(subnet_a_ips, subnet_a_scores)]
        + [_candidate(ip, score) for ip, score in zip(subnet_b_ips, subnet_b_scores)]
    )
    base = _base_for(subnet_a_ips + subnet_b_ips)

    # --- 對照組：網段A成功聚合 ---
    aggregated_success = p.aggregate_to_cidr(candidates, base, NOT_WHITELISTED, protected_ranges=[])
    assert any(e[0] == "203.0.113.0/24" for e in aggregated_success), "對照組應該成功聚合成單一CIDR"
    throttled_success = p.throttle_by_asn(aggregated_success)
    kept_ips_success = set()
    for e in throttled_success:
        kept_ips_success.update(e[5])
    assert kept_ips_success == set(subnet_a_ips) | set(subnet_b_ips), (
        "對照組：聚合成功只占1個條目，同ASN共4個條目遠低於上限5，應該全部保留"
    )

    # --- 實驗組：網段A因網段重疊被拒絕聚合 ---
    protected = [ipaddress.ip_network("203.0.113.0/24")]
    aggregated_rejected = p.aggregate_to_cidr(candidates, base, NOT_WHITELISTED, protected_ranges=protected)
    assert all("/" not in e[0] for e in aggregated_rejected), "實驗組：網段A應該退回個別IP，不應該有CIDR條目"
    throttled_rejected = p.throttle_by_asn(aggregated_rejected)
    kept_ips_rejected = set()
    for e in throttled_rejected:
        kept_ips_rejected.update(e[5])

    # 現狀（非政策建議）：網段A因分數全面領先，獨佔同ASN全部5個名額
    assert kept_ips_rejected == set(subnet_a_ips), (
        "實驗組現狀：網段A的5筆個別條目分數全面領先，佔滿ASN節流上限"
    )
    # 核心發現：網段B這3筆完全合格、跟網段A無關的候選，在實驗組被完全節流排除
    assert set(subnet_b_ips).isdisjoint(kept_ips_rejected), (
        "核心發現：網段B三筆無關候選在實驗組被完全排擠出局，"
        "對照組(聚合成功)則完全不受影響——此為CIDR安全拒絕對ASN節流的連鎖效應"
    )


def test_cidr_rejection_ripple_effect_is_bounded_by_asn_cap_not_unlimited():
    """確認這個連鎖效應有其邊界：即使網段A被拒絕聚合、產生5個條目，
    也不會『整個排擠機制失控』——最終同ASN保留的條目數，不論哪種情境
    都絕對不會超過 ASN_THROTTLE_MAX_PER_ASN，這點不受CIDR聚合成功與否
    影響，仍然是現行節流政策唯一不變的硬性保證。"""
    subnet_a_ips = [f"203.0.113.{i}" for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1)]
    subnet_b_ips = [f"198.51.100.{i}" for i in range(1, 4)]
    candidates = (
        [_candidate(ip, 100 - i) for i, ip in enumerate(subnet_a_ips)]
        + [_candidate(ip, 50 - i) for i, ip in enumerate(subnet_b_ips)]
    )
    base = _base_for(subnet_a_ips + subnet_b_ips)
    protected = [ipaddress.ip_network("203.0.113.0/24")]

    aggregated = p.aggregate_to_cidr(candidates, base, NOT_WHITELISTED, protected_ranges=protected)
    throttled = p.throttle_by_asn(aggregated)
    assert len(throttled) <= p.ASN_THROTTLE_MAX_PER_ASN


def test_different_asn_not_affected_by_neighboring_rejection():
    """確認這個連鎖效應只會在『同一ASN』內發生：另一個ASN底下的候選
    完全不受網段A被拒絕聚合的影響，節流分組本來就是依ASN獨立計算。"""
    subnet_a_ips = [f"203.0.113.{i}" for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1)]
    other_asn_ips = [f"198.51.100.{i}" for i in range(1, 4)]
    candidates = (
        [_candidate(ip, 100) for ip in subnet_a_ips]
        + [_candidate(ip, 50) for ip in other_asn_ips]
    )
    base = {**_base_for(subnet_a_ips, asn="AS64500 Example"),
            **_base_for(other_asn_ips, asn="AS64999 Other")}
    protected = [ipaddress.ip_network("203.0.113.0/24")]

    aggregated = p.aggregate_to_cidr(candidates, base, NOT_WHITELISTED, protected_ranges=protected)
    throttled = p.throttle_by_asn(aggregated)
    kept_ips = set()
    for e in throttled:
        kept_ips.update(e[5])
    assert set(other_asn_ips) <= kept_ips, "不同ASN的候選不應該被網段A的拒絕聚合連累"


# --------------------------------------------------------------------------- #
# 3. 白名單IP在這個混合情境下仍必須完全不出現在最終輸出
# --------------------------------------------------------------------------- #
def test_whitelisted_ip_absent_from_final_output_even_amid_cidr_asn_interaction(make_record, now):
    """完整走過 select_edl_candidates()（而不是只測aggregate_to_cidr/
    throttle_by_asn兩個片段函式），在『CIDR安全拒絕+ASN節流互相拉扯』
    的混合情境下，額外混入幾筆真正命中白名單(exact IP)的候選，確認
    不論ASN節流名額怎麼競爭，白名單IP都在candidates階段就被擋下，
    絕對不會出現在最終selected清單裡。"""
    from datetime import timedelta
    from unittest.mock import patch

    base = {}
    whitelisted_ips = set()

    # 網段A：5筆候選，之後會被模擬成與保護網段重疊而拒絕聚合
    subnet_a_ips = [f"203.0.113.{i}" for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1)]
    for i, ip in enumerate(subnet_a_ips):
        base[ip] = make_record(labels=["c2"], threat_score=100 - i, confidence=90,
                                last_seen=(now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                asn="AS64500 Example")

    # 網段B：3筆正常候選，同ASN
    subnet_b_ips = [f"198.51.100.{i}" for i in range(1, 4)]
    for i, ip in enumerate(subnet_b_ips):
        base[ip] = make_record(labels=["c2"], threat_score=95 - i, confidence=90,
                                last_seen=(now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                asn="AS64500 Example")

    # 另外2筆，本來會合格，但命中白名單(exact IP)
    whitelisted_ips.update({"8.8.8.8", "9.9.9.9"})
    for ip in whitelisted_ips:
        base[ip] = make_record(labels=["c2"], threat_score=100, confidence=99,
                                last_seen=(now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                asn="AS64500 Example")

    protected_cidr_ranges = [ipaddress.ip_network("203.0.113.0/24")]

    def fake_matcher():
        return lambda ip, asn: ip in whitelisted_ips

    with patch.object(p, "load_public_infra_matcher", fake_matcher), \
         patch.object(p, "load_public_infra_cidr_ranges", lambda: protected_cidr_ranges):
        selected, stats, _export, _retired = p.select_edl_candidates(base, now)

    for ip in whitelisted_ips:
        assert ip not in selected, f"{ip} 命中白名單，不論ASN節流結果如何都不該出現在最終輸出"
        assert base[ip]["edl_tier"] is None
    assert stats["whitelist_excluded"] == len(whitelisted_ips)
    # 確認情境本身真的有觸發CIDR拒絕(網段A應該是個別IP，不是CIDR字串)
    assert "203.0.113.0/24" not in selected
