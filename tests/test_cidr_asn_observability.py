"""
「CIDR安全拒絕 x ASN節流」互動情境的可觀測性統計（選項D：只新增統計，
不改變既有選擇結果）。驗證 select_edl_candidates() 新增的統計欄位：
  pre_aggregation_candidate_count / post_aggregation_entry_count
  cidr_rejected_subnet_count / cidr_rejected_candidate_ip_count
  asn_throttle_excluded_entries / asn_throttle_excluded_unique_ip_count
  asn_throttle_excluded_from_rejected_cidr_count
  asn_throttle_excluded_high_score_unique_ip_count
  final_unique_ip_coverage

歸因方式一律用 aggregate_to_cidr() 的 rejected_subnet_reports 這個明確
的內部metadata（分組當下直接記錄），不靠事後字串/正規表示式猜測。
"""
from datetime import timedelta
from unittest.mock import patch

import pipeline as p


def _iso(now, days_ago=0, hours_ago=0):
    return (now - timedelta(days=days_ago, hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_candidate_record(make_record, now, score, asn):
    """通道A（命中must-have標籤）完全不受ASN節流影響（見throttle_by_asn()
    docstring：『通道A...一律保留』），所以凡是要測ASN節流互動情境的
    候選，一律不能用通道A，改用通道C的樣式（無標籤、近7天內3次以上、
    分數/信心值達標）：score可以是88~100之間任何值，照樣能滿足通道C
    的score>=99？——不行，通道C要求score>=99，可用範圍太窄不利測試
    分數排序，這裡改用通道B樣式（無標籤、近14天內5次以上、score>=88
    無上限、confidence>=80），分數可用範圍是88~100，足夠用來測試
    throttle_by_asn()按分數排序的節流行為。"""
    return make_record(
        labels=[], threat_score=score, confidence=90,
        last_seen=_iso(now, hours_ago=1), asn=asn,
        seen_history=[_iso(now, days_ago=d) for d in range(5)],  # 近14天內5次，滿足通道B頻次門檻
        seen_count=5,
    )


def _run(base, now, protected_ranges):
    with patch.object(p, "load_public_infra_matcher", lambda: (lambda ip, asn: False)), \
         patch.object(p, "load_public_infra_cidr_ranges", lambda: protected_ranges):
        return p.select_edl_candidates(base, now)


# --------------------------------------------------------------------------- #
# 1. CIDR聚合成功時，新舊統計都要維持原樣
# --------------------------------------------------------------------------- #
def test_successful_aggregation_leaves_all_stats_as_before(make_record, now):
    subnet_ips = [f"45.33.100.{i}" for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1)]
    base = {ip: _make_candidate_record(make_record, now, 95, "AS64500 Example") for ip in subnet_ips}

    selected, stats, _export, _retired = _run(base, now, protected_ranges=[])

    # 既有行為：成功聚合成1個CIDR，5筆候選全部保留
    assert selected == ["45.33.100.0/24"]
    assert stats["cidr_rollup_subnets"] == 1
    assert stats["cidr_rollup_ips_absorbed"] == len(subnet_ips)
    assert stats["asn_throttle_excluded"] == 0

    # 新增統計：完全沒有任何網段被拒絕聚合
    assert stats["cidr_rejected_subnet_count"] == 0
    assert stats["cidr_rejected_candidate_ip_count"] == 0
    assert stats["asn_throttle_excluded_from_rejected_cidr_count"] == 0
    assert stats["asn_throttle_excluded_entries"] == 0
    assert stats["asn_throttle_excluded_unique_ip_count"] == 0
    assert stats["asn_throttle_excluded_high_score_unique_ip_count"] == 0

    # 新增的「明確區分」統計
    assert stats["pre_aggregation_candidate_count"] == len(subnet_ips)
    assert stats["post_aggregation_entry_count"] == 1  # 聚合後只剩1個CIDR條目
    assert stats["final_unique_ip_coverage"] == len(subnet_ips)  # 唯一IP數仍是5


# --------------------------------------------------------------------------- #
# 2. CIDR聚合遭拒絕，部分IP被ASN節流排除 -> 統計要正確歸因
# --------------------------------------------------------------------------- #
def test_rejection_and_partial_throttle_attributed_correctly(make_record, now):
    """
    同一ASN，三組候選（全部用通道B樣式：無標籤、score>=88、近14天內
    5次，確保不會命中通道A而被排除在ASN節流機制之外）：
      網段A（45.33.100.x，5筆，分數[100,96,93,90,89]）：因與保護網段
        重疊被拒絕聚合，退回5個個別條目。
      網段B（45.33.101.x，3筆，分數[99,98,97]）：獨立候選，未達聚合
        門檻，不涉及拒絕。
      網段C（45.33.102.1，1筆，分數88）：另一個獨立候選，分數全場最低。

    總共9個條目競爭同ASN的5個節流名額，依分數排序：
      100(A) 99(B) 98(B) 97(B) 96(A) | 93(A) 90(A) 89(A) 88(C)
      ─────────── 保留5筆 ───────────   ────── 節流排除4筆 ──────

    保留：A的2筆(100,96) + B的3筆(99,98,97) = 5筆
    排除：A的3筆(93,90,89) + C的1筆(88) = 4筆

    驗證重點：節流排除的4筆條目裡，只有3筆（不是全部4筆、也不是0筆）
    來自「CIDR聚合遭拒絕」的網段A——C完全無關，不該被誤算進歸因統計。
    """
    asn = "AS64500 Example"
    subnet_a_ips = [f"45.33.100.{i}" for i in range(1, 6)]
    subnet_a_scores = [100, 96, 93, 90, 89]
    subnet_b_ips = [f"45.33.101.{i}" for i in range(1, 4)]
    subnet_b_scores = [99, 98, 97]
    subnet_c_ip = "45.33.102.1"
    subnet_c_score = 88

    base = {}
    for ip, score in zip(subnet_a_ips, subnet_a_scores):
        base[ip] = _make_candidate_record(make_record, now, score, asn)
    for ip, score in zip(subnet_b_ips, subnet_b_scores):
        base[ip] = _make_candidate_record(make_record, now, score, asn)
    base[subnet_c_ip] = _make_candidate_record(make_record, now, subnet_c_score, asn)

    import ipaddress
    protected = [ipaddress.ip_network("45.33.100.0/24")]
    selected, stats, _export, _retired = _run(base, now, protected_ranges=protected)

    assert "45.33.100.0/24" not in selected  # 確認網段A真的被拒絕聚合

    assert stats["cidr_rejected_subnet_count"] == 1
    assert stats["cidr_rejected_candidate_ip_count"] == 5

    assert stats["asn_throttle_excluded_entries"] == 4
    assert stats["asn_throttle_excluded_unique_ip_count"] == 4
    # 核心歸因：4筆被節流排除的條目裡，只有3筆來自遭拒絕的網段A
    # （85,80,75），不是4筆也不是0筆——證明交叉比對確實有在做集合運算，
    # 不是直接複製asn_throttle_excluded_entries的數字。
    assert stats["asn_throttle_excluded_from_rejected_cidr_count"] == 3
    assert stats["asn_throttle_excluded_from_rejected_cidr_count"] != stats["asn_throttle_excluded_entries"]

    # 高分稽核門檻(預設95)：被節流排除的4筆裡，只有85/80/75/70，沒有一筆
    # 達到95分以上，所以這個統計應該是0。
    assert stats["asn_throttle_excluded_high_score_unique_ip_count"] == 0


def test_high_score_audit_count_catches_severe_throttled_case(make_record, now):
    """驗證「被節流排除且達高分稽核門檻」統計真的會被觸發，不是恆為0
    的死欄位：構造一個分數96分（高於門檻95）但仍被節流擠掉的候選。"""
    asn = "AS64500 Example"
    subnet_a_ips = [f"45.33.100.{i}" for i in range(1, 6)]
    subnet_a_scores = [100, 99, 98, 97, 96]  # 全部 >= 96，含剛好達門檻95以上者
    subnet_b_ip = "45.33.101.1"
    subnet_b_score = 100  # 比A組任何一筆都高，確保能擠掉A組某一筆

    base = {ip: _make_candidate_record(make_record, now, score, asn)
            for ip, score in zip(subnet_a_ips, subnet_a_scores)}
    base[subnet_b_ip] = _make_candidate_record(make_record, now, subnet_b_score, asn)

    import ipaddress
    protected = [ipaddress.ip_network("45.33.100.0/24")]
    _selected, stats, _export, _retired = _run(base, now, protected_ranges=protected)

    # 6個條目搶5個名額：B(100) + A(100,99,98,97) 保留，A(96)被擠掉
    assert stats["asn_throttle_excluded_entries"] == 1
    assert stats["asn_throttle_excluded_high_score_unique_ip_count"] == 1
    assert stats["asn_throttle_excluded_from_rejected_cidr_count"] == 1


# --------------------------------------------------------------------------- #
# 3. 一般候選IP不會被錯誤標記為來自遭拒絕網段
# --------------------------------------------------------------------------- #
def test_normal_candidates_not_mislabeled_as_rejected_origin(make_record, now):
    """直接檢查 aggregate_to_cidr() 的 rejected_subnet_reports 明確
    metadata，確認只有網段A在裡面，網段B/C的IP完全不會被記錄進去。"""
    candidates = (
        [(ip, 90, "2026-10-21T00:00:00Z", "C") for ip in [f"45.33.100.{i}" for i in range(1, 6)]]
        + [(ip, 90, "2026-10-21T00:00:00Z", "C") for ip in [f"45.33.101.{i}" for i in range(1, 4)]]
    )
    base = {ip: {"asn": "AS64500"} for ip, *_ in candidates}
    import ipaddress
    protected = [ipaddress.ip_network("45.33.100.0/24")]

    reports: list = []
    p.aggregate_to_cidr(candidates, base, lambda ip, asn: False, protected, rejected_subnet_reports=reports)

    assert len(reports) == 1
    assert reports[0]["subnet"] == "45.33.100.0/24"
    reported_ips = set(reports[0]["member_ips"])
    assert reported_ips == {f"45.33.100.{i}" for i in range(1, 6)}
    # 網段B的IP一個都不該出現在任何一筆report裡
    for ip in [f"45.33.101.{i}" for i in range(1, 4)]:
        assert ip not in reported_ips


def test_subnet_below_threshold_not_recorded_as_rejected():
    """候選數原本就沒達到CIDR_ROLLUP_THRESHOLD的網段，根本沒有嘗試
    聚合，不該被記錄進rejected_subnet_reports——『未達門檻』跟『達門檻
    但沒通過安全檢查』在統計意義上是兩回事，不可混為一談。"""
    ips = [f"45.33.100.{i}" for i in range(1, p.CIDR_ROLLUP_THRESHOLD)]  # threshold-1筆，未達門檻
    candidates = [(ip, 90, "2026-10-21T00:00:00Z", "C") for ip in ips]
    base = {ip: {"asn": "AS64500"} for ip in ips}

    reports: list = []
    p.aggregate_to_cidr(candidates, base, lambda ip, asn: False, protected_ranges=[], rejected_subnet_reports=reports)
    assert reports == []


def test_rejected_subnet_reports_default_none_has_zero_side_effect():
    """不傳 rejected_subnet_reports 參數（舊呼叫端的既有用法）時，函式
    行為必須跟加這個功能之前完全一致，不能要求所有呼叫端都更新。"""
    ips = [f"45.33.100.{i}" for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1)]
    candidates = [(ip, 90, "2026-10-21T00:00:00Z", "C") for ip in ips]
    base = {ip: {"asn": "AS64500"} for ip in ips}
    import ipaddress
    protected = [ipaddress.ip_network("45.33.100.0/24")]

    # 不傳 rejected_subnet_reports，應該正常運作、不報錯
    entries = p.aggregate_to_cidr(candidates, base, lambda ip, asn: False, protected)
    assert len(entries) == len(ips)
    assert all("/" not in e[0] for e in entries)


# --------------------------------------------------------------------------- #
# 4. 不同ASN之間統計不互相污染
# --------------------------------------------------------------------------- #
def test_stats_do_not_cross_contaminate_between_asns(make_record, now):
    """ASN甲有一個遭拒絕聚合的網段（5筆退回個別IP，剛好打滿自己的節流
    上限，不觸發節流）；ASN乙完全是另一回事——5筆各自不同/24、從未
    嘗試聚合的候選，同樣剛好打滿自己的節流上限。兩邊都是0筆被節流，
    藉此驗證 cidr_rejected_subnet_count / cidr_rejected_candidate_ip_
    count 只歸因到ASN甲，不會因為兩個ASN的候選混在同一次執行裡就
    互相污染或重複計算。"""
    asn_a = "AS64500 Example"
    asn_b = "AS64999 Other"

    subnet_a_ips = [f"45.33.100.{i}" for i in range(1, 6)]
    subnet_a_scores = [100, 96, 93, 90, 88]
    base = {ip: _make_candidate_record(make_record, now, score, asn_a)
            for ip, score in zip(subnet_a_ips, subnet_a_scores)}

    # ASN乙：5筆各自不同/24（都未達聚合門檻，從未嘗試聚合），分數跟
    # ASN甲完全無關，剛好5筆打滿自己ASN的節流上限。
    asn_b_scores = [95, 94, 93, 92, 91]
    for i, score in enumerate(asn_b_scores):
        ip = f"91.{i}.0.1"
        base[ip] = _make_candidate_record(make_record, now, score, asn_b)

    import ipaddress
    protected = [ipaddress.ip_network("45.33.100.0/24")]
    _selected, stats, _export, _retired = _run(base, now, protected_ranges=protected)

    # ASN甲：5筆候選搶5個名額 -> 不會被自己節流（條目數剛好等於上限）
    # ASN乙：5筆未聚合候選搶5個名額 -> 也剛好打滿，同樣不觸發節流
    assert stats["asn_throttle_excluded_entries"] == 0
    assert stats["cidr_rejected_subnet_count"] == 1
    assert stats["cidr_rejected_candidate_ip_count"] == 5
    # 沒有任何IP被節流排除，歸因統計自然也是0，而不是誤算進ASN乙的任何東西
    assert stats["asn_throttle_excluded_from_rejected_cidr_count"] == 0


# --------------------------------------------------------------------------- #
# 5. 唯一IP數不因CIDR條目與個別IP重複/漏算
# --------------------------------------------------------------------------- #
def test_final_unique_ip_coverage_counts_cidr_members_and_individuals_correctly(make_record, now):
    """最終輸出同時包含1個成功聚合的CIDR條目(5個成員IP)跟3個完全不同
    ASN、不同網段的個別IP條目，final_unique_ip_coverage應該精準等於
    5+3=8，不多不少。"""
    base = {}
    cidr_ips = [f"45.33.100.{i}" for i in range(1, 6)]
    for ip in cidr_ips:
        base[ip] = _make_candidate_record(make_record, now, 95, "AS64500 Example")

    individual_ips = ["45.1.1.1", "45.2.2.2", "45.3.3.3"]
    for i, ip in enumerate(individual_ips):
        base[ip] = _make_candidate_record(make_record, now, 90, f"AS700{i} Example")

    selected, stats, export_entries, _retired = _run(base, now, protected_ranges=[])

    assert "45.33.100.0/24" in selected
    for ip in individual_ips:
        assert ip in selected

    assert stats["final_unique_ip_coverage"] == len(cidr_ips) + len(individual_ips)  # 5+3=8

    # 交叉驗證：直接攤平export_entries的member_ips，用set去重後應該也是8，
    # 且跟final_unique_ip_coverage完全吻合，證明沒有重複/漏算。
    all_covered = set()
    for entry in export_entries:
        all_covered.update(entry[5])
    assert len(all_covered) == stats["final_unique_ip_coverage"]
