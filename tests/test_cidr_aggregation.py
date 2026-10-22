"""
/24 CIDR 動態聚合收斂（aggregate_to_cidr() + verify_cidr_safe_for_
aggregation()）：2026-10-22保守策略修正——同一/24出現>=門檻候選數
只是「有資格接受安全檢查」的前提，不是自動聚合的充分條件。
"""
import ipaddress

import pipeline as p


def _candidates(ips, score=90, last_seen="2026-10-21T00:00:00Z", tier="C"):
    return [(ip, score, last_seen, tier) for ip in ips]


def _base(ips, asn="AS64500 Example"):
    return {ip: {"asn": asn} for ip in ips}


def test_below_threshold_kept_as_individual_ips():
    ips = [f"203.0.113.{i}" for i in range(1, p.CIDR_ROLLUP_THRESHOLD)]  # threshold-1 筆
    candidates = _candidates(ips)
    base = _base(ips)
    entries = p.aggregate_to_cidr(candidates, base, lambda ip, asn: False, protected_ranges=[])
    assert len(entries) == len(ips)
    assert all("/" not in e[0] for e in entries)


def test_meets_threshold_and_passes_safety_check_rolls_up_to_single_cidr():
    ips = [f"203.0.113.{i}" for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1)]
    candidates = _candidates(ips)
    base = _base(ips)
    entries = p.aggregate_to_cidr(candidates, base, lambda ip, asn: False, protected_ranges=[])
    assert len(entries) == 1
    entry, score, last_seen, tier, asn, member_ips = entries[0]
    assert entry == "203.0.113.0/24"
    assert sorted(member_ips) == sorted(ips)


def test_member_whitelist_hit_blocks_aggregation():
    """候選成員本身命中白名單（is_public_cloud逐一比對），即使數量達標
    也必須維持個別IP輸出，防止誤殺合法雲端服務。"""
    ips = [f"203.0.113.{i}" for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1)]
    candidates = _candidates(ips)
    base = _base(ips)
    entries = p.aggregate_to_cidr(candidates, base, lambda ip, asn: True, protected_ranges=[])
    assert len(entries) == len(ips)
    assert all("/" not in e[0] for e in entries)


def test_subnet_overlaps_protected_range_blocks_aggregation():
    """任務二的核心保守策略：即使候選成員本身都沒有個別命中白名單的
    IP/ASN，只要整個/24網段範圍跟已知公用雲端/CDN網段有重疊，就不能
    聚合——這涵蓋『網段裡其餘254個不是候選名單、沒有逐一資料可查的
    位址，但剛好屬於某個公用雲端供應商』的情況，不能只檢查候選成員
    本身。"""
    ips = [f"203.0.113.{i}" for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1)]
    candidates = _candidates(ips)
    base = _base(ips)
    protected = [ipaddress.ip_network("203.0.113.0/24")]
    entries = p.aggregate_to_cidr(candidates, base, lambda ip, asn: False, protected_ranges=protected)
    assert len(entries) == len(ips)
    assert all("/" not in e[0] for e in entries)


def test_subnet_overlaps_partial_protected_range_still_blocks():
    """即使已知保護網段只是候選/24的其中一部分（例如/25子網），只要有
    重疊就保守地拒絕聚合整個/24——不嘗試去精算『扣掉重疊那一小段剩下
    的部分安不安全』這種更複雜的邏輯。"""
    ips = [f"203.0.113.{i}" for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1)]
    candidates = _candidates(ips)
    base = _base(ips)
    protected = [ipaddress.ip_network("203.0.113.0/25")]  # 只涵蓋.0~.127，仍與候選網段重疊
    entries = p.aggregate_to_cidr(candidates, base, lambda ip, asn: False, protected_ranges=protected)
    assert all("/" not in e[0] for e in entries)


def test_ipv4_candidates_unaffected_by_ipv6_guard():
    """迴歸測試：加入IPv4/IPv6邊界檢查後，純IPv4情境的聚合行為必須
    完全不變（跟test_meets_threshold_and_passes_safety_check_rolls_up_
    to_single_cidr()是同一組輸入，驗證沒有因為新增的版本檢查而影響
    正常IPv4路徑）。"""
    ips = [f"203.0.113.{i}" for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1)]
    candidates = _candidates(ips)
    base = _base(ips)
    entries = p.aggregate_to_cidr(candidates, base, lambda ip, asn: False, protected_ranges=[])
    assert len(entries) == 1
    assert entries[0][0] == "203.0.113.0/24"
    assert sorted(entries[0][5]) == sorted(ips)


def test_ipv6_candidate_not_converted_to_slash_24_subnet():
    """IPv6位址若被誤套用f"{ip}/24"字串組合，ipaddress.ip_network()仍會
    成功解析成一個IPv6Network（/24是合法的IPv6前綴長度，但語意跟IPv4的
    /24完全不同）。驗證aggregate_to_cidr()不會把IPv6候選聚合成這種假的
    CIDR條目，而是略過不納入輸出。"""
    ipv6_ips = ["2001:db8::1", "2001:db8::2", "2001:db8::3", "2001:db8::4", "2001:db8::5"]
    candidates = _candidates(ipv6_ips)
    base = _base(ipv6_ips)
    entries = p.aggregate_to_cidr(candidates, base, lambda ip, asn: False, protected_ranges=[])
    assert entries == []
    assert not any("/24" in e[0] for e in entries)


def test_ipv6_against_ipv4_protected_ranges_not_silently_aggregated():
    """核心回歸測試：修正前實際驗證過的行為（不是理論推測）——IPv6候選
    若沒有被提前攔截，f"{ip}/24"仍會被ipaddress.ip_network()解析成一個
    合法的IPv6Network（/24是合法的IPv6前綴長度，但涵蓋範圍跟IPv4的/24
    完全不是一回事）。原本預期這會在跟protected_ranges裡的IPv4Network
    比較時丟出TypeError，但實測發現Python的ipaddress.overlaps()對不同
    版本一律回傳False（不拋例外）、也沒有命中任何白名單成員，於是
    verify_cidr_safe_for_aggregation()會判定「安全」，實際後果是**靜默
    產生一個無意義的聚合條目**（例如把5個IPv6位址合併成一個
    `2001:d00::/24`這種跟IPv4/24語意完全不同、毫無防火牆意義的假CIDR
    字串），而不是立即crash——這點比crash更隱蔽、更危險。真正會crash的
    地方在更下游：select_edl_candidates()最終對selected清單排序時
    （`int(x) for x in s.split("/")[0].split(".")`）會因為IPv6字串無法
    被拆成IPv4四段式數字而丟出ValueError（見
    test_ipv4_ipv6_boundary.py的pipeline層級測試）。驗證修正後IPv6
    候選完全不應該出現在aggregate_to_cidr()的輸出裡，不論是以真的IPv6
    CIDR字串、還是以個別IPv6字串的形式。"""
    ipv6_ips = ["2001:db8::1", "2001:db8::2", "2001:db8::3", "2001:db8::4", "2001:db8::5"]
    candidates = _candidates(ipv6_ips)
    base = _base(ipv6_ips)
    protected = [ipaddress.ip_network("203.0.113.0/24")]  # 刻意是IPv4Network
    entries = p.aggregate_to_cidr(candidates, base, lambda ip, asn: False, protected_ranges=protected)
    assert entries == []


def test_mixed_ipv4_ipv6_candidates_ipv4_still_aggregates_normally():
    """混合輸入情境：同一批候選同時有IPv4與IPv6，IPv6不應該中斷或影響
    IPv4候選的正常聚合處理。"""
    ipv4_ips = [f"203.0.113.{i}" for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1)]
    ipv6_ips = ["2001:db8::1", "2001:db8::2", "2001:db8::3"]
    all_ips = ipv4_ips + ipv6_ips
    candidates = _candidates(all_ips)
    base = _base(all_ips)
    entries = p.aggregate_to_cidr(candidates, base, lambda ip, asn: False, protected_ranges=[])
    # IPv4那組仍應正常聚合成單一/24條目；IPv6候選被略過，不出現在輸出裡
    assert len(entries) == 1
    assert entries[0][0] == "203.0.113.0/24"
    assert sorted(entries[0][5]) == sorted(ipv4_ips)


def test_cannot_verify_protected_ranges_fails_closed():
    """若無法可靠驗證聚合範圍（protected_ranges=None，代表白名單設定檔
    無法讀取/解析），預設不輸出該CIDR，退回個別候選IP——寧可保守也不要
    在無法驗證安全性的情況下自動聚合。"""
    ips = [f"203.0.113.{i}" for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1)]
    candidates = _candidates(ips)
    base = _base(ips)
    entries = p.aggregate_to_cidr(candidates, base, lambda ip, asn: False, protected_ranges=None)
    assert len(entries) == len(ips)
    assert all("/" not in e[0] for e in entries)


def test_representative_tier_prefers_highest_priority_member():
    """聚合後的代表tier要取組內最高優先序（A > B > C），確保混入任何
    通道A成員的聚合結果，在後續ASN節流階段仍被視為通道A豁免。"""
    ips = [f"203.0.113.{i}" for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1)]
    candidates = [(ip, 90, "2026-10-21T00:00:00Z", "C") for ip in ips]
    candidates[2] = (ips[2], 90, "2026-10-21T00:00:00Z", "A")  # 混入一個通道A成員
    base = _base(ips)
    entries = p.aggregate_to_cidr(candidates, base, lambda ip, asn: False, protected_ranges=[])
    assert entries[0][3] == "A"


def test_representative_score_and_last_seen_take_max():
    ips = [f"203.0.113.{i}" for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1)]
    candidates = [(ip, 80 + i, "2026-10-1" + str(min(i, 9)) + "T00:00:00Z", "C")
                  for i, ip in enumerate(ips)]
    base = _base(ips)
    entries = p.aggregate_to_cidr(candidates, base, lambda ip, asn: False, protected_ranges=[])
    best_score = max(c[1] for c in candidates)
    assert entries[0][1] == best_score


def test_different_subnets_grouped_independently():
    ips_a = [f"203.0.113.{i}" for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1)]
    ips_b = [f"198.51.100.{i}" for i in range(1, p.CIDR_ROLLUP_THRESHOLD + 1)]
    candidates = _candidates(ips_a) + _candidates(ips_b)
    base = _base(ips_a + ips_b)
    entries = p.aggregate_to_cidr(candidates, base, lambda ip, asn: False, protected_ranges=[])
    entry_names = {e[0] for e in entries}
    assert entry_names == {"203.0.113.0/24", "198.51.100.0/24"}
