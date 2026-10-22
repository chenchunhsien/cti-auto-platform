"""
IOC 收斂可觀測性分析。

第一階段（2026-10-22之前）：不改變既有 A/B/C 門檻、不改變正式 EDL
輸出，純觀測。第二階段（本次）：pipeline.py 的 select_edl_candidates()
已經修正白名單命中會真的排除在EDL之外、CIDR聚合也加了安全檢查
（verify_cidr_safe_for_aggregation()），這支模組同步更新判定邏輯，
確保呈現的「誰命中誰沒命中」持續跟正式管線一致，不會卡在舊行為的
假設上。

這支模組刻意獨立於 pipeline.py 之外：所有會影響「誰被收錄進 EDL」的
決策邏輯（三通道門檻、白名單排除、CIDR聚合、ASN節流）一律直接呼叫
pipeline.py 裡「真正會被 select_edl_candidates() 使用」的那幾個純函式
（is_edl_candidate / aggregate_to_cidr / throttle_by_asn /
compute_recent_seen_count / load_public_infra_matcher /
load_public_infra_cidr_ranges），不另外重寫一份門檻常數或決策分支——
這樣可以保證分析報表呈現的結果永遠跟正式管線的實際行為同步，不會因為
日後調整門檻卻忘了同步更新這支分析模組而產生兩邊對不起來的風險。

本模組只負責「讀取 + 計算 + 產出報表」，不寫回 base_iocs.json、不呼叫
write_outputs()、不觸發 git 操作，確保純粹是觀測工具而不是另一條會
影響正式輸出的路徑。
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple

import pipeline as p

# --------------------------------------------------------------------------- #
# 排除原因分類
# --------------------------------------------------------------------------- #
# 重要：這些代碼只描述「為什麼沒有以這個身分出現在 blocklist_edl.txt
# 裡」，純粹是技術性分類，不代表「這筆IOC是安全的」。
#
# WHITELIST_OR_PUBLIC_INFRA_PROTECTED（2026-10-22起）：select_edl_
# candidates() 已修正為白名單命中時一律把tier打回None，所以這個分類
# 現在會被真的指派——判斷依據是 whitelist_match=True 且
# final_tier（套用is_edl_candidate()算出的『假設沒有白名單時』結果）
# 不是None。
EXCLUSION_NOT_IOC_WORTHY = "NOT_IOC_WORTHY"
EXCLUSION_SCANNER_NOISE = "SCANNER_NOISE_EXCLUDED"
EXCLUSION_WHITELIST_PROTECTED = "WHITELIST_OR_PUBLIC_INFRA_PROTECTED"
EXCLUSION_AGGREGATED_INTO_CIDR = "AGGREGATED_INTO_CIDR"
EXCLUSION_ASN_THROTTLED = "ASN_THROTTLED"
EXCLUSION_OTHER_FORMAT_OR_SAFETY = "OTHER_FORMAT_OR_SAFETY_CHECK"
# IPv4/IPv6邊界（審查後新增）：aggregate_to_cidr()的/24分組（用
# f"{ip}/24"字串組合）與verify_cidr_safe_for_aggregation()的
# protected_ranges比對目前只支援IPv4，IPv6候選即使通過A/B/C門檻也不能
# 進入候選名單。實測確認過：IPv6不會讓這些函式拋出例外（Python的
# ipaddress模組對不同版本的網段比較一律回傳False，不會報錯），真正的
# 風險是「靜默產生無意義的假CIDR聚合條目」，以及更下游select_edl_
# candidates()排序輸出清單時假設IPv4四段式數字格式而丟出ValueError。
# 這裡獨立給一個明確的分類，不跟「非公開路由」的
# OTHER_FORMAT_OR_SAFETY_CHECK混在一起，方便未來若要支援IPv6時能準確
# 找到受影響的IP。
EXCLUSION_UNSUPPORTED_IP_VERSION = "UNSUPPORTED_IP_VERSION"
EXCLUSION_NONE_INCLUDED = None  # 有被收錄，不算排除


def _evaluate_channel_a(labels_norm, threat_score, last_seen_dt, now) -> Dict[str, Any]:
    tag_hit = bool(labels_norm & p.MUST_HAVE_TAGS)
    matched_tags = sorted(labels_norm & p.MUST_HAVE_TAGS)
    window_ok = last_seen_dt is not None and last_seen_dt >= now - timedelta(
        hours=p.STRICT_WINDOW_HOURS
    )
    score_ok = threat_score >= p.MUST_HAVE_MIN_SCORE
    return {
        "channel": "A",
        "matched": tag_hit and window_ok and score_ok,
        "tag_hit": tag_hit,
        "matched_tags": matched_tags,
        "window_hours": p.STRICT_WINDOW_HOURS,
        "window_ok": window_ok,
        "score_threshold": p.MUST_HAVE_MIN_SCORE,
        "score_ok": score_ok,
        "miss_reasons": [
            r for r, ok in (
                ("no_must_have_tag", tag_hit),
                ("outside_24h_window", window_ok),
                ("score_below_85", score_ok),
            ) if not ok
        ],
    }


def _evaluate_channel_c(threat_score, confidence, last_seen_dt, freq_c, now) -> Dict[str, Any]:
    window_ok = last_seen_dt is not None and last_seen_dt >= now - timedelta(
        hours=p.FALLBACK_WINDOW_HOURS
    )
    freq_ok = freq_c >= p.FALLBACK_MIN_SEEN_COUNT
    score_ok = threat_score >= p.FALLBACK_MIN_SCORE
    conf_ok = confidence >= p.FALLBACK_MIN_CONFIDENCE
    return {
        "channel": "C",
        "matched": window_ok and freq_ok and score_ok and conf_ok,
        "window_hours": p.FALLBACK_WINDOW_HOURS,
        "window_ok": window_ok,
        "freq_7d": freq_c,
        "freq_threshold": p.FALLBACK_MIN_SEEN_COUNT,
        "freq_ok": freq_ok,
        "score_threshold": p.FALLBACK_MIN_SCORE,
        "score_ok": score_ok,
        "confidence_threshold": p.FALLBACK_MIN_CONFIDENCE,
        "confidence_ok": conf_ok,
        "miss_reasons": [
            r for r, ok in (
                ("outside_24h_window", window_ok),
                ("freq_7d_below_3", freq_ok),
                ("score_below_99", score_ok),
                ("confidence_below_90", conf_ok),
            ) if not ok
        ],
    }


def _evaluate_channel_b(threat_score, confidence, last_seen_dt, freq_b, now) -> Dict[str, Any]:
    window_ok = last_seen_dt is not None and last_seen_dt >= now - timedelta(
        days=p.PERSISTENCE_RECENCY_WINDOW_DAYS
    )
    freq_ok = freq_b >= p.PERSISTENCE_MIN_SEEN_COUNT
    score_ok = threat_score >= p.PERSISTENCE_MIN_SCORE
    conf_ok = confidence >= p.PERSISTENCE_MIN_CONFIDENCE
    return {
        "channel": "B",
        "matched": window_ok and freq_ok and score_ok and conf_ok,
        "recency_window_days": p.PERSISTENCE_RECENCY_WINDOW_DAYS,
        "window_ok": window_ok,
        "freq_14d": freq_b,
        "freq_window_days": p.PERSISTENCE_WINDOW_DAYS,
        "freq_threshold": p.PERSISTENCE_MIN_SEEN_COUNT,
        "freq_ok": freq_ok,
        "score_threshold": p.PERSISTENCE_MIN_SCORE,
        "score_ok": score_ok,
        "confidence_threshold": p.PERSISTENCE_MIN_CONFIDENCE,
        "confidence_ok": conf_ok,
        "miss_reasons": [
            r for r, ok in (
                ("outside_7day_recency_window", window_ok),
                ("freq_14d_below_5", freq_ok),
                ("score_below_88", score_ok),
                ("confidence_below_80", conf_ok),
            ) if not ok
        ],
    }


def evaluate_ip_decision(
    ip: str,
    record: Dict[str, Any],
    now: datetime,
    is_public_cloud: Callable[[str, Any], bool],
) -> Dict[str, Any]:
    """針對單一IP，組出完整的判定明細（不含CIDR聚合/ASN節流的群組級
    結果——那兩項要等候選名單都跑完才有意義，由
    build_decision_detail_rows() 在群組階段之後回填）。"""
    routable = p.is_valid_public_ip(ip)
    # is_valid_public_ip()保證routable=True時ip一定能被ipaddress.ip_address()
    # 解析，這裡再檢查一次版本號，判斷是否為目前CIDR聚合唯一支援的IPv4。
    is_ipv4 = routable and ipaddress.ip_address(ip).version == 4
    labels_norm = p.normalize_tags(record.get("labels"))
    threat_score = p.to_number(record.get("threat_score")) or 0
    confidence = p.to_number(record.get("confidence")) or 0
    last_seen_dt = p.parse_iso(record.get("last_seen"))
    freq_c = p.compute_recent_seen_count(record, now, window_days=p.RECENT_WINDOW_DAYS)
    freq_b = p.compute_recent_seen_count(record, now, window_days=p.PERSISTENCE_WINDOW_DAYS)

    scanner_noise_hit = bool(labels_norm & p.SCANNER_NOISE_TAGS)
    whitelist_match = is_public_cloud(ip, record.get("asn"))

    channel_a = _evaluate_channel_a(labels_norm, threat_score, last_seen_dt, now)
    # 通道A命中標籤時，軌道設計上不會往下評估B/C（見is_edl_candidate()
    # 說明），但觀測報表刻意把B/C的『假設有評估的話』結果也算出來，讓
    # 分析人員能看到「這筆IOC其實同時逼近多個通道的門檻」，不是只能看
    # 到最終拍板的那一個。
    channel_c = _evaluate_channel_c(threat_score, confidence, last_seen_dt, freq_c, now)
    channel_b = _evaluate_channel_b(threat_score, confidence, last_seen_dt, freq_b, now)

    # channel_match_tier：單純套用三通道門檻算出的結果，不考慮白名單
    # ——保留這個「假設沒有白名單時會是什麼」的稽核資訊；final_tier
    # 則是套用白名單排除之後的「實際」結果，必須跟正式
    # select_edl_candidates() 寫回 base[ip]["edl_tier"] 的值一致，才能
    # 正確驅動後續CIDR聚合/ASN節流的候選名單（見
    # build_decision_detail_rows()）。
    channel_match_tier = None
    if is_ipv4:
        channel_match_tier = p.is_edl_candidate(
            labels_norm, threat_score, confidence, last_seen_dt, freq_c, freq_b, now
        )
    final_tier = None if whitelist_match else channel_match_tier

    if not routable or last_seen_dt is None:
        exclusion_reason = EXCLUSION_OTHER_FORMAT_OR_SAFETY
    elif not is_ipv4:
        exclusion_reason = EXCLUSION_UNSUPPORTED_IP_VERSION
    elif whitelist_match and channel_match_tier is not None:
        exclusion_reason = EXCLUSION_WHITELIST_PROTECTED
    elif final_tier is not None:
        exclusion_reason = EXCLUSION_NONE_INCLUDED
    elif scanner_noise_hit and not (labels_norm & p.MUST_HAVE_TAGS):
        exclusion_reason = EXCLUSION_SCANNER_NOISE
    else:
        exclusion_reason = EXCLUSION_NOT_IOC_WORTHY

    return {
        "ip": ip,
        "routable": routable,
        "is_ipv4": is_ipv4,
        "threat_score": threat_score,
        "confidence": confidence,
        "labels": sorted(labels_norm),
        "last_seen": record.get("last_seen"),
        "freq_7d": freq_c,
        "freq_14d": freq_b,
        # 情報來源數：STIX資料本身沒有獨立的「情報來源/feed」欄位，目前
        # 資料模型無法取得，誠實回報None而不是捏造一個數字。
        "intel_source_count": None,
        "final_tier": final_tier,
        "channel_match_tier": channel_match_tier,
        "channel_a": channel_a,
        "channel_b": channel_b,
        "channel_c": channel_c,
        "scanner_noise_hit": scanner_noise_hit,
        # whitelist_match=True 且 channel_match_tier 不是 None 時，
        # exclusion_reason 會是 WHITELIST_OR_PUBLIC_INFRA_PROTECTED，
        # final_tier 也會被強制壓成 None——這筆IP不會出現在正式EDL裡，
        # 這是2026-10-22修正過的現行行為（修正前的舊版本這裡永遠是
        # None，即白名單命中不影響輸出，是當時刻意記錄下來的真實風險
        # 缺口，現已修正）。
        "whitelist_match": whitelist_match,
        "exclusion_reason": exclusion_reason,
        # 以下兩個欄位先給預設值，由 build_decision_detail_rows() 在
        # 跑完CIDR聚合/ASN節流之後回填正確結果。
        "cidr_aggregated": False,
        "asn_throttled": False,
    }


def build_decision_detail_rows(
    base: Dict[str, Dict[str, Any]], now: datetime
) -> List[Dict[str, Any]]:
    """
    針對情資庫裡的每一筆IOC，產出完整的判定明細列。純讀取，不修改
    base 裡的任何欄位（跟 select_edl_candidates() 不同，那支函式會把
    edl_tier 等欄位寫回 base；這支刻意不碰，確保純觀測不影響正式狀態）。
    """
    is_public_cloud = p.load_public_infra_matcher()
    protected_ranges = p.load_public_infra_cidr_ranges()

    rows: Dict[str, Dict[str, Any]] = {}
    candidates: List[Tuple[str, float, str, str]] = []

    for ip, record in base.items():
        row = evaluate_ip_decision(ip, record, now, is_public_cloud)
        rows[ip] = row
        if row["final_tier"] is not None:
            candidates.append((ip, row["threat_score"], record.get("last_seen") or "", row["final_tier"]))

    # 重跑一次「正式管線真正會用到」的CIDR聚合+ASN節流，取得群組級結果
    # ——直接呼叫pipeline.py的真實函式，不重寫邏輯。candidates已經排除
    # 過白名單命中的IP（見上方final_tier的計算方式），不會有白名單IP
    # 混進CIDR聚合的候選名單。
    aggregated = p.aggregate_to_cidr(candidates, base, is_public_cloud, protected_ranges)
    throttled = p.throttle_by_asn(aggregated)

    kept_ips = set()
    for entry in throttled:
        kept_ips.update(entry[5])
    all_candidate_ips = set()
    for entry in aggregated:
        all_candidate_ips.update(entry[5])
    throttled_out_ips = all_candidate_ips - kept_ips

    # 哪些IP的所屬entry是一個聚合後的CIDR（member數>1）
    cidr_member_ips = set()
    for entry in aggregated:
        if "/" in entry[0] and len(entry[5]) > 1:
            cidr_member_ips.update(entry[5])

    for ip in throttled_out_ips:
        rows[ip]["asn_throttled"] = True
        rows[ip]["exclusion_reason"] = EXCLUSION_ASN_THROTTLED
    for ip in cidr_member_ips - throttled_out_ips:
        rows[ip]["cidr_aggregated"] = True
        rows[ip]["exclusion_reason"] = EXCLUSION_AGGREGATED_INTO_CIDR

    return list(rows.values())


# --------------------------------------------------------------------------- #
# CIDR 聚合評估報表
# --------------------------------------------------------------------------- #
def build_cidr_aggregation_report(
    base: Dict[str, Dict[str, Any]],
    now: datetime,
    is_public_cloud: Optional[Callable[[str, Any], bool]] = None,
    protected_ranges: Optional[List[ipaddress.IPv4Network]] = None,
) -> List[Dict[str, Any]]:
    """
    針對「所有通過三通道判定、且未命中白名單的候選IP」依/24網段分組
    （跟aggregate_to_cidr()內部分組邏輯一致），逐一網段產出聚合前後的
    評估數據——不論這個網段最終實際上有沒有通過安全檢查都列出來，讓
    分析人員能看到『差一點點就會被聚合』的網段，不是只看最終聚合結果。

    would_aggregate 直接呼叫正式的 verify_cidr_safe_for_aggregation()
    （保守策略：候選數達標只是前提，還要通過白名單/網段重疊安全檢查），
    不是另外寫一份簡化版判斷，確保報表跟實際聚合結果一致。

    is_public_cloud / protected_ranges 皆可注入（供測試替換），預設讀
    正式的公用設施白名單設定檔。
    """
    if is_public_cloud is None:
        is_public_cloud = p.load_public_infra_matcher()
    if protected_ranges is None:
        protected_ranges = p.load_public_infra_cidr_ranges()

    candidates: List[Tuple[str, Dict[str, Any]]] = []
    for ip, record in base.items():
        row = evaluate_ip_decision(ip, record, now, is_public_cloud)
        if row["final_tier"] is not None:
            candidates.append((ip, row))

    groups: Dict[Any, List[Tuple[str, Dict[str, Any]]]] = defaultdict(list)
    for ip, row in candidates:
        subnet = ipaddress.ip_network(f"{ip}/24", strict=False)
        groups[subnet].append((ip, row))

    report = []
    for subnet, members in groups.items():
        member_ips = [ip for ip, _row in members]
        scores = [row["threat_score"] for _ip, row in members]
        confidences = [row["confidence"] for _ip, row in members]
        channels = sorted({row["final_tier"] for _ip, row in members})
        candidate_count = len(member_ips)

        if candidate_count >= p.CIDR_ROLLUP_THRESHOLD:
            would_aggregate, safety_check_reason = p.verify_cidr_safe_for_aggregation(
                subnet, member_ips, base, is_public_cloud, protected_ranges
            )
        else:
            would_aggregate = False
            safety_check_reason = f"候選數{candidate_count}未達聚合門檻{p.CIDR_ROLLUP_THRESHOLD}"
        whitelist_protected = any(is_public_cloud(ip, base.get(ip, {}).get("asn")) for ip in member_ips)
        edl_entries_before = candidate_count
        edl_entries_after = 1 if would_aggregate else candidate_count

        report.append({
            "cidr": str(subnet),
            "candidate_count": candidate_count,
            "candidate_ratio_of_subnet": round(candidate_count / subnet.num_addresses, 4),
            "member_ips": sorted(member_ips, key=lambda s: tuple(int(x) for x in s.split("."))),
            "score_min": min(scores), "score_max": max(scores),
            "score_avg": round(sum(scores) / len(scores), 2),
            "confidence_min": min(confidences), "confidence_max": max(confidences),
            "confidence_avg": round(sum(confidences) / len(confidences), 2),
            "channels_present": channels,
            # 同上，資料模型無獨立情報來源欄位，誠實回報None。
            "distinct_intel_source_count": None,
            "whitelist_protected": whitelist_protected,
            "would_aggregate": would_aggregate,
            "safety_check_reason": safety_check_reason,
            "edl_entries_before": edl_entries_before,
            "edl_entries_after": edl_entries_after,
            "entries_saved": edl_entries_before - edl_entries_after,
            # 聚合後若真的輸出成/24 CIDR，防火牆實際上會連同這個網段裡
            # 所有256個位址一起阻斷，不只是候選名單裡這幾筆——這裡算出
            # 「候選名單以外、但會被這個CIDR一併涵蓋」的位址數，供誤封
            # 風險評估使用。
            "collateral_ips_if_aggregated": subnet.num_addresses - candidate_count if would_aggregate else 0,
        })

    report.sort(key=lambda r: r["candidate_count"], reverse=True)
    return report


# --------------------------------------------------------------------------- #
# 規則回測：門檻可參數化的分類器
# --------------------------------------------------------------------------- #
# 刻意把「現行規則」的門檻值抽成這份預設字典、直接讀pipeline.py的真實
# 常數（不是另外寫死一份數字），確保「現行規則」這個基準組永遠跟正式
# 管線同步；候選規則只需要覆寫其中想測試的少數幾個鍵。
DEFAULT_THRESHOLDS: Dict[str, Any] = {
    "strict_window_hours": p.STRICT_WINDOW_HOURS,
    "must_have_min_score": p.MUST_HAVE_MIN_SCORE,
    "recent_window_days": p.RECENT_WINDOW_DAYS,
    "fallback_window_hours": p.FALLBACK_WINDOW_HOURS,
    "fallback_min_seen_count": p.FALLBACK_MIN_SEEN_COUNT,
    "fallback_min_score": p.FALLBACK_MIN_SCORE,
    "fallback_min_confidence": p.FALLBACK_MIN_CONFIDENCE,
    "persistence_recency_window_days": p.PERSISTENCE_RECENCY_WINDOW_DAYS,
    "persistence_window_days": p.PERSISTENCE_WINDOW_DAYS,
    "persistence_min_seen_count": p.PERSISTENCE_MIN_SEEN_COUNT,
    "persistence_min_score": p.PERSISTENCE_MIN_SCORE,
    "persistence_min_confidence": p.PERSISTENCE_MIN_CONFIDENCE,
}


def classify_with_thresholds(
    labels_norm, threat_score, confidence, last_seen_dt, freq_c, freq_b, now,
    thresholds: Dict[str, Any],
) -> Optional[str]:
    """跟 pipeline.is_edl_candidate() 結構完全一致的三通道決策樹，差別
    只在於門檻數值改吃參數而非模組常數，供規則回測比較「現行規則」跟
    「候選規則」用。呼叫端傳入 DEFAULT_THRESHOLDS（不覆寫）時，結果
    必須跟 pipeline.is_edl_candidate() 100%一致——tests/test_rule_
    backtest.py 有專門測試鎖住這個等價性，避免兩邊決策邏輯日後各自
    修改而悄悄分岔。"""
    t = thresholds
    if last_seen_dt is None:
        return None
    if labels_norm & p.MUST_HAVE_TAGS:
        is_recent_a = last_seen_dt >= now - timedelta(hours=t["strict_window_hours"])
        return "A" if is_recent_a and threat_score >= t["must_have_min_score"] else None
    if labels_norm & p.SCANNER_NOISE_TAGS:
        return None
    is_recent_fallback = last_seen_dt >= now - timedelta(hours=t["fallback_window_hours"])
    if (
        is_recent_fallback
        and freq_c >= t["fallback_min_seen_count"]
        and threat_score >= t["fallback_min_score"]
        and confidence >= t["fallback_min_confidence"]
    ):
        return "C"
    is_recent_persistence = last_seen_dt >= now - timedelta(days=t["persistence_recency_window_days"])
    if (
        is_recent_persistence
        and freq_b >= t["persistence_min_seen_count"]
        and threat_score >= t["persistence_min_score"]
        and confidence >= t["persistence_min_confidence"]
    ):
        return "B"
    return None


def run_ruleset(
    base: Dict[str, Dict[str, Any]], now: datetime, thresholds: Dict[str, Any]
) -> Tuple[List[str], Dict[str, Any]]:
    """用指定的門檻組，對整個base跑一次完整的四階漏斗（判定 -> 白名單
    排除 -> CIDR聚合安全檢查 -> ASN節流），純計算、不修改base、不寫
    任何檔案。回傳(最終EDL條目列表, 統計字典)，供規則回測比較用。

    白名單排除與CIDR聚合安全檢查是現行管線的強制行為（2026-10-22
    修正），不是可調整的「門檻」，所以不管current或candidate規則組都
    一律套用，確保回測比較的是純粹的A/B/C數值門檻差異，不會因為白名單
    behavior不同調而混淆了比較基準。"""
    stats = {
        "condition_a": 0, "condition_b": 0, "condition_c": 0,
        "excluded_non_routable": 0, "excluded_scanner_noise": 0,
        "excluded_other": 0, "whitelist_excluded": 0,
        # 同pipeline.py的select_edl_candidates()：/24 CIDR聚合只支援
        # IPv4，IPv6候選在這裡獨立排除、獨立計數，不跟excluded_non_routable
        # 混在一起（審查後新增）。
        "excluded_non_ipv4": 0,
    }
    is_public_cloud = p.load_public_infra_matcher()
    protected_ranges = p.load_public_infra_cidr_ranges()
    candidates: List[Tuple[str, float, str, str]] = []

    for ip, record in base.items():
        if not p.is_valid_public_ip(ip):
            stats["excluded_non_routable"] += 1
            continue
        if ipaddress.ip_address(ip).version != 4:
            stats["excluded_non_ipv4"] += 1
            continue
        labels_norm = p.normalize_tags(record.get("labels"))
        threat_score = p.to_number(record.get("threat_score")) or 0
        confidence = p.to_number(record.get("confidence")) or 0
        last_seen_dt = p.parse_iso(record.get("last_seen"))
        freq_c = p.compute_recent_seen_count(record, now, window_days=thresholds["recent_window_days"])
        freq_b = p.compute_recent_seen_count(record, now, window_days=thresholds["persistence_window_days"])

        tier = classify_with_thresholds(
            labels_norm, threat_score, confidence, last_seen_dt, freq_c, freq_b, now, thresholds
        )
        if tier in ("A", "B", "C") and is_public_cloud(ip, record.get("asn")):
            stats["whitelist_excluded"] += 1
            continue
        if tier in ("A", "B", "C"):
            stats[{"A": "condition_a", "B": "condition_b", "C": "condition_c"}[tier]] += 1
            candidates.append((ip, threat_score, record.get("last_seen") or "", tier))
        elif labels_norm & p.SCANNER_NOISE_TAGS and not (labels_norm & p.MUST_HAVE_TAGS):
            stats["excluded_scanner_noise"] += 1
        else:
            stats["excluded_other"] += 1

    aggregated = p.aggregate_to_cidr(candidates, base, is_public_cloud, protected_ranges)
    throttled = p.throttle_by_asn(aggregated)

    all_member_ips: set = set()
    for item in aggregated:
        all_member_ips.update(item[5])
    kept_member_ips: set = set()
    for item in throttled:
        kept_member_ips.update(item[5])

    cidr_rollup_subnets = [e for e in aggregated if "/" in e[0]]
    collateral_ips = 0
    for entry in cidr_rollup_subnets:
        subnet = ipaddress.ip_network(entry[0], strict=False)
        collateral_ips += subnet.num_addresses - len(entry[5])

    final_entries = list(dict.fromkeys(item[0] for item in throttled))
    final_entries.sort(key=lambda s: tuple(int(x) for x in s.split("/")[0].split(".")))

    stats["asn_throttle_excluded"] = len(all_member_ips) - len(kept_member_ips)
    stats["cidr_rollup_subnets"] = len(cidr_rollup_subnets)
    stats["cidr_rollup_ips_absorbed"] = len(candidates) - (len(aggregated) - len(cidr_rollup_subnets))
    stats["collateral_ips_if_aggregated_total"] = collateral_ips
    stats["edl_total"] = len(final_entries)

    return final_entries, stats
