"""
規則回測模式：拿同一份歷史情資庫，分別套用「現行規則」與「候選規則」
算一次完整的EDL結果，比較兩者差異。

安全保證（務必維持）：
  - 只呼叫 pipeline.load_base_iocs() / read_json() 等純讀取函式。
  - 絕不呼叫 write_outputs()、git_push()，不觸碰 sync.lock /
    sync_state.json，也不修改讀進來的 base 字典。
  - 絕不會推送、寫回或覆蓋任何正式 EDL 檔案——所有輸出只會印到終端機
    或寫進使用者用 --output 指定的另一個報表檔案。

用法範例：
  # 單純確認回測機制本身不動到任何東西，不覆寫任何門檻（應該跟現行
  # 規則結果完全一致）：
  python rule_backtest.py

  # 測試把通道A分數門檻從85調高到90會有什麼影響：
  python rule_backtest.py --candidate must_have_min_score=90

  # 同時測試多個門檻、並把完整比較結果存成報表檔：
  python rule_backtest.py \
      --candidate persistence_min_seen_count=6 \
      --candidate fallback_min_score=97 \
      --output data/rule_backtest_report.json
"""
import argparse
import json
from datetime import datetime, timezone

import pipeline as p
import rule_analysis as ra


def parse_candidate_overrides(pairs):
    overrides = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise SystemExit(f"--candidate 參數格式錯誤，須為 key=value：{pair!r}")
        key, raw_value = pair.split("=", 1)
        key = key.strip()
        if key not in ra.DEFAULT_THRESHOLDS:
            valid = ", ".join(sorted(ra.DEFAULT_THRESHOLDS))
            raise SystemExit(f"未知的門檻名稱 {key!r}，合法選項：{valid}")
        try:
            value = float(raw_value)
            if value.is_integer():
                value = int(value)
        except ValueError:
            raise SystemExit(f"--candidate {pair!r} 的值必須是數字")
        overrides[key] = value
    return overrides


def summarize(label, edl_ips, stats):
    lines = [
        f"=== {label} ===",
        f"EDL總條目數: {stats['edl_total']}",
        f"  通道A命中: {stats['condition_a']}",
        f"  通道B命中: {stats['condition_b']}",
        f"  通道C命中: {stats['condition_c']}",
        f"排除-非公開路由: {stats['excluded_non_routable']}",
        f"排除-掃描雜訊: {stats['excluded_scanner_noise']}",
        f"排除-未達門檻: {stats['excluded_other']}",
        f"排除-白名單/公用設施命中(2026-10-22起強制排除，非可調門檻): {stats['whitelist_excluded']}",
        f"ASN節流排除(含CIDR條目成員): {stats['asn_throttle_excluded']}",
        f"/24聚合網段數: {stats['cidr_rollup_subnets']}（吸收 {stats['cidr_rollup_ips_absorbed']} 筆個別IP，"
        f"重複情報/同網段聚合的計數影響即此處）",
        f"CIDR聚合涵蓋的非候選位址數(誤封風險，若真的聚合成/24一併阻斷): {stats['collateral_ips_if_aggregated_total']}",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", default=None, help="情資庫JSON路徑，預設讀 data/base_iocs.json")
    parser.add_argument(
        "--now", default=None,
        help="固定的『現在』時間戳(ISO8601)，不指定則用執行當下的UTC時間；"
             "建議回測時固定指定，確保結果可重現、不受執行時間影響",
    )
    parser.add_argument(
        "--candidate", action="append", default=[],
        help="候選規則門檻覆寫，格式 key=value，可重複指定多個；"
             "合法key見 rule_analysis.DEFAULT_THRESHOLDS",
    )
    parser.add_argument("--output", default=None, help="把完整比較結果(JSON)另外寫到這個檔案路徑")
    args = parser.parse_args()

    if args.base:
        base = p.read_json(args.base, {})
        if isinstance(base, dict) and isinstance(base.get("iocs"), dict):
            base = base["iocs"]
    else:
        base = p.load_base_iocs()

    now = datetime.fromisoformat(args.now.replace("Z", "+00:00")) if args.now else datetime.now(timezone.utc)

    candidate_overrides = parse_candidate_overrides(args.candidate)
    current_thresholds = dict(ra.DEFAULT_THRESHOLDS)
    candidate_thresholds = dict(ra.DEFAULT_THRESHOLDS)
    candidate_thresholds.update(candidate_overrides)

    current_ips, current_stats = ra.run_ruleset(base, now, current_thresholds)
    candidate_ips, candidate_stats = ra.run_ruleset(base, now, candidate_thresholds)

    print(summarize("現行規則 (current)", current_ips, current_stats))
    print()
    print(summarize("候選規則 (candidate)", candidate_ips, candidate_stats))
    print()
    print("=== 差異摘要 ===")
    print(f"EDL條目數變化: {current_stats['edl_total']} -> {candidate_stats['edl_total']} "
          f"({candidate_stats['edl_total'] - current_stats['edl_total']:+d})")
    for ch, key in (("A", "condition_a"), ("B", "condition_b"), ("C", "condition_c")):
        diff = candidate_stats[key] - current_stats[key]
        print(f"通道{ch}命中數變化: {current_stats[key]} -> {candidate_stats[key]} ({diff:+d})")
    print(f"白名單排除數變化: {current_stats['whitelist_excluded']} -> "
          f"{candidate_stats['whitelist_excluded']} "
          f"({candidate_stats['whitelist_excluded'] - current_stats['whitelist_excluded']:+d})")
    print(f"ASN節流排除數變化: {current_stats['asn_throttle_excluded']} -> "
          f"{candidate_stats['asn_throttle_excluded']} "
          f"({candidate_stats['asn_throttle_excluded'] - current_stats['asn_throttle_excluded']:+d})")
    print(f"CIDR聚合吸收IP數變化: {current_stats['cidr_rollup_ips_absorbed']} -> "
          f"{candidate_stats['cidr_rollup_ips_absorbed']} "
          f"({candidate_stats['cidr_rollup_ips_absorbed'] - current_stats['cidr_rollup_ips_absorbed']:+d})")
    print(f"CIDR聚合涵蓋非候選位址數變化: {current_stats['collateral_ips_if_aggregated_total']} -> "
          f"{candidate_stats['collateral_ips_if_aggregated_total']} "
          f"({candidate_stats['collateral_ips_if_aggregated_total'] - current_stats['collateral_ips_if_aggregated_total']:+d})")

    newly_added = sorted(set(candidate_ips) - set(current_ips))
    newly_removed = sorted(set(current_ips) - set(candidate_ips))
    print(f"候選規則新增的條目數: {len(newly_added)}（範例: {newly_added[:5]}）")
    print(f"候選規則移除的條目數: {len(newly_removed)}（範例: {newly_removed[:5]}）")

    print()
    print("=== 已知惡意IOC保留率 ===")
    print("此系統目前沒有可靠的外部『已知惡意』標記資料集（STIX來源本身"
          "不含人工驗證過的真實標籤），無法可靠統計保留率，略過此項，"
          "避免用不可靠資料捏造一個看似精確但沒有根據的數字。")

    if args.output:
        report = {
            "generated_at": p.now_utc_iso(),
            "now_used_for_backtest": now.isoformat(),
            "candidate_overrides": candidate_overrides,
            "current": {"edl_total": current_stats["edl_total"], "stats": current_stats},
            "candidate": {"edl_total": candidate_stats["edl_total"], "stats": candidate_stats},
            "newly_added_entries": newly_added,
            "newly_removed_entries": newly_removed,
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"\n完整比較結果已寫入: {args.output}")

    print("\n[回測模式僅做比較與輸出報表，未修改任何正式EDL輸出或資料庫檔案，也未執行git操作]")


if __name__ == "__main__":
    main()
