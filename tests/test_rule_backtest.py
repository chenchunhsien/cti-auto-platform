"""
規則回測模式（rule_analysis.classify_with_thresholds / run_ruleset，
rule_backtest.py）：最重要的兩件事——(1) DEFAULT_THRESHOLDS跑出來的
結果必須跟正式的is_edl_candidate()100%等價，不能悄悄分岔；(2) 回測
絕對不能修改任何正式輸出或資料庫檔案。
"""
import copy
import json
import random
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pipeline as p
import rule_analysis as ra

ROOT = Path(__file__).resolve().parent.parent


def _iso(now, days_ago=0, hours_ago=0):
    return (now - timedelta(days=days_ago, hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_default_thresholds_mirror_real_pipeline_constants():
    assert ra.DEFAULT_THRESHOLDS["must_have_min_score"] == p.MUST_HAVE_MIN_SCORE
    assert ra.DEFAULT_THRESHOLDS["persistence_recency_window_days"] == p.PERSISTENCE_RECENCY_WINDOW_DAYS
    assert ra.DEFAULT_THRESHOLDS["persistence_window_days"] == p.PERSISTENCE_WINDOW_DAYS
    assert ra.DEFAULT_THRESHOLDS["persistence_min_seen_count"] == p.PERSISTENCE_MIN_SEEN_COUNT
    assert ra.DEFAULT_THRESHOLDS["fallback_min_score"] == p.FALLBACK_MIN_SCORE
    assert ra.DEFAULT_THRESHOLDS["recent_window_days"] == p.RECENT_WINDOW_DAYS


def test_classify_with_default_thresholds_matches_is_edl_candidate_randomized(now):
    """隨機production大量組合輸入，驗證classify_with_thresholds(用
    DEFAULT_THRESHOLDS，不覆寫任何值)在每一種情況下都跟正式的
    is_edl_candidate()回傳完全相同的結果——這是回測機制『現行規則』
    這組基準線可信的前提，一旦兩邊決策邏輯日後分岔，這個測試會立刻
    抓到。"""
    rng = random.Random(42)
    tag_pool = list(p.MUST_HAVE_TAGS) + list(p.SCANNER_NOISE_TAGS) + ["malicious-activity", "phishing", ""]
    mismatches = []
    for _ in range(500):
        labels_norm = set(rng.sample(tag_pool, k=rng.randint(0, 2)))
        labels_norm.discard("")
        score = rng.choice([0, 50, 84, 85, 87, 88, 90, 95, 98, 99, 100])
        confidence = rng.choice([0, 50, 79, 80, 89, 90, 95, 100])
        last_seen_dt = now - timedelta(hours=rng.choice([0, 1, 23, 24, 25, 48, 24 * 6, 24 * 7,
                                                           24 * 8, 24 * 13, 24 * 14, 24 * 15]))
        freq_c = rng.choice([0, 1, 2, 3, 4, 10])
        freq_b = rng.choice([0, 1, 4, 5, 6, 10])

        expected = p.is_edl_candidate(labels_norm, score, confidence, last_seen_dt, freq_c, freq_b, now)
        actual = ra.classify_with_thresholds(
            labels_norm, score, confidence, last_seen_dt, freq_c, freq_b, now, ra.DEFAULT_THRESHOLDS
        )
        if expected != actual:
            mismatches.append((labels_norm, score, confidence, last_seen_dt, freq_c, freq_b, expected, actual))

    assert not mismatches, f"發現 {len(mismatches)} 筆不一致，例如: {mismatches[:3]}"


def test_run_ruleset_with_defaults_matches_select_edl_candidates(make_record, now):
    """用一批合成情資庫，驗證 run_ruleset(..., DEFAULT_THRESHOLDS) 算出
    的EDL結果，跟正式的select_edl_candidates()完全一致（在deepcopy過
    的base上跑，避免select_edl_candidates()的就地寫回汙染run_ruleset
    的輸入）。"""
    base = {
        "1.2.3.4": make_record(labels=["c2"], threat_score=95, confidence=90,
                                last_seen=_iso(now, hours_ago=1)),
        "2.3.4.5": make_record(labels=[], threat_score=99, confidence=95,
                                last_seen=_iso(now, hours_ago=2),
                                seen_history=[_iso(now, d) for d in [0, 2, 5]]),
        "3.4.5.6": make_record(labels=[], threat_score=90, confidence=85,
                                last_seen=_iso(now, days_ago=3),
                                seen_history=[_iso(now, d) for d in [1, 3, 6, 9, 12]]),
        "4.5.6.7": make_record(labels=[], threat_score=50, confidence=50,
                                last_seen=_iso(now, hours_ago=1)),
    }

    base_for_select = copy.deepcopy(base)
    selected, _stats, _export, _retired = p.select_edl_candidates(base_for_select, now)

    base_for_backtest = copy.deepcopy(base)
    backtest_ips, backtest_stats = ra.run_ruleset(base_for_backtest, now, ra.DEFAULT_THRESHOLDS)

    assert sorted(selected) == sorted(backtest_ips)
    assert backtest_stats["edl_total"] == len(selected)


def test_run_ruleset_does_not_mutate_base(make_record, now):
    base = {
        "1.2.3.4": make_record(labels=["c2"], threat_score=95, last_seen=_iso(now, hours_ago=1)),
    }
    before = copy.deepcopy(base)
    ra.run_ruleset(base, now, ra.DEFAULT_THRESHOLDS)
    assert base == before, "run_ruleset() 不應該修改傳入的 base 字典"


def test_candidate_threshold_override_changes_result(make_record, now):
    """覆寫門檻確實要讓結果改變，否則回測機制形同虛設。"""
    base = {
        "1.2.3.4": make_record(labels=["c2"], threat_score=87, confidence=90,
                                last_seen=_iso(now, hours_ago=1)),
    }
    current_ips, _ = ra.run_ruleset(copy.deepcopy(base), now, ra.DEFAULT_THRESHOLDS)
    strict = dict(ra.DEFAULT_THRESHOLDS)
    strict["must_have_min_score"] = 90
    candidate_ips, _ = ra.run_ruleset(copy.deepcopy(base), now, strict)

    assert "1.2.3.4" in current_ips
    assert "1.2.3.4" not in candidate_ips


def test_cli_script_never_writes_to_production_files(tmp_path):
    """端到端驗證：透過子行程實際執行 rule_backtest.py CLI，確認正式
    的 data/base_iocs.json 與 data/blocklist_edl.txt 內容在執行前後
    位元組完全相同——這是回測模式『絕不能推送至正式EDL』這項安全保證
    最直接的證據，不只是信任程式碼的docstring承諾。"""
    base_iocs_path = ROOT / "data" / "base_iocs.json"
    edl_path = ROOT / "data" / "blocklist_edl.txt"

    before_base = base_iocs_path.read_bytes() if base_iocs_path.exists() else None
    before_edl = edl_path.read_bytes() if edl_path.exists() else None

    result = subprocess.run(
        [sys.executable, str(ROOT / "rule_backtest.py"),
         "--now", "2026-10-21T01:21:30+00:00",
         "--candidate", "must_have_min_score=95"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr

    after_base = base_iocs_path.read_bytes() if base_iocs_path.exists() else None
    after_edl = edl_path.read_bytes() if edl_path.exists() else None

    assert before_base == after_base, "rule_backtest.py 不應該修改 data/base_iocs.json"
    assert before_edl == after_edl, "rule_backtest.py 不應該修改 data/blocklist_edl.txt"


def test_cli_script_rejects_unknown_threshold_name():
    result = subprocess.run(
        [sys.executable, str(ROOT / "rule_backtest.py"), "--candidate", "not_a_real_threshold=1"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=30,
    )
    assert result.returncode != 0


def test_cli_script_output_report_is_valid_json(tmp_path):
    output_path = tmp_path / "report.json"
    result = subprocess.run(
        [sys.executable, str(ROOT / "rule_backtest.py"),
         "--now", "2026-10-21T01:21:30+00:00",
         "--candidate", "persistence_min_seen_count=8",
         "--output", str(output_path)],
        cwd=str(ROOT), capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert output_path.exists()
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert "current" in report and "candidate" in report
    assert report["candidate_overrides"] == {"persistence_min_seen_count": 8}
