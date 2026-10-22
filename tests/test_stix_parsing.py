"""
STIX 2.1 解析與規則引擎（parse_indicators() + load_local_objects()），
用 tests/sample_stix.json 當固定基準資料集：
  obj1: IP .44, conf=95, score=98 -> 通過
  obj2: IP .17, conf=90, score=90 -> 通過（剛好卡在門檻上）
  obj3: IP 203.0.113.9, conf=72 -> confidence不足，剔除
  obj4: IP 198.51.100.23, conf=99, score=61 -> score不足，剔除
  obj5: domain-only（無IPv4 pattern）-> 不計入 ipv4_indicators
  obj6: IP .44（跟obj1同一個IP）, conf=93, score=96 -> 通過，應與obj1合併
  obj7: identity 物件（非 indicator）-> 不計入 indicators
"""
from pathlib import Path

import pipeline as p

FIXTURE = Path(__file__).resolve().parent / "sample_stix.json"


def _load():
    objects, _latest = p.load_local_objects(str(FIXTURE))
    return p.parse_indicators(objects, min_confidence=90, min_threat_score=90)


def test_object_and_indicator_counts():
    _results, stats = _load()
    assert stats["total_objects"] == 7
    assert stats["indicators"] == 6
    # obj5 是 domain-only pattern，extract_ip() 應該拿不到 IP
    assert stats["ipv4_indicators"] == 5


def test_confidence_and_score_rejection_counts():
    _results, stats = _load()
    assert stats["rejected_confidence"] == 1  # obj3
    assert stats["rejected_score"] == 1       # obj4
    assert stats["passed"] == 3               # obj1, obj2, obj6


def test_duplicate_ip_merged_into_one_record():
    results, stats = _load()
    assert stats["unique_ips"] == 2
    ips = {item["ip"] for item in results}
    assert ips == {"185.220.101.44", "45.142.212.17"}


def test_merged_record_takes_max_score_and_confidence():
    results, _stats = _load()
    merged = next(r for r in results if r["ip"] == "185.220.101.44")
    # obj1: conf=95/score=98, obj6: conf=93/score=96 -> 合併後取較大值
    assert merged["threat_score"] == 98
    assert merged["confidence"] == 95


def test_merged_record_unions_labels_and_domains():
    results, _stats = _load()
    merged = next(r for r in results if r["ip"] == "185.220.101.44")
    assert {"malicious-activity", "c2", "cobalt-strike", "tor-exit-node"} <= set(merged["labels"])
    assert {"evil-c2.example.net", "beacon.example.org", "relay.example.io"} <= set(
        merged["resolving_domains"]
    )


def test_merged_record_takes_latest_last_seen():
    results, _stats = _load()
    merged = next(r for r in results if r["ip"] == "185.220.101.44")
    # obj1 collection_date 是 06:30，obj6 是 14:20，應取較晚者
    assert merged["last_seen"] == "2026-10-14T14:20:00.000Z"


def test_empty_feed_produces_zero_results():
    empty_fixture = Path(__file__).resolve().parent / "empty_stix.json"
    objects, _latest = p.load_local_objects(str(empty_fixture))
    results, stats = p.parse_indicators(objects, min_confidence=90, min_threat_score=90)
    assert results == []
    assert stats["passed"] == 0
