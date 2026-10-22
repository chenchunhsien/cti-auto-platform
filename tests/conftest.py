"""
共用測試夾具：讓 tests/ 底下的測試檔案都能 import 到 pipeline.py，
並提供固定的 now 時間戳跟最小可用的情資紀錄工廠函式，避免每個測試
檔案各自手刻一份、彼此格式漂移。
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

import pipeline as p  # noqa: E402 - 需先插入 sys.path 才能 import


@pytest.fixture
def now():
    """固定的「現在」時間戳，所有測試都用同一個基準，不依賴真實時鐘，
    避免測試結果隨著跑測試的當下日期漂移。"""
    return datetime(2026, 10, 21, 1, 21, 30, tzinfo=timezone.utc)


@pytest.fixture
def make_record():
    """回傳一個工廠函式，建立一筆最小可用的 base_iocs 紀錄，個別測試
    只需要覆寫跟該案例相關的欄位。history_tracking_since 預設抓得比
    TRANSITION_PERIOD_DAYS（7天）更早，確保預設路徑是走純滾動視窗
    計算、不觸發過渡期保底機制，個別測試要測過渡期才主動覆寫。"""
    def _make(**overrides):
        record = {
            "labels": [],
            "threat_score": 90,
            "confidence": 90,
            "last_seen": "2026-10-21T00:00:00Z",
            "first_seen": "2026-10-14T00:00:00Z",
            "seen_count": 1,
            "seen_history": ["2026-10-21T00:00:00Z"],
            "history_tracking_since": "2026-09-01T00:00:00Z",
            "asn": "AS64500 Example Net",
            "resolving_domains": [],
        }
        record.update(overrides)
        return record
    return _make
