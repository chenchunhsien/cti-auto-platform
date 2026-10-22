"""
write_text_atomic() 的直接單元測試（審查後新增，2026-10-22，第二輪）。

blocklist_edl.txt / blocklist_edl_retired.txt 原本用 Path.write_text()
直接寫入正式路徑——若process在寫入中途被中斷，會留下寫到一半的半成品
檔案，防火牆下次拉取EDL時可能讀到被截斷、不完整的清單。這裡比照既有
write_json()的atomic write模式（寫入<檔名>.tmp、同目錄replace()），但
額外在任一步驟失敗時主動清理殘留的.tmp檔（write_json()目前沒有這一步）。

重要：這裡刻意不用mock把write_text_atomic()本身的核心邏輯換掉，而是
用unittest.mock.patch.object(Path, ...)模擬底層I/O失敗，驗證函式在真實
檔案系統互動時的容錯行為。
"""
from pathlib import Path
from unittest.mock import patch

import pytest

import pipeline as p


def test_normal_write_matches_legacy_write_text_byte_for_byte(tmp_path):
    """正常寫入後內容必須完全一致——跟修正前直接用Path.write_text()的
    位元組輸出逐一比對，包含Windows上"\\n"會被轉成"\\r\\n"寫入的既有
    行為，確保這次改成atomic write沒有意外改變編碼或換行符號。"""
    content = "# Generated_At: 2026-10-22T00:00:00+08:00\n45.33.1.1\n45.33.1.2\n"
    legacy_path = tmp_path / "legacy.txt"
    atomic_path = tmp_path / "atomic.txt"

    legacy_path.write_text(content, encoding="utf-8")
    p.write_text_atomic(atomic_path, content)

    assert atomic_path.read_bytes() == legacy_path.read_bytes()
    assert atomic_path.read_text(encoding="utf-8") == content


def test_normal_write_leaves_no_tmp_file_behind(tmp_path):
    target = tmp_path / "blocklist_edl.txt"
    p.write_text_atomic(target, "45.33.1.1\n")

    assert target.exists()
    assert not target.with_suffix(target.suffix + ".tmp").exists()


def test_empty_ip_list_writes_header_only_content(tmp_path):
    """空清單情境（本輪沒有任何IP符合EDL條件，或退場清單剛好0筆）：
    輸出應該只有header、沒有任何IP列，檔案仍然要被正常寫出（不是略過
    不寫），這是既有行為，atomic化後必須維持不變。"""
    header_only = (
        "# Generated_At: 2026-10-22T00:00:00+08:00\n"
        "# Baseline_Snapshot_At: 2026-10-21T00:00:00+08:00\n"
        "# Feed_Type: Active_IOCs\n"
    )
    target = tmp_path / "blocklist_edl.txt"
    p.write_text_atomic(target, header_only)

    assert target.read_text(encoding="utf-8") == header_only


def test_tmp_write_failure_leaves_existing_official_file_untouched(tmp_path):
    """寫入.tmp階段就失敗（模擬磁碟滿/權限問題）：既有正式檔案的內容
    必須完全不受影響——因為write_text_atomic()從頭到尾沒有直接寫入過
    path本身，只有寫.tmp成功後才會透過replace()換過去。"""
    target = tmp_path / "blocklist_edl.txt"
    target.write_text("OLD_CONTENT\n", encoding="utf-8")

    def failing_write_text(self, *args, **kwargs):
        raise OSError("simulated disk full")

    with patch.object(Path, "write_text", failing_write_text):
        with pytest.raises(OSError):
            p.write_text_atomic(target, "NEW_CONTENT\n")

    assert target.read_text(encoding="utf-8") == "OLD_CONTENT\n"


def test_tmp_write_failure_does_not_leave_stray_tmp_file(tmp_path):
    target = tmp_path / "blocklist_edl.txt"
    target.write_text("OLD_CONTENT\n", encoding="utf-8")

    def failing_write_text(self, *args, **kwargs):
        raise OSError("simulated disk full")

    with patch.object(Path, "write_text", failing_write_text):
        with pytest.raises(OSError):
            p.write_text_atomic(target, "NEW_CONTENT\n")

    assert not target.with_suffix(target.suffix + ".tmp").exists()


def test_replace_failure_leaves_existing_official_file_untouched(tmp_path):
    """replace()階段才失敗（模擬目標檔案被鎖定/權限問題）：.tmp已經寫好
    新內容，但還沒換過去——既有正式檔案必須保留失敗前的舊內容，不能是
    半新半舊的中間狀態（Path.replace()本身在OS層級是atomic rename，
    失敗時不會讓目的檔案處於partial狀態，這裡驗證的是整支函式的外顯
    行為符合這個保證）。"""
    target = tmp_path / "blocklist_edl.txt"
    target.write_text("OLD_CONTENT\n", encoding="utf-8")

    def failing_replace(self, *args, **kwargs):
        raise OSError("simulated permission denied")

    with patch.object(Path, "replace", failing_replace):
        with pytest.raises(OSError):
            p.write_text_atomic(target, "NEW_CONTENT\n")

    assert target.read_text(encoding="utf-8") == "OLD_CONTENT\n"


def test_replace_failure_still_cleans_up_tmp_file(tmp_path):
    """replace()失敗後，write_text_atomic()必須主動清掉已經寫好但沒換
    成功的.tmp檔，不能留下不應存在的殘留檔案（這點比write_json()現有
    實作更嚴謹——write_json()目前沒有這一步）。"""
    target = tmp_path / "blocklist_edl.txt"
    target.write_text("OLD_CONTENT\n", encoding="utf-8")

    def failing_replace(self, *args, **kwargs):
        raise OSError("simulated permission denied")

    with patch.object(Path, "replace", failing_replace):
        with pytest.raises(OSError):
            p.write_text_atomic(target, "NEW_CONTENT\n")

    assert not target.with_suffix(target.suffix + ".tmp").exists()


def test_creates_parent_directory_if_missing(tmp_path):
    target = tmp_path / "nested" / "dir" / "blocklist_edl.txt"
    p.write_text_atomic(target, "45.33.1.1\n")

    assert target.read_text(encoding="utf-8") == "45.33.1.1\n"
