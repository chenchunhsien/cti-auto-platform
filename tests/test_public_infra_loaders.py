"""
load_public_infra_matcher() 與 load_public_infra_cidr_ranges() 的直接
單元測試（審查後新增，2026-10-22）。

先前的測試（test_whitelist_exclusion.py、test_cidr_asn_interaction.py、
test_cidr_asn_observability.py）全部用 unittest.mock.patch.object() 直接
替換掉這兩支函式本身，只驗證下游消費者（select_edl_candidates()、
aggregate_to_cidr()）拿到mock回傳值時的行為——這兩支函式自己讀取真實
檔案時的fail-safe語意（缺檔/JSON格式錯誤/頂層非物件/CIDR格式錯誤/
混合合法與非法CIDR）從未被直接驗證過。

這裡用pytest的tmp_path夾具搭配patch.object(p, "PUBLIC_INFRA_RULES_FILE",
...)把模組常數指向可控的暫存檔案路徑，直接對著真實檔案I/O測試這兩支
函式，不mock它們自己。

重要：兩支函式的fail-safe語意刻意不同（docstring裡已明確說明），測試
也分別驗證兩邊各自的行為，不假設兩者應該一致：

- load_public_infra_matcher()：定位是「盡力而為的防呆保護」，缺檔/讀取
  失敗/頂層非物件一律降級為「永遠判斷False」的matcher（不中斷EDL流程）；
  單一CIDR格式錯誤則是靜默跳過該筆、其餘仍正常生效。
- load_public_infra_cidr_ranges()：定位是「能不能安全聚合」的硬性關卡，
  缺檔視為合法的空白名單（回傳[]）；但讀取失敗/頂層非物件/任何一筆CIDR
  格式錯誤，一律保守回傳None（fail-closed），即使其餘CIDR都合法。
"""
import ipaddress
import json
from unittest.mock import patch

import pipeline as p


def _patched(tmp_path, filename="public_infra_rules.json"):
    return patch.object(p, "PUBLIC_INFRA_RULES_FILE", tmp_path / filename)


# --------------------------------------------------------------------------- #
# load_public_infra_matcher()
# --------------------------------------------------------------------------- #
def test_matcher_valid_config_matches_exact_ip_asn_and_cidr(tmp_path):
    rules_file = tmp_path / "public_infra_rules.json"
    rules_file.write_text(json.dumps({
        "exact_ips": [{"ip": "1.1.1.1", "name": "Cloudflare DNS"}],
        "asns": [{"asn": "AS13335", "name": "Cloudflare"}],
        "cdn_cidrs": [{"provider": "Cloudflare", "cidrs": ["104.16.0.0/13"]}],
    }), encoding="utf-8")

    with _patched(tmp_path):
        is_public_cloud = p.load_public_infra_matcher()

    assert is_public_cloud("1.1.1.1", None) is True
    assert is_public_cloud("9.9.9.9", "AS13335 Cloudflare") is True
    assert is_public_cloud("104.16.1.1", None) is True
    assert is_public_cloud("45.33.1.1", "AS64500") is False


def test_matcher_missing_file_degrades_to_always_false(tmp_path):
    """檔案不存在：docstring明確說明這是合法的降級狀態（不受保護、照常
    參與聚合），不是錯誤。"""
    with _patched(tmp_path, filename="does_not_exist.json"):
        is_public_cloud = p.load_public_infra_matcher()

    assert is_public_cloud("1.1.1.1", None) is False
    assert is_public_cloud("45.33.1.1", "AS64500") is False


def test_matcher_malformed_json_degrades_to_always_false(tmp_path):
    rules_file = tmp_path / "public_infra_rules.json"
    rules_file.write_text("{not valid json!!!", encoding="utf-8")

    with _patched(tmp_path):
        is_public_cloud = p.load_public_infra_matcher()

    assert is_public_cloud("1.1.1.1", None) is False


def test_matcher_top_level_not_object_degrades_to_always_false(tmp_path):
    rules_file = tmp_path / "public_infra_rules.json"
    rules_file.write_text(json.dumps(["1.1.1.1", "8.8.8.8"]), encoding="utf-8")

    with _patched(tmp_path):
        is_public_cloud = p.load_public_infra_matcher()

    assert is_public_cloud("1.1.1.1", None) is False


def test_matcher_invalid_cidr_silently_skipped_others_still_work(tmp_path):
    """跟load_public_infra_cidr_ranges()不同：matcher對單筆CIDR格式錯誤
    是靜默跳過，不影響其餘合法CIDR繼續生效、也不會讓整個matcher失效。"""
    rules_file = tmp_path / "public_infra_rules.json"
    rules_file.write_text(json.dumps({
        "cdn_cidrs": [{
            "provider": "Mixed",
            "cidrs": ["not-a-cidr", "104.16.0.0/13", "999.999.999.999/24"],
        }],
    }), encoding="utf-8")

    with _patched(tmp_path):
        is_public_cloud = p.load_public_infra_matcher()

    assert is_public_cloud("104.16.1.1", None) is True  # 合法的那筆仍生效
    assert is_public_cloud("45.33.1.1", None) is False  # 不受格式錯誤影響


# --------------------------------------------------------------------------- #
# load_public_infra_cidr_ranges()
# --------------------------------------------------------------------------- #
def test_cidr_ranges_valid_config_returns_parsed_networks(tmp_path):
    rules_file = tmp_path / "public_infra_rules.json"
    rules_file.write_text(json.dumps({
        "cdn_cidrs": [
            {"provider": "Cloudflare", "cidrs": ["104.16.0.0/13"]},
            {"provider": "Fastly", "cidrs": ["151.101.0.0/16"]},
        ],
    }), encoding="utf-8")

    with _patched(tmp_path):
        ranges = p.load_public_infra_cidr_ranges()

    assert ranges == [
        ipaddress.ip_network("104.16.0.0/13"),
        ipaddress.ip_network("151.101.0.0/16"),
    ]


def test_cidr_ranges_missing_file_returns_empty_list_not_none(tmp_path):
    """檔案不存在：docstring明確說明這是「合法的空白名單狀態」，回傳[]
    （代表『目前沒有設定任何已知保護網段』），不是驗證失敗，不能跟
    「無法可靠驗證」的None混為一談。"""
    with _patched(tmp_path, filename="does_not_exist.json"):
        ranges = p.load_public_infra_cidr_ranges()

    assert ranges == []
    assert ranges is not None


def test_cidr_ranges_malformed_json_fails_closed_to_none(tmp_path):
    rules_file = tmp_path / "public_infra_rules.json"
    rules_file.write_text("{not valid json!!!", encoding="utf-8")

    with _patched(tmp_path):
        ranges = p.load_public_infra_cidr_ranges()

    assert ranges is None


def test_cidr_ranges_top_level_not_object_fails_closed_to_none(tmp_path):
    rules_file = tmp_path / "public_infra_rules.json"
    rules_file.write_text(json.dumps(["104.16.0.0/13"]), encoding="utf-8")

    with _patched(tmp_path):
        ranges = p.load_public_infra_cidr_ranges()

    assert ranges is None


def test_cidr_ranges_single_invalid_cidr_fails_closed_to_none(tmp_path):
    rules_file = tmp_path / "public_infra_rules.json"
    rules_file.write_text(json.dumps({
        "cdn_cidrs": [{"provider": "Broken", "cidrs": ["not-a-cidr"]}],
    }), encoding="utf-8")

    with _patched(tmp_path):
        ranges = p.load_public_infra_cidr_ranges()

    assert ranges is None


def test_cidr_ranges_mixed_valid_and_invalid_cidr_fails_closed_to_none(tmp_path):
    """關鍵情境（使用者明確要求覆蓋）：同一份設定檔裡混合合法與非法CIDR
    字串時，load_public_infra_cidr_ranges()必須保守地整體回傳None——
    不是『跳過壞的那筆、回傳其餘合法網段』。這跟load_public_infra_
    matcher()的「靜默跳過單筆」行為刻意不同，因為這支函式是CIDR聚合
    安全檢查的硬性關卡，混合情況下的『部分正確』結果沒有意義：呼叫端
    （verify_cidr_safe_for_aggregation）沒辦法分辨『這份清單真的只有
    這幾個網段』還是『另一個本來該擋住某個候選網段的CIDR因為格式錯誤
    而遺漏了』，保守一律拒絕聚合才是安全的。"""
    rules_file = tmp_path / "public_infra_rules.json"
    rules_file.write_text(json.dumps({
        "cdn_cidrs": [{
            "provider": "Mixed",
            "cidrs": ["104.16.0.0/13", "not-a-cidr", "151.101.0.0/16"],
        }],
    }), encoding="utf-8")

    with _patched(tmp_path):
        ranges = p.load_public_infra_cidr_ranges()

    assert ranges is None
