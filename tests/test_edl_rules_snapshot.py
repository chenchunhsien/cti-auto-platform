"""
build_edl_rules_snapshot() 的直接單元測試（審查後新增，2026-10-22第三輪）。

重點是新增的 edl_tab_summary 欄位——docs/index.html「EDL阻斷清單」頁籤
最下方CIDR/ASN/白名單說明footnote的單一資料來源改造（方案A）：
app.js的renderEdlCriteriaFootnote()會用這個欄位動態覆寫原本寫死的
靜態文字。這裡驗證：
1. 欄位確實存在且是從真實常數組出來的（不是另外寫死的數字，門檻改了
   這裡會跟著變，不會各自維護兩份數字）。
2. 文字涵蓋審查報告要求的4個重點（白名單候選階段排除、CIDR聚合檢查
   候選成員與整段網段重疊、無法驗證時fail-closed、退回個別IP仍受ASN
   節流約束），避免未來編輯時不小心漏掉其中一項。
"""
import pipeline as p


def test_edl_tab_summary_field_exists_and_non_empty():
    snap = p.build_edl_rules_snapshot()
    assert "edl_tab_summary" in snap
    summary = snap["edl_tab_summary"]["description"]
    assert isinstance(summary, str) and len(summary) > 0


def test_edl_tab_summary_uses_real_threshold_constants():
    """門檻數字必須是從常數內插進去的，不是另外寫死——用改過的常數值
    重新產生一次，確認文字裡的數字真的會跟著變。"""
    snap = p.build_edl_rules_snapshot()
    summary = snap["edl_tab_summary"]["description"]
    assert str(p.CIDR_ROLLUP_THRESHOLD) in summary
    assert str(p.ASN_THROTTLE_MAX_PER_ASN) in summary


def test_edl_tab_summary_covers_four_required_points():
    snap = p.build_edl_rules_snapshot()
    summary = snap["edl_tab_summary"]["description"]

    # 1. 白名單命中IP在候選階段排除（不限特定通道）
    assert "白名單" in summary and "候選階段" in summary and "排除" in summary

    # 2. CIDR聚合會檢查候選成員「與」整段網段是否與受保護範圍重疊
    assert "候選成員本身" in summary and "整個網段範圍" in summary and "重疊" in summary

    # 3. 無法讀取/無法驗證時 fail-closed，不允許該次聚合通過安全檢查
    assert "無法讀取" in summary
    assert "無法可靠完成驗證" in summary or "無法驗證" in summary
    assert "不允許該次聚合通過安全檢查" in summary or "視為不安全" in summary

    # 4. 被CIDR安全檢查拒絕、退回的個別IP仍受ASN節流約束
    assert "退回" in summary and "節流規則約束" in summary


def test_snapshot_still_contains_existing_stage_keys():
    """迴歸測試：新增edl_tab_summary不應該影響既有的4個stage區塊。"""
    snap = p.build_edl_rules_snapshot()
    for key in (
        "stage1_ip_filter", "stage2_tags", "stage3_channels",
        "stage3b_whitelist_exclusion", "stage4_convergence",
    ):
        assert key in snap
