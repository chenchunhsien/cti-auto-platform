"""
ASN組織名稱純英文化（ascii_only_org_name() / resolve_asn_parts()）：
英文匯出檔案（CSV/TXT）必須零殘留CJK字元，即使底層asn_dict.json裡
混雜中文名稱也要清乾淨。
"""
import pipeline as p


def test_pure_english_name_unchanged():
    assert p.ascii_only_org_name("HURRICANE") == "HURRICANE"


def test_strips_leading_cjk_prefix():
    assert p.ascii_only_org_name("中國電信 ChinaNet") == "ChinaNet"


def test_strips_cjk_and_unwraps_stray_parens():
    assert p.ascii_only_org_name("阿里雲 (Alibaba Cloud)") == "Alibaba Cloud"


def test_pure_cjk_name_falls_back_to_empty_string():
    """查無任何英文殘留時寧可留白，不捏造內容。"""
    assert p.ascii_only_org_name("純中文名稱") == ""


def test_none_or_empty_input():
    assert p.ascii_only_org_name(None) == ""
    assert p.ascii_only_org_name("") == ""


def test_result_is_always_ascii_only():
    for name in ["中華電信 HiNet", "台灣大哥大 TWM", "Tencent Cloud (騰訊雲)", "ChinaNet"]:
        assert p.ascii_only_org_name(name).isascii()


def test_resolve_asn_parts_known_entry():
    asn_dict = {"64500": {"name": "中國電信 ChinaNet"}}
    asn, org = p.resolve_asn_parts("AS64500", asn_dict)
    assert asn == "AS64500"
    assert org == "ChinaNet"


def test_resolve_asn_parts_unknown_entry_returns_bare_as_number():
    asn, org = p.resolve_asn_parts("AS64500", {})
    assert asn == "AS64500"
    assert org == ""


def test_resolve_asn_parts_missing_asn_returns_empty_tuple():
    asn, org = p.resolve_asn_parts(None, {"64500": {"name": "Example"}})
    assert asn == ""
    assert org == ""
