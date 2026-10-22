"""
標籤正規化（normalize_tags()）：轉小寫、去除前後空白，供三層標籤
決策樹比對用。
"""
import pipeline as p


def test_lowercases_and_strips_whitespace():
    result = p.normalize_tags([" C2 ", "Botnet", "  trojan"])
    assert result == {"c2", "botnet", "trojan"}


def test_deduplicates():
    result = p.normalize_tags(["c2", "C2", " c2 "])
    assert result == {"c2"}


def test_empty_or_none_input_returns_empty_set():
    assert p.normalize_tags([]) == set()
    assert p.normalize_tags(None) == set()


def test_non_string_items_are_stringified():
    result = p.normalize_tags([123, None, "scanner"])
    # None 本身是 falsy 的字串化結果 "none"，正規化後仍會被保留（只要
    # strip 後非空字串都算數）；這裡重點是確認不會因為非字串型別而炸掉
    assert "123" in result
    assert "scanner" in result


def test_blank_strings_are_dropped():
    result = p.normalize_tags(["   ", "", "c2"])
    assert result == {"c2"}
