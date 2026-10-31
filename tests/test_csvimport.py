import base64

from misp_modules.modules.import_mod import csvimport


def _import(data, header, delimiter=""):
    request = {
        "data": base64.b64encode(data.encode()).decode(),
        "config": {"header": header, "has_header": "0", "special_delimiter": delimiter},
    }
    return csvimport.dict_handler(request)


def _attributes(result):
    return result["results"]["Attribute"]


def test_special_delimiter_keeps_commas_inside_fields():
    result = _import("1.2.3.4;seen in phishing, then C2\nevil,example.com;x\n", "ip-src,comment", ";")
    attributes = _attributes(result)
    assert [(a["value"], a["comment"]) for a in attributes] == [
        ("1.2.3.4", "seen in phishing, then C2"),
        ("evil,example.com", "x"),
    ]


def test_special_delimiter_honours_quoting():
    result = _import('"a;b.example";"note; with delimiter"\n', "domain,comment", ";")
    assert [(a["value"], a["comment"]) for a in _attributes(result)] == [("a;b.example", "note; with delimiter")]


def test_multi_character_delimiter():
    result = _import("1.2.3.4||first, second\n", "ip-src,comment", "||")
    assert [(a["value"], a["comment"]) for a in _attributes(result)] == [("1.2.3.4", "first, second")]


def test_empty_to_ids_cell():
    result = _import("ip-src,1.2.3.4,\nip-src,5.6.7.8,1\nip-src,9.9.9.9,0\n", "type,value,to_ids")
    to_ids = {a["value"]: a["to_ids"] for a in _attributes(result)}
    assert to_ids["5.6.7.8"] is True
    assert to_ids["9.9.9.9"] is False
    assert "1.2.3.4" in to_ids


def test_empty_to_ids_cell_with_type_columns():
    result = _import("1.2.3.4,\n", "ip-src,to_ids")
    assert [a["value"] for a in _attributes(result)] == ["1.2.3.4"]


def test_empty_category_cell():
    result = _import("ip-src,1.2.3.4,\nip-src,5.6.7.8,network activity\n", "type,value,category")
    categories = {a["value"]: a["category"] for a in _attributes(result)}
    assert categories["5.6.7.8"] == "Network activity"
    assert "1.2.3.4" in categories


def test_attribute_tag_column():
    result = _import('ip-src,1.2.3.4,"tlp:green, malware"\n', "type,value,attribute_tag")
    (attribute,) = _attributes(result)
    assert [tag["name"] for tag in attribute["Tag"]] == ["tlp:green", "malware"]
    assert "attribute_tag" not in attribute


def test_multi_character_delimiter_skips_blank_lines():
    result = _import("1.2.3.4||a.example\n\n5.6.7.8||b.example\n", "ip-src,domain", "||")
    assert [a["value"] for a in _attributes(result)] == ["1.2.3.4", "a.example", "5.6.7.8", "b.example"]
