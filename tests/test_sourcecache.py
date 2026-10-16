import base64
import json
from unittest.mock import patch

from misp_modules.modules.expansion import sourcecache

UUID = "5b582d80-7a7e-4b6a-9f22-77656e72bb3b"
PAGE = b"<html><body>MISP feeds</body></html>"
ARMORED = base64.b64encode(PAGE)


def _run(attribute, fetch=None, config=None):
    query = json.dumps({"module": "sourcecache", "attribute": attribute, "config": config or {}})
    with patch.object(sourcecache.url_archiver, "Archive") as mock_archive:
        if fetch is None:
            mock_archive.return_value.fetch.return_value = ARMORED
        else:
            mock_archive.return_value.fetch.side_effect = fetch
        return sourcecache.handler(query), mock_archive


def _object(result):
    return next(obj for obj in result["results"]["Object"] if obj["name"] == "page-capture")


def _values(misp_object):
    return {(a["object_relation"], str(a["value"])) for a in misp_object["Attribute"]}


def test_page_capture_carries_the_url_and_the_page():
    attribute = {"type": "link", "value": "https://www.misp-project.org/feeds/", "uuid": UUID}
    result, _ = _run(attribute)
    misp_object = _object(result)
    values = _values(misp_object)
    assert ("url", "https://www.misp-project.org/feeds/") in values
    assert ("domain", "www.misp-project.org") in values
    attachment = next(a for a in misp_object["Attribute"] if a["object_relation"] == "attachment")
    assert base64.b64decode(attachment["data"]) == PAGE


def test_capture_date_is_set_by_this_module():
    attribute = {"type": "url", "value": "https://www.misp-project.org/feeds/", "uuid": UUID}
    result, _ = _run(attribute)
    relations = {relation for relation, _ in _values(_object(result))}
    assert "capture-date" in relations


def test_filename_comes_from_the_url():
    attribute = {"type": "url", "value": "https://example.com/reports/report.pdf", "uuid": UUID}
    result, _ = _run(attribute)
    assert ("attachment", "report.pdf") in _values(_object(result))


def test_object_references_the_input_attribute():
    attribute = {"type": "link", "value": "https://www.misp-project.org/feeds/", "uuid": UUID}
    result, _ = _run(attribute)
    references = _object(result)["ObjectReference"]
    assert [(r["referenced_uuid"], r["relationship_type"]) for r in references] == [(UUID, "related-to")]


def test_link_and_url_produce_the_same_object():
    names = []
    for attribute_type in ("link", "url"):
        attribute = {"type": attribute_type, "value": "https://www.misp-project.org/feeds/", "uuid": UUID}
        result, _ = _run(attribute)
        names.append(sorted(relation for relation, _ in _values(_object(result))))
    # The module used to rewrite its module-global output per input type.
    assert names[0] == names[1]
    assert sourcecache.mispattributes["input"] == ["link", "url"]


def test_archivepath_defaults_when_config_is_empty():
    attribute = {"type": "link", "value": "https://www.misp-project.org/feeds/", "uuid": UUID}
    _, mock_archive = _run(attribute, config={})
    assert mock_archive.call_args.kwargs["archive_path"] == "/tmp/"


def test_fetch_failure_returns_error():
    def fetch(**kwargs):
        raise OSError("no route to host")

    attribute = {"type": "link", "value": "https://www.misp-project.org/feeds/", "uuid": UUID}
    result, _ = _run(attribute, fetch=fetch)
    assert "error" in result


def test_wrong_attribute_type_returns_error():
    attribute = {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e", "uuid": UUID}
    result, _ = _run(attribute)
    assert "error" in result


def test_introspection_and_version():
    assert sourcecache.introspection() == sourcecache.mispattributes
    assert sourcecache.mispattributes["format"] == "misp_standard"
    assert sourcecache.version()["name"] == "URL Archiver"
