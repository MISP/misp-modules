import sys
from types import ModuleType


def load_remove_common_subject_markers():
    pymisp = ModuleType("pymisp")
    tools = ModuleType("pymisp.tools")
    tools.EMailObject = object
    tools.URLObject = object
    tools.make_binary_objects = lambda *args, **kwargs: None
    sys.modules.setdefault("pymisp", pymisp)
    sys.modules.setdefault("pymisp.tools", tools)

    from misp_modules.modules.import_mod.email_import import remove_common_subject_markers

    return remove_common_subject_markers


def test_remove_common_subject_markers_preserves_meaningful_bracketed_prefixes():
    remove_common_subject_markers = load_remove_common_subject_markers()

    assert remove_common_subject_markers("[CASE-123] RE: malware") == "[CASE-123] RE: malware"
    assert remove_common_subject_markers("[TLP:AMBER] RE: incident") == "[TLP:AMBER] RE: incident"


def test_remove_common_subject_markers_strips_leading_reply_forward_markers():
    remove_common_subject_markers = load_remove_common_subject_markers()

    assert remove_common_subject_markers("RE: malware") == "malware"
    assert remove_common_subject_markers(" Fwd: RE: malware") == "malware"
    assert remove_common_subject_markers("AW[2]: WG: incident") == "incident"
