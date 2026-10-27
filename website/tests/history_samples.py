"""Illustrative investigation paths; addresses and domains are sample data."""
from copy import deepcopy


def node(number, query, attribute, modules, children=None):
    return {
        "uuid": f"00000000-0000-4000-8000-{number:012d}", "query": [query],
        "input": attribute, "modules": modules, "query_date": f"2026-10-27 10:{number % 60:02d}",
        "children": children or [], "config": {"apikey": "fixture-secret-not-for-display"},
    }


SAMPLE_PATHS = [
    node(101, "circl.lu", "domain", ["circl_passivedns"], [
        node(102, "ns2.eurodns.com", "hostname", ["circl_passivedns"], [
            node(103, "198.51.100.24", "ip-dst", ["asn_lookup"], [
                node(104, "AS64500", "AS", ["bgpranking"]),
            ]),
        ]),
        node(105, "mail.circl.lu", "hostname", ["dns"], [
            node(106, "192.0.2.14", "ip-dst", ["circl_passivessl"]),
        ]),
    ]),
    node(201, "https://example.org/login?view=details", "url", ["extract_url_components"], [
        node(202, "example.org", "domain", ["whois"], [
            node(203, "security@example.org", "email-src", ["emailrep"]),
        ]),
    ]),
    node(301, "a3f8" * 16, "sha256", ["virustotal"], [
        node(302, "download.example", "domain", ["dns"], [
            node(303, "203.0.113.77", "ip-dst", ["asn_lookup"]),
        ]),
    ]),
]


def seed_history_samples(mode):
    """Populate real session/database history for opt-in browser review."""
    import json
    from datetime import datetime
    from flask import session
    from app import db
    from app.models import History_Tree, Session_db
    from app.history.history_core import util_save_history

    if session.get("_history_samples_initialized"):
        return
    for root in SAMPLE_PATHS:
        session[root["uuid"]] = deepcopy(root)
        existing = History_Tree.query.filter_by(session_uuid=root["uuid"]).first()
        if existing:
            db.session.delete(existing)
        pending = [root]
        while pending:
            current = pending.pop()
            if not Session_db.query.filter_by(uuid=current["uuid"]).first():
                db.session.add(Session_db(
                    uuid=current["uuid"], query_enter=json.dumps(current["query"]),
                    modules_list=json.dumps(current["modules"]), input_query=current["input"],
                    nb_errors=0, query_date=datetime(2026, 10, 27, 10, 0), config_module="{}",
                    result=json.dumps({current["query"][0]: {current["modules"][0]: {"results": [{"types": [current["input"]], "values": current["query"]}]}}}),
                ))
            pending.extend(current["children"])
        if mode == "saved":
            db.session.add(History_Tree(session_uuid=root["uuid"], tree=json.dumps(util_save_history(root))))
    session["current_query"] = SAMPLE_PATHS[0]["uuid"]
    session["_history_samples_initialized"] = True
    db.session.commit()
