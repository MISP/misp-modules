import json
from unittest.mock import patch

import requests

from misp_modules.modules.expansion import tweetfeed

# Fixtures below are the verbatim JSON bodies captured from
# https://api.tweetfeed.live/v1/ioc?value=<v> on 2026-09-06.

IOC_DOMAIN = json.loads(
    r"""{"found":true,"query":"raku-point-gche.com","window":"365d","records":[{"count":1,"first_seen":"2026-09-05 23:09:02","last_seen":"2026-09-05 23:09:02","related":[["domain","raku-point-ankanz.com"],["domain","raku-point-edia.com"],["sha256","4d7e9e75f44a68fd6c109bbfa6d6b8fd343b274e7ac1afb0a0a628f624a83308"]],"tags":["#malware","#phishing"],"tweets":["https://x.com/masaomi346/status/2096375079101940086"],"type":"domain","users":["masaomi346"],"value":"raku-point-gche.com"},{"count":1,"first_seen":"2026-09-05 23:09:02","last_seen":"2026-09-05 23:09:02","related":[["domain","raku-point-ankanz.com"],["domain","raku-point-edia.com"],["sha256","4d7e9e75f44a68fd6c109bbfa6d6b8fd343b274e7ac1afb0a0a628f624a83308"]],"tags":["#malware","#phishing"],"tweets":["https://x.com/masaomi346/status/2096375079101940086"],"type":"url","users":["masaomi346"],"value":"https://raku-point-gche.com"}],"ai":{"summary":"Android malware impersonating Rakuten distributed via three phishing domains including raku-point-ankanz.com.","family":null,"threat_type":"malware","suggested_tags":["android","phishing","malware"],"confidence":0.85,"tweet_id":"2096375079101940086","enriched_at":"2026-09-06T00:40:04Z"},"reg":{"apex":"raku-point-gche.com","asn":"AS396982","checked_at":"2026-09-05T23:15:29Z","created":"2026-09-05T20:05:42Z","ips":["34.97.12.225"],"ns":["LOU.NS.CLOUDFLARE.COM","LUCY.NS.CLOUDFLARE.COM"],"org":"Google LLC","registrar":"Aceville Pte. Ltd.","status":"ok","age_days_at_report":0,"newly_registered":true},"campaigns":[{"id":"tfc-09c2d5ccfa23","name":"Android malware impersonating Rakuten on raku-point-* domains","confidence":"low","threat_types":["malware"],"ioc_count":6,"last_seen":"2026-09-05"}]}"""  # noqa: E501
)

IOC_URL = json.loads(
    r"""{"found":true,"query":"site-oficial-havan.online","window":"365d","records":[{"count":1,"first_seen":"2026-08-31 00:53:10","last_seen":"2026-08-31 00:53:10","tags":["#phishing","#scam"],"tweets":["https://x.com/Coolcarlos17/status/2094226959345610845"],"type":"domain","users":["Coolcarlos17"],"value":"site-oficial-havan.online"},{"count":1,"first_seen":"2026-08-31 00:53:10","last_seen":"2026-08-31 00:53:10","tags":["#phishing","#scam"],"tweets":["https://x.com/Coolcarlos17/status/2094226959345610845"],"type":"url","users":["Coolcarlos17"],"value":"https://site-oficial-havan.online"}],"ai":{"summary":"Fake clone website impersonating Brazilian retailer Havan (site-oficial-havan.online) used for phishing/scam.","family":null,"threat_type":"phishing","suggested_tags":["phishing","scam"],"confidence":0.88,"tweet_id":"2094226959345610845","enriched_at":"2026-08-31T06:40:05Z"},"reg":{"apex":"site-oficial-havan.online","asn":"AS35278","checked_at":"2026-08-31T01:15:26Z","created":"2026-08-30T22:57:17.584Z","ips":["141.8.192.178"],"ns":["ns1.sprinthost.ru","ns2.sprinthost.ru","ns3.sprinthost.net","ns4.sprinthost.net"],"org":"SPRINTHOST.RU LLC","registrar":"Dynadot Inc","status":"ok","age_days_at_report":1,"newly_registered":true}}"""  # noqa: E501
)

IOC_IP = json.loads(
    r"""{"found":true,"query":"43.165.128.22","window":"365d","records":[{"count":3,"first_seen":"2026-08-10 12:48:25","last_seen":"2026-08-31 06:37:28","related":[["url","https://rnwm.pvvchxh.cn/ap/"],["domain","apple.wgxdijj.cn"],["domain","rnwm.fuofxwh.cn"],["url","https://rnwm.fuofxwh.cn/ap/"]],"tags":["#phishing"],"tweets":["https://x.com/Metemcyber/status/2086796811432558627","https://x.com/Metemcyber/status/2089321601628328237","https://x.com/Metemcyber/status/2094313604724212181"],"type":"url","users":["Metemcyber"],"value":"http://43.165.128.22"},{"count":3,"first_seen":"2026-08-10 12:48:25","last_seen":"2026-08-31 06:37:28","related":[["url","https://rnwm.pvvchxh.cn/ap/"],["domain","apple.wgxdijj.cn"],["domain","rnwm.fuofxwh.cn"],["url","https://rnwm.fuofxwh.cn/ap/"]],"tags":["#phishing"],"tweets":["https://x.com/Metemcyber/status/2086796811432558627","https://x.com/Metemcyber/status/2089321601628328237","https://x.com/Metemcyber/status/2094313604724212181"],"type":"ip","users":["Metemcyber"],"value":"43.165.128.22"}],"ai":{"summary":"Amazon-branded phishing campaign (Japanese targets) served from rnwm.fuofxwh.cn/ap/ resolving to 43.165.128.22.","family":null,"threat_type":"phishing","suggested_tags":["phishing"],"confidence":0.92,"tweet_id":"2086796811432558627","enriched_at":"2026-08-10T18:40:03Z"},"net":{"city":"Tokyo","country":"JP","fetched_at":"2026-08-10T13:35:03Z","org":"AS132203 Tencent Building, Kejizhongyi Avenue"}}"""  # noqa: E501
)

IOC_SHA256 = json.loads(
    r"""{"found":true,"query":"fb86366bffbc63e8b355fd9d1ebef9ab280ffe628b059bea378d28845d8374a5","window":"365d","records":[{"count":1,"first_seen":"2026-09-01 00:31:39","last_seen":"2026-09-01 00:31:39","related":[["domain","point-plsidaw.com"]],"tags":["#malware","#phishing"],"tweets":["https://x.com/masaomi346/status/2094583933044392305"],"type":"sha256","users":["masaomi346"],"value":"fb86366bffbc63e8b355fd9d1ebef9ab280ffe628b059bea378d28845d8374a5"}],"ai":{"summary":"Android malware impersonating the Rakuten Points app distributed via point-plsidaw.com; SHA256 hash provided.","family":null,"threat_type":"malware","suggested_tags":["android","malware","phishing"],"confidence":0.85,"tweet_id":"2094583933044392305","enriched_at":"2026-09-01T06:40:04Z"}}"""  # noqa: E501
)

IOC_MD5 = json.loads(
    r"""{"found":true,"query":"3d0a14d2446efc7cde12984611ec6183","window":"365d","records":[{"count":1,"first_seen":"2026-09-02 00:33:42","last_seen":"2026-09-02 00:33:42","related":[["domain","satinmaple4.com"],["url","https://satinmaple4.com/curl/0djk1usgn/yrdkr6r6fyp8viva.txt"],["domain","terminalbrewmac.com"]],"tags":["#ClickFix"],"tweets":["https://x.com/sicehice/status/2094946837140549785"],"type":"md5","users":["sicehice"],"value":"3d0a14d2446efc7cde12984611ec6183"}],"ai":{"summary":"Malicious Google ad impersonating Mac Homebrew delivers ClickFix-style malware via terminalbrewmac.com; payload hosted on satinmaple4.com.","family":null,"threat_type":"malware","suggested_tags":["clickfix","malvertising","malware"],"confidence":0.92,"tweet_id":"2094946837140549785","enriched_at":"2026-09-02T06:40:04Z"}}"""  # noqa: E501
)

IOC_EXTERNAL = json.loads(
    r"""{"found":true,"query":"0028.duckdns.org","window":"365d","records":[{"count":1,"first_seen":"2026-02-14 22:37:19","last_seen":"2026-02-14 22:37:19","related":[["domain","forwebsite.ddns.net"],["domain","luvxcide.duckdns.org"],["domain","skibidi111.airdns.org"],["domain","cloud.airdns.org"],["domain","kocrap.airdns.org"]],"tags":[],"tweets":["https://x.com/skocherhan/status/2022802361434222752"],"type":"domain","users":["skocherhan"],"value":"0028.duckdns.org"},{"count":1,"first_seen":"2026-02-14 22:37:19","last_seen":"2026-02-14 22:37:19","related":[["domain","forwebsite.ddns.net"],["domain","luvxcide.duckdns.org"],["domain","skibidi111.airdns.org"],["domain","cloud.airdns.org"],["domain","kocrap.airdns.org"]],"tags":[],"tweets":["https://x.com/skocherhan/status/2022802361434222752"],"type":"url","users":["skocherhan"],"value":"http://0028.duckdns.org"}],"external":[{"added":"2025-12-23","link":"https://threatfox.abuse.ch/ioc/1685203/","src":"threatfox","threat":"botnet_cc (Remcos)"}]}"""  # noqa: E501
)

IOC_ARCHIVE = json.loads(
    r"""{"found":false,"query":"103.167.89.81","window":"365d","records":[],"archive":{"window":"pre-365d","total":2,"records":[{"type":"ip","value":"103.167.89.81","first_seen":"2025-05-02 22:48:51","last_seen":"2025-05-07 20:53:55","count":2,"tweet_id":"1918437559014687218","tags":["#C2","#CobaltStrike"]}]}}"""  # noqa: E501
)

IOC_MISS = json.loads(r"""{"found":false,"query":"google.com","window":"365d","records":[]}""")


class MockResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        return self.payload


def _query(attr_type="domain", value="raku-point-gche.com", uuid="5b582d80-7a7e-4b6a-9f22-77656e72bb3b"):
    # uuid="" keeps the required "uuid" key present (satisfies check_input_attribute) while being
    # falsy, mirroring a hover call that carries no usable reference uuid.
    attribute = {"type": attr_type, "value": value, "uuid": uuid}
    return {"module": "tweetfeed", "attribute": attribute}


def _handle(payload, attr_type="domain", value="raku-point-gche.com", uuid="5b582d80-7a7e-4b6a-9f22-77656e72bb3b"):
    with patch.object(tweetfeed.requests, "get", return_value=MockResponse(payload)):
        return tweetfeed.handler(json.dumps(_query(attr_type, value, uuid)))


def test_domain_hit_returns_microblog_related_reg_ai_and_campaign():
    result = _handle(IOC_DOMAIN)
    objects = result["results"]["Object"]
    attributes = result["results"]["Attribute"]

    microblogs = [o for o in objects if o["name"] == "microblog"]
    assert len(microblogs) == 1
    mb_values = {a["object_relation"]: a["value"] for a in microblogs[0]["Attribute"]}
    assert mb_values["username"] == "masaomi346"
    assert "creation-date" in mb_values
    hashtags = [a["value"] for a in microblogs[0]["Attribute"] if a["object_relation"] == "hashtag"]
    assert len(hashtags) == 2

    # Related IOCs co-reported in the same tweet: 2 domains + 1 sha256 (all 3 pairs from the
    # record's "related" list are distinct and none equals the queried value).
    related_values = {"raku-point-ankanz.com", "raku-point-edia.com"}
    related_attrs = [a for a in attributes if a["value"] in related_values or a["type"] == "sha256"]
    assert len(related_attrs) == 3
    # 3 references to the related IOCs plus 1 to the queried attribute itself.
    assert all(ref["relationship_type"] == "mentions" for ref in microblogs[0]["ObjectReference"])
    assert len(microblogs[0]["ObjectReference"]) == 4

    domain_ip = next(o for o in objects if o["name"] == "domain-ip")
    di_values = {a["object_relation"]: a["value"] for a in domain_ip["Attribute"]}
    assert di_values["domain"] == "raku-point-gche.com"
    assert "registration-date" in di_values

    ai_attrs = [a for a in attributes if a["type"] == "text" and "threat_type: malware" in a["value"]]
    assert len(ai_attrs) == 1

    campaign_attrs = [a for a in attributes if a["type"] == "link" and "tfc-09c2d5ccfa23" in a["value"]]
    assert len(campaign_attrs) == 1


def test_url_hit_returns_microblog_and_reg_without_campaigns():
    result = _handle(IOC_URL, attr_type="url", value="https://site-oficial-havan.online")
    objects = result["results"]["Object"]
    microblogs = [o for o in objects if o["name"] == "microblog"]
    assert len(microblogs) == 1
    domain_ip = next(o for o in objects if o["name"] == "domain-ip")
    assert {a["object_relation"]: a["value"] for a in domain_ip["Attribute"]}["domain"] == "site-oficial-havan.online"
    attributes = result["results"].get("Attribute", [])
    assert not any(a["type"] == "link" and "campaigns" in a["value"] for a in attributes)


def test_ip_hit_returns_network_text_attribute():
    result = _handle(IOC_IP, attr_type="ip-dst", value="43.165.128.22")
    attributes = result["results"]["Attribute"]
    net_attrs = [a for a in attributes if a["value"].startswith("Network:")]
    assert len(net_attrs) == 1
    objects = result["results"]["Object"]
    microblogs = [o for o in objects if o["name"] == "microblog"]
    assert len(microblogs) == 3


def test_sha256_and_md5_hits_return_microblog_and_ai_only():
    for payload, attr_type, value in (
        (IOC_SHA256, "sha256", "fb86366bffbc63e8b355fd9d1ebef9ab280ffe628b059bea378d28845d8374a5"),
        (IOC_MD5, "md5", "3d0a14d2446efc7cde12984611ec6183"),
    ):
        result = _handle(payload, attr_type=attr_type, value=value)
        objects = result["results"]["Object"]
        assert len(objects) == 1
        assert objects[0]["name"] == "microblog"


def test_external_hit_returns_link_with_source_name():
    result = _handle(IOC_EXTERNAL, attr_type="domain", value="0028.duckdns.org")
    attributes = result["results"]["Attribute"]
    links = [a for a in attributes if a["type"] == "link"]
    assert len(links) == 1
    assert "ThreatFox" in links[0]["comment"]


def test_archive_only_hit_returns_one_microblog_without_username_and_no_error():
    result = _handle(IOC_ARCHIVE, attr_type="ip-dst", value="103.167.89.81")
    assert "error" not in result
    objects = result["results"]["Object"]
    microblogs = [o for o in objects if o["name"] == "microblog"]
    assert len(microblogs) == 1
    values = {a["object_relation"]: a["value"] for a in microblogs[0]["Attribute"]}
    assert "i/web/status/1918437559014687218" in values["url"]
    assert "username" not in values


def test_miss_returns_no_result_error():
    result = _handle(IOC_MISS, attr_type="domain", value="google.com")
    assert "error" in result
    assert "results" not in result


def test_unsupported_attribute_type_returns_error():
    result = tweetfeed.handler(json.dumps(_query(attr_type="email", value="a@b.com")))
    assert result["error"] == "Unsupported attribute type."


def test_missing_attribute_returns_error():
    result = tweetfeed.handler(json.dumps({"module": "tweetfeed"}))
    assert result["error"].startswith('This module requires an "attribute" field')


def test_http_error_mentions_status_code():
    with patch.object(tweetfeed.requests, "get", return_value=MockResponse(None, 500)):
        result = tweetfeed.handler(json.dumps(_query()))
    assert "500" in result["error"]


def test_requests_exception_is_reported():
    with patch.object(tweetfeed.requests, "get", side_effect=requests.exceptions.RequestException("boom")):
        result = tweetfeed.handler(json.dumps(_query()))
    assert "TweetFeed API request failed" in result["error"]


def test_hover_call_without_uuid_does_not_crash():
    # No reference to the (missing) queried-attribute uuid; the 3 related-IOC references
    # (which don't depend on it) are still present.
    result = _handle(IOC_DOMAIN, uuid="")
    objects = result["results"]["Object"]
    microblogs = [o for o in objects if o["name"] == "microblog"]
    assert len(microblogs) == 1
    referenced_uuids = [ref["referenced_uuid"] for ref in microblogs[0].get("ObjectReference", [])]
    assert "" not in referenced_uuids
    assert len(referenced_uuids) == 3


def test_introspection_and_version():
    assert tweetfeed.introspection() == tweetfeed.mispattributes
    assert tweetfeed.version()["name"] == "TweetFeed Lookup"
