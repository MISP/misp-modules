# This module does not appear to be actively maintained.
# Please see https://github.com/DomainTools/domaintools_misp
# for the official DomainTools-supported MISP app

import json
import logging
import sys

from domaintools import API

log = logging.getLogger("domaintools")
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
log.addHandler(ch)

misperrors = {"error": "Error"}
mispattributes = {
    "input": [
        "domain",
        "email-src",
        "email-dst",
        "target-email",
        "whois-registrant-email",
        "whois-registrant-name",
        "whois-registrant-phone",
        "ip-src",
        "ip-dst",
    ],
    "output": [
        "whois-registrant-email",
        "whois-registrant-phone",
        "whois-registrant-name",
        "whois-registrar",
        "whois-creation-date",
        "freetext",
        "domain",
    ],
}

moduleinfo = {
    "version": "0.1",
    "author": "Raphaël Vinot",
    "description": "DomainTools MISP expansion module.",
    "module-type": ["expansion", "hover"],
    "name": "DomainTools Lookup",
    "logo": "domaintools.png",
    "requirements": [
        "Domaintools python library",
        "A Domaintools API access (username & apikey)",
    ],
    "features": (
        "This module takes a MISP attribute as input to query the Domaintools API. The API returns then the result of"
        " the query with some types we map into compatible types we add as MISP attributes.\n\nPlease note that"
        " composite attributes composed by at least one of the input types mentionned below (domains, IPs, hostnames)"
        " are also supported."
    ),
    "references": ["https://www.domaintools.com/"],
    "input": (
        "A MISP attribute included in the following list:\n- domain\n- hostname\n- email-src\n- email-dst\n-"
        " target-email\n- whois-registrant-email\n- whois-registrant-name\n- whois-registrant-phone\n- ip-src\n- ip-dst"
    ),
    "output": (
        "MISP attributes mapped after the Domaintools API has been queried, included in the following list:\n-"
        " whois-registrant-email\n- whois-registrant-phone\n- whois-registrant-name\n- whois-registrar\n-"
        " whois-creation-date\n- text\n- domain"
    ),
}

moduleconfig = ["username", "api_key"]

query_profiles = [
    {
        "inputs": ["domain"],
        "services": ["parsed_whois", "domain_profile", "reputation", "reverse_ip"],
    },
    {
        "inputs": [
            "email-src",
            "email-dst",
            "target-email",
            "whois-registrant-email",
            "whois-registrant-name",
            "whois-registrant-phone",
        ],
        "services": ["reverse_whois"],
    },
    {"inputs": ["ip-src", "ip-dst"], "services": ["host_domains"]},
]


class DomainTools(object):

    def __init__(self):
        self.reg_mail = {}
        self.reg_phone = {}
        self.reg_name = {}
        self.registrar = {}
        self.creation_date = {}
        self.domain_ip = {}
        self.domain = {}
        self.risk = ()
        self.freetext = ""

    def _add_value(self, value_type, value, comment):
        if value_type.get(value):
            if comment and comment not in value_type[value]:
                value_type[value] += " - {}".format(comment)
        else:
            value_type[value] = comment or ""
        return value_type

    def add_mail(self, mail, comment=None):
        self.reg_mail = self._add_value(self.reg_mail, mail, comment)

    def add_phone(self, phone, comment=None):
        self.reg_phone = self._add_value(self.reg_phone, phone, comment)

    def add_name(self, name, comment=None):
        self.reg_name = self._add_value(self.reg_name, name, comment)

    def add_registrar(self, reg, comment=None):
        self.registrar = self._add_value(self.registrar, reg, comment)

    def add_creation_date(self, date, comment=None):
        self.creation_date = self._add_value(self.creation_date, date, comment)

    def add_ip(self, ip, comment=None):
        self.domain_ip = self._add_value(self.domain_ip, ip, comment)

    def add_domain(self, domain, comment=None):
        self.domain = self._add_value(self.domain, domain, comment)

    def dump(self):
        to_return = []
        if self.reg_mail:
            for mail, comment in self.reg_mail.items():
                to_return.append(
                    {
                        "type": "whois-registrant-email",
                        "values": [mail],
                        "comment": comment or "",
                    }
                )
        if self.reg_phone:
            for phone, comment in self.reg_phone.items():
                to_return.append(
                    {
                        "type": "whois-registrant-phone",
                        "values": [phone],
                        "comment": comment or "",
                    }
                )
        if self.reg_name:
            for name, comment in self.reg_name.items():
                to_return.append(
                    {
                        "type": "whois-registrant-name",
                        "values": [name],
                        "comment": comment or "",
                    }
                )
        if self.registrar:
            for reg, comment in self.registrar.items():
                to_return.append(
                    {
                        "type": "whois-registrar",
                        "values": [reg],
                        "comment": comment or "",
                    }
                )
        if self.creation_date:
            for date, comment in self.creation_date.items():
                to_return.append(
                    {
                        "type": "whois-creation-date",
                        "values": [date],
                        "comment": comment or "",
                    }
                )
        if self.domain_ip:
            for ip, comment in self.domain_ip.items():
                to_return.append(
                    {
                        "types": ["ip-dst", "ip-src"],
                        "values": [ip],
                        "comment": comment or "",
                    }
                )
        if self.domain:
            for domain, comment in self.domain.items():
                to_return.append({"type": "domain", "values": [domain], "comment": comment or ""})
        if self.freetext:
            to_return.append(
                {
                    "type": "freetext",
                    "values": [self.freetext],
                    "comment": "Freetext import",
                }
            )
        if self.risk:
            to_return.append({"type": "text", "values": [self.risk[0]], "comment": self.risk[1]})
        return to_return


def parsed_whois(domtools, to_query, values):
    whois_entry = domtools.parsed_whois(to_query)
    if whois_entry.get("error"):
        misperrors["error"] = whois_entry["error"]["message"]
        return misperrors

    if whois_entry.get("registrant"):
        values.add_name(whois_entry["registrant"], "Parsed registrant")

    if whois_entry.get("registration"):
        values.add_creation_date(whois_entry["registration"]["created"], "timestamp")

    if whois_entry.get("whois"):
        values.freetext = whois_entry["whois"]["record"]
    if whois_entry.get("parsed_whois"):
        if whois_entry["parsed_whois"]["created_date"]:
            values.add_creation_date(whois_entry["parsed_whois"]["created_date"], "created")
        if whois_entry["parsed_whois"]["registrar"]["name"]:
            values.add_registrar(whois_entry["parsed_whois"]["registrar"]["name"], "name")
        if whois_entry["parsed_whois"]["registrar"]["url"]:
            values.add_registrar(whois_entry["parsed_whois"]["registrar"]["url"], "url")
        if whois_entry["parsed_whois"]["registrar"]["iana_id"]:
            values.add_registrar(whois_entry["parsed_whois"]["registrar"]["iana_id"], "iana_id")
        for key, entry in whois_entry["parsed_whois"]["contacts"].items():
            if entry["email"]:
                values.add_mail(entry["email"], key)
            if entry["phone"]:
                values.add_phone(entry["phone"], key)
            if entry["name"]:
                values.add_name(entry["name"], key)
    if whois_entry.emails():
        for mail in whois_entry.emails():
            if mail not in values.reg_mail.keys():
                values.add_mail(mail, "Maybe registrar")
    return values


def domain_profile(domtools, to_query, values):
    profile = domtools.domain_profile(to_query)
    # NOTE: profile['website_data']['response_code'] could be used to see if the host is still up. Maybe set a tag.
    if profile.get("error"):
        misperrors["error"] = profile["error"]["message"]
        return misperrors

    if profile.get("registrant"):
        values.add_name(profile["registrant"]["name"], "Profile registrant")

    if profile.get("server"):
        other_domains = profile["server"]["other_domains"]
        values.add_ip(
            profile["server"]["ip_address"],
            "IP of {} (via DomainTools). Has {} other domains.".format(to_query, other_domains),
        )

    if profile.get("registration"):
        if profile["registration"].get("created"):
            values.add_creation_date(profile["registration"]["created"], "created")
        if profile["registration"].get("updated"):
            values.add_creation_date(profile["registration"]["updated"], "updated")
        if profile["registration"].get("registrar"):
            values.add_registrar(profile["registration"]["registrar"], "name")
    return values


def reputation(domtools, to_query, values):
    rep = domtools.reputation(to_query, include_reasons=True)
    # NOTE: use that value in a tag when we will have attribute level tagging
    if rep and not rep.get("error"):
        reasons = ", ".join(rep["reasons"])
        values.risk = [
            rep["risk_score"],
            "Risk value of {} (via Domain Tools), Reasons: {}".format(to_query, reasons),
        ]
    return values


def reverse_ip(domtools, to_query, values):
    rev_ip = domtools.reverse_ip(to_query)
    if rev_ip and not rev_ip.get("error"):
        ip_addresses = rev_ip["ip_addresses"]
        values.add_ip(
            ip_addresses["ip_address"],
            "IP of {} (via DomainTools). Has {} other domains.".format(to_query, ip_addresses["domain_count"]),
        )
        for d in ip_addresses["domain_names"]:
            values.add_domain(d, "Other domain on {}.".format(ip_addresses["ip_address"]))
    return values


def reverse_whois(domtools, to_query, values):
    rev_whois = domtools.reverse_whois(to_query, mode="purchase")
    if rev_whois.get("error"):
        misperrors["error"] = rev_whois["error"]["message"]
        return misperrors
    for d in rev_whois["domains"]:
        values.add_domain(d, "Reverse domain related to {}.".format(to_query))
    return values


def host_domains(domtools, to_query, values):
    hostdom = domtools.host_domains(to_query)
    if hostdom.get("error"):
        misperrors["error"] = hostdom["error"]["message"]
        return misperrors
    ip_addresses = hostdom["ip_addresses"]
    if to_query != ip_addresses["ip_address"]:
        values.add_ip(
            ip_addresses["ip_address"],
            "IP of {} (via DomainTools). Has {} other domains.".format(to_query, ip_addresses["domain_count"]),
        )
    for d in ip_addresses["domain_names"]:
        values.add_domain(d, "Other domain on {}.".format(ip_addresses["ip_address"]))
    return values


def reverse_ip_whois(domtools, to_query, values):
    # Disabled for now, dies with domaintools.exceptions.NotAuthorizedException
    rev_whois = domtools.reverse_ip_whois(ip=to_query)
    print(rev_whois)
    if rev_whois.get("error"):
        misperrors["error"] = rev_whois["error"]["message"]
        return misperrors
    # for d in rev_whois['domains']:
    #    values.add_domain(d, 'Reverse domain related to {}.'.format(to_query))
    return values


def get_services(request):
    for t in mispattributes["input"]:
        to_query = request.get(t)
        if not to_query:
            continue
        for p in query_profiles:
            if t in p["inputs"]:
                return p["services"]


def handler(q=False):
    if not q:
        return q

    request = json.loads(q)
    to_query = None
    for t in mispattributes["input"]:
        to_query = request.get(t)
        if to_query:
            break
    if not to_query:
        misperrors["error"] = "Unsupported attributes type"
        return misperrors

    if request.get("config"):
        if (request["config"].get("username") is None) or (request["config"].get("api_key") is None):
            misperrors["error"] = "DomainTools authentication is incomplete"
            return misperrors
        else:
            domtools = API(request["config"].get("username"), request["config"].get("api_key"))
    else:
        misperrors["error"] = "DomainTools authentication is missing"
        return misperrors

    values = DomainTools()
    services = get_services(request)
    if services:
        try:
            for s in services:
                globals()[s](domtools, to_query, values)
        except Exception as e:
            print(to_query, type(e), e)

    return {"results": values.dump()}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
