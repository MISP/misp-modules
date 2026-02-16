#!/usr/bin/env python

import logging
import os

import requests

# import pprint

copyright = """
  Copyright 2019 (C) by Aaron Kaplan <aaron@lo-res.org>, all rights reserved.
  This file is part of the ransomwarecoindDB project and licensed under the AGPL 3.0 license
"""

__version__ = 0.1


baseurl = "https://ransomcoindb.concinnity-risks.com/api/v1/"
user_agent = "ransomcoindb client via python-requests/%s" % requests.__version__

urls = {
    "BTC": {
        "btc": baseurl + "bin2btc/",
        "md5": baseurl + "bin2btc/md5/",
        "sha1": baseurl + "bin2btc/sha1/",
        "sha256": baseurl + "bin2btc/sha256/",
    },
    "XMR": {
        "xmr": baseurl + "bin2crypto/XMR/",
        "md5": baseurl + "bin2crypto/XMR/md5/",
        "sha1": baseurl + "bin2crypto/XMR/sha1/",
        "sha256": baseurl + "bin2crypto/XMR/sha256/",
    },
}


def get_data_by(coin: str, key: str, value: str, api_key: str):
    """
    Abstract function to fetch data from the bin2btc/{key} endpoint.
    This function must be made concrete by generating a relevant function.
    See below for examples.
    """

    # pprint.pprint("api-key: %s" % api_key)

    headers = {"x-api-key": api_key, "content-type": "application/json"}
    headers.update({"User-Agent": user_agent})

    # check first if valid:
    valid_coins = ["BTC", "XMR"]
    valid_keys = ["btc", "md5", "sha1", "sha256"]
    if coin not in valid_coins or key not in valid_keys:
        logging.error(
            "get_data_by_X(): not a valid key parameter. Must be  a valid coin (i.e. from %r) and one of: %r"
            % (valid_coins, valid_keys)
        )
        return None
    try:

        url = urls[coin.upper()][key]
        logging.debug("url = %s" % url)
        if not url:
            logging.error(
                "Could not find a valid coin/key combination. Must be  a valid coin (i.e. from %r) and one of: %r"
                % (valid_coins, valid_keys)
            )
            return None
        r = requests.get(url + "%s" % (value), headers=headers)
    except Exception as ex:
        logging.error("could not fetch from the service. Error: %s" % str(ex))

    if r.status_code != 200:
        logging.error("could not fetch from the service. Status code: %s" % r.status_code)
    return r.json()


def get_bin2btc_by_btc(btc_addr: str, api_key: str):
    """Function to fetch the data from the bin2btc/{btc} endpoint"""
    return get_data_by("BTC", "btc", btc_addr, api_key)


def get_bin2btc_by_md5(md5: str, api_key: str):
    """Function to fetch the data from the bin2btc/{md5} endpoint"""
    return get_data_by("BTC", "md5", md5, api_key)


def get_bin2btc_by_sha1(sha1: str, api_key: str):
    """Function to fetch the data from the bin2btc/{sha1} endpoint"""
    return get_data_by("BTC", "sha1", sha1, api_key)


def get_bin2btc_by_sha256(sha256: str, api_key: str):
    """Function to fetch the data from the bin2btc/{sha256} endpoint"""
    return get_data_by("BTC", "sha256", sha256, api_key)


if __name__ == "__main__":
    """Just for testing on the cmd line."""
    to_btc = "1KnuC7FdhGuHpvFNxtBpz299Q5QteUdNCq"
    api_key = os.getenv("api_key")
    r = get_bin2btc_by_btc(to_btc, api_key)
    print(r)
    r = get_bin2btc_by_md5("abc", api_key)
    print(r)
    r = get_data_by("XMR", "md5", "452878CD7", api_key)
    print(r)
