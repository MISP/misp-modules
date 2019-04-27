dnsdb-query
===========

These clients are reference implementations of the [DNSDB HTTP API](https://api.dnsdb.info/).  Output is
compliant with the [Passive DNS Common Output Format](http://tools.ietf.org/html/draft-dulaunoy-kaplan-passive-dns-cof-01).

Please see https://www.dnsdb.info/ for more information.

Requirements
------------
 * Linux, BSD, OS X
 * Curl
 * Python 2.7.x
 * Farsight DNSDB API key

Installation
------------
1. Create a directory

  ```
  mkdir ~/dnsdb
  ```
1. Download the software

  ```
  curl https://codeload.github.com/dnsdb/dnsdb-query/tar.gz/debian/0.2-1 -o ~/dnsdb/0.2-1.tar.gz
  ```
1. Extract the software

  ```
  tar xzvf ~/dnsdb/0.2-1.tar.gz -C ~/dnsdb/ --strip-components=1
  ```
1. Create a API key file

  ```
  nano ~/.dnsdb-query.conf
  ```
1. Cut and paste the following and replace '\<apikey\>' with your API Key

   ```
   APIKEY="<apikey>"
   ```
1. Test the Python client

  ```
  $ python dnsdb/dnsdb_query.py -i 104.244.13.104
  ```
  ```
  ...
  www.farsightsecurity.com. IN A 104.244.13.104
  ```

dnsdb_query.py
--------------

dnsdb_query.py is a Python client for the DNSDB HTTP API. It is similar
to the dnsdb-query shell script but supports some additional features
like sorting and setting the result limit parameter. It is also embeddable
as a Python module.

```
Usage: dnsdb_query.py [options]

Options:
  -h, --help            show this help message and exit
  -c CONFIG, --config=CONFIG
                        config file
  -r RRSET, --rrset=RRSET
                        rrset <ONAME>[/<RRTYPE>[/BAILIWICK]]
  -n RDATA_NAME, --rdataname=RDATA_NAME
                        rdata name <NAME>[/<RRTYPE>]
  -i RDATA_IP, --rdataip=RDATA_IP
                        rdata ip <IPADDRESS|IPRANGE|IPNETWORK>
  -s SORT, --sort=SORT  sort key
  -R, --reverse         reverse sort
  -j, --json            output in JSON format
  -l LIMIT, --limit=LIMIT
                        limit number of results
  --before=BEFORE       only output results seen before this time
  --after=AFTER         only output results seen after this time

Time formats are: "%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d" (UNIX timestamp),
"-%d" (Relative time in seconds), BIND format relative timestamp (e.g. 1w1h,
(w)eek, (d)ay, (h)our, (m)inute, (s)econd)
```

Or, from Python:

```
from dnsdb_query import DnsdbClient

server='https://api.dnsdb.info'
apikey='d41d8cd98f00b204e9800998ecf8427e'

client = DnsdbClient(server,apikey)
for rrset in client.query_rrset('www.dnsdb.info'):
    # rrset is a decoded JSON blob
    print repr(rrset)
```

Other configuration options that may be set:

`DNSDB_SERVER`
The base URL of the DNSDB HTTP API, minus the /lookup component. Defaults to
`https://api.dnsdb.info.`

`HTTP_PROXY`
The URL of the HTTP proxy that you wish to use.

`HTTPS_PROXY`
The URL of the HTTPS proxy that you wish to use.

dnsdb-query
-----------

dnsdb-query is a simple curl-based wrapper for the DNSDB HTTP API.

The script sources the config file `/etc/dnsdb-query.conf` as a shell fragment.
If the config file is not present in `/etc`, the file `$HOME/.dnsdb-query.conf`
is sourced instead.

The config file MUST set the value of the APIKEY shell variable to the API
key provided to you by Farsight Security.

For example, if your API key is d41d8cd98f00b204e9800998ecf8427e, place the
following line in `/etc/dnsdb-query.conf` or `$HOME/.dnsdb-query.conf`:

```
APIKEY="d41d8cd98f00b204e9800998ecf8427e"
```

Other shell variables that may be set via the config file or command line
are:

`DNSDB_SERVER`
The base URL of the DNSDB HTTP API, minus the /lookup component. Defaults to
`https://api.dnsdb.info.`

`DNSDB_FORMAT`
The result format to use, either text or json. Defaults to text.

`HTTP_PROXY`
The URL of the HTTP proxy that you wish to use.

`HTTPS_PROXY`
The URL of the HTTPS proxy that you wish to use.

dnsdb-query supports the following usages:

```
Usage: dnsdb-query rrset <ONAME>[/<RRTYPE>[/<BAILIWICK>]]
Usage: dnsdb-query rdata ip <IPADDRESS>
Usage: dnsdb-query rdata name <NAME>[/<RRTYPE>]
Usage: dnsdb-query rdata raw <HEX>[/<RRTYPE>]
```

If your rrname, bailiwick or rdata contains the `/` character you
will need to escape it to `%2F` on the command line.  eg:

`./dnsdb_query -r 1.0%2F1.0.168.192.in-addr.arpa`
	
retrieves the rrsets for `1.0/1.0.168.192.in-addr.arpa`.
