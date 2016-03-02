# MISP modules

MISP modules are autonomous modules that can be used for expansion and other services in [MISP](https://github.com/MISP/MISP).

The modules are written in Python 3 following a simple API interface. The objective is to ease the extensions of MISP functionalities
without modifying core components. The API is available via a simple REST API which is independent from MISP installation or configuration. 

MISP modules support is included in MISP starting from version 2.4.X.

## Existing MISP modules

* [DNS](modules/expansion/dns.py) - a simple module to resolve MISP attributes like hostname and domain to expand IP addresses attributes.
* [passivetotal](modules/expansion/passivetotal.py) - a [passivetotal](https://www.passivetotal.org/) module to query the passivetotal passive DNS interface.

## How to add your own MISP modules?

Create your module in [modules/expansion/](modules/expansion/). The module should have at minimum two functions:

* **introspection** function that returns an array of the supported attributes by your expansion module.
* **handler** function which accepts a JSON document to expand the values and return a dictionary of the expanded values.

Don't forget to return an error key and value if an error is raised to propagate it to the MISP user-interface.

## Testing your modules?

MISP uses the **modules** function to discover the available MISP modules and their supported MISP attributes:

~~~
% curl -s http://127.0.0.1:6666/modules | jq .
[
  {
    "mispattributes": {
      "output": [
        "ip-src",
        "ip-dst"
      ],
      "input": [
        "hostname",
        "domain"
      ]
    },
    "type": "expansion",
    "name": "dns",
    "version": "0.1"
  }
]

~~~

The MISP module service returns the available modules in a JSON array containing each module name along with their supported input attributes.

Based on this information, a query can be built in a JSON format and saved as body.json:

~~~json
{
  "results": [
    {
      "types": [
        "ip-src",
        "ip-dst"
      ],
      "values": [
        "188.65.217.78"
      ]
    }
  ]
}
~~~

Then you can POST this JSON format query towards the MISP object server:

~~~
curl -s http://127.0.0.1:6666/query -H "Content-Type: application/json" --data @body.json -X POST
~~~

