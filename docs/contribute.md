## How to add your own MISP modules?

Create your module in [misp_modules/modules/expansion/](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/), [misp_modules/modules/export_mod/](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/export_mod/), or [misp_modules/modules/import_mod/](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/). The module should have at minimum three functions:

* **introspection** function that returns a dict of the supported attributes (input and output) by your expansion module.
* **handler** function which accepts a JSON document to expand the values and return a dictionary of the expanded values.
* **version** function that returns a dict with the version and the associated meta-data including potential configurations required of the module.

Don't forget to return an error key and value if an error is raised to propagate it to the MISP user-interface.

Your module's script name should also be added in the `__all__` list of `<module type folder>/__init__.py` in order for it to be loaded.

~~~python
...
    # Checking for required value
    if not request.get('ip-src'):
        # Return an error message
        return {'error': "A source IP is required"}
...
~~~


### introspection

The function that returns a dict of the supported attributes (input and output) by your expansion module.

~~~python
mispattributes = {'input': ['link', 'url'],
                  'output': ['attachment', 'malware-sample']}

def introspection():
    return mispattributes
~~~

### version

The function that returns a dict with the version and the associated meta-data including potential configurations required of the module.


### Additional Configuration Values

If your module requires additional configuration (to be exposed via the MISP user-interface), you can define those in the moduleconfig value returned by the version function.

~~~python
# config fields that your code expects from the site admin
moduleconfig = ["apikey", "event_limit"]

def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
~~~


When you do this a config array is added to the meta-data output containing all the potential configuration values:

~~~
"meta": {
      "description": "PassiveTotal expansion service to expand values with multiple Passive DNS sources",
      "config": [
        "username",
        "password"
      ],
      "module-type": [
        "expansion",
        "hover"
      ],

...
~~~


If you want to use the configuration values set in the web interface they are stored in the key `config` in the JSON object passed to the handler.

~~~
def handler(q=False):

    # Check if we were given a configuration
    config = q.get("config", {})

    # Find out if there is a username field
    username = config.get("username", None)
~~~


### handler

The function which accepts a JSON document to expand the values and return a dictionary of the expanded values.

~~~python
def handler(q=False):
    "Fully functional rot-13 encoder"
    if q is False:
        return False
    request = json.loads(q)
    src = request.get('ip-src')
    if src is None:
        # Return an error message
        return {'error': "A source IP is required"}
    else:
        return {'results':
                codecs.encode(src, "rot-13")}
~~~

#### export module

For an export module, the `request["data"]` object corresponds to a list of events (dictionaries) to handle.

Iterating over events attributes is performed using their `Attribute` key.

~~~python
...
for event in request["data"]:
        for attribute in event["Attribute"]:
          # do stuff w/ attribute['type'], attribute['value'], ...
...

### Returning Binary Data

If you want to return a file or other data you need to add a data attribute.

~~~python
{"results": {"values": "filename.txt",
             "types": "attachment",
             "data"  : base64.b64encode(<ByteIO>)  # base64 encode your data first
             "comment": "This is an attachment"}}
~~~

If the binary file is malware you can use 'malware-sample' as the type. If you do this the malware sample will be automatically zipped and password protected ('infected') after being uploaded.


~~~python
{"results": {"values": "filename.txt",
             "types": "malware-sample",
             "data"  : base64.b64encode(<ByteIO>)  # base64 encode your data first
             "comment": "This is an attachment"}}
~~~

[To learn more about how data attributes are processed you can read the processing code here.](https://github.com/MISP/PyMISP/blob/4f230c9299ad9d2d1c851148c629b61a94f3f117/pymisp/mispevent.py#L185-L200)


### Module type

A MISP module can be of four types:

- **expansion** - service related to an attribute that can be used to extend and update an existing event.
- **hover** - service related to an attribute to provide additional information to the users without updating the event.
- **import** - service related to importing and parsing an external object that can be used to extend an existing event.
- **export** - service related to exporting an object, event, or data.

module-type is an array where the list of supported types can be added.

## Testing your modules?

MISP uses the **modules** function to discover the available MISP modules and their supported MISP attributes:

~~~
% curl -s http://127.0.0.1:6666/modules | jq .
[
  {
    "name": "passivetotal",
    "type": "expansion",
    "mispattributes": {
      "input": [
        "hostname",
        "domain",
        "ip-src",
        "ip-dst"
      ],
      "output": [
        "ip-src",
        "ip-dst",
        "hostname",
        "domain"
      ]
    },
    "meta": {
      "description": "PassiveTotal expansion service to expand values with multiple Passive DNS sources",
      "config": [
        "username",
        "password"
      ],
      "author": "Alexandre Dulaunoy",
      "version": "0.1"
    }
  },
  {
    "name": "sourcecache",
    "type": "expansion",
    "mispattributes": {
      "input": [
        "link"
      ],
      "output": [
        "link"
      ]
    },
    "meta": {
      "description": "Module to cache web pages of analysis reports, OSINT sources. The module returns a link of the cached page.",
      "author": "Alexandre Dulaunoy",
      "version": "0.1"
    }
  },
  {
    "name": "dns",
    "type": "expansion",
    "mispattributes": {
      "input": [
        "hostname",
        "domain"
      ],
      "output": [
        "ip-src",
        "ip-dst"
      ]
    },
    "meta": {
      "description": "Simple DNS expansion service to resolve IP address from MISP attributes",
      "author": "Alexandre Dulaunoy",
      "version": "0.1"
    }
  }
]

~~~

The MISP module service returns the available modules in a JSON array containing each module name along with their supported input attributes.

Based on this information, a query can be built in a JSON format and saved as body.json:

~~~json
{
  "hostname": "www.foo.be",
  "module": "dns"
}
~~~

Then you can POST this JSON format query towards the MISP object server:

~~~bash
curl -s http://127.0.0.1:6666/query -H "Content-Type: application/json" --data @body.json -X POST
~~~

The module should output the following JSON:

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

It is also possible to restrict the category options of the resolved attributes by passing a list of categories along (optional):

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
      ],
      "categories": [
        "Network activity",
        "Payload delivery"
      ]
    }
  ]
}
~~~

For both the type and the category lists, the first item in the list will be the default setting on the interface.

### Enable your module in the web interface

For a module to be activated in the MISP web interface it must be enabled in the "Plugin Settings.

Go to "Administration > Server Settings" in the top menu
- Go to "Plugin Settings" in the top "tab menu bar"
- Click on the name of the type of module you have created to expand the list of plugins to show your module.
- Find the name of your plugin's "enabled" value in the Setting Column.
"Plugin.[MODULE NAME]_enabled"
- Double click on its "Value" column

~~~
Priority        Setting                         Value   Description                             Error Message
Recommended     Plugin.Import_ocr_enabled       false   Enable or disable the ocr module.       Value not set.
~~~

- Use the drop-down to set the enabled value to 'true'

~~~
Priority        Setting                         Value   Description                             Error Message
Recommended     Plugin.Import_ocr_enabled       true   Enable or disable the ocr module.       Value not set.
~~~

### Set any other required settings for your module

In this same menu set any other plugin settings that are required for testing.



## Documentation

In order to provide documentation about some modules that require specific input / output / configuration, the [doc](https://github.com/MISP/misp-modules/tree/master/doc) directory contains detailed information about the general purpose, requirements, features, input and output of each of these modules:

- ***description** - quick description of the general purpose of the module, as the one given by the moduleinfo
- **requirements** - special libraries needed to make the module work
- **features** - description of the way to use the module, with the required MISP features to make the module give the intended result
- **references** - link(s) giving additional information about the format concerned in the module
- **input** - description of the format of data used in input
- **output** - description of the format given as the result of the module execution

In addition to the module documentation please add your module to [docs/index.md](https://github.com/MISP/misp-modules/tree/master/docs/index.md).

There are also [complementary slides](https://www.misp-project.org/misp-training/3.1-misp-modules.pdf) for the creation of MISP modules.


## Tips for developers creating modules

Download a pre-built virtual image from the [MISP training materials](https://www.circl.lu/services/misp-training-materials/).

- Create a Host-Only adapter in VirtualBox
- Set your Misp OVA to that Host-Only adapter
- Start the virtual machine
- Get the IP address of the virutal machine
- SSH into the machine (Login info on training page)
- Go into the misp-modules directory

~~~bash
cd /usr/local/src/misp-modules
~~~

Set the git repo to your fork and checkout your development branch. If you SSH'ed in as the misp user you will have to use sudo.

~~~bash
sudo git remote set-url origin https://github.com/YourRepo/misp-modules.git
sudo git pull
sudo git checkout MyModBranch
~~~

Remove the contents of the build directory and re-install misp-modules.

~~~python
sudo rm -fr build/*
sudo pip3 install --upgrade .
~~~

SSH in with a different terminal and run `misp-modules` with debugging enabled.

~~~python
sudo killall misp-modules
misp-modules -d
~~~


In your original terminal you can now run your tests manually and see any errors that arrive

~~~bash
cd tests/
curl -s http://127.0.0.1:6666/query -H "Content-Type: application/json" --data @MY_TEST_FILE.json -X POST
cd ../
~~~
