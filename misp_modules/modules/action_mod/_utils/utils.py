#!/usr/bin/env python

from jinja2.sandbox import SandboxedEnvironment

default_template = """
# Tutorial: How to use jinja2 templating

:warning: For these examples, we consider the module received data under the MISP core format

1. You can use the dot `.` notation or the subscript syntax `[]` to access attributes of a variable
    - `{% raw %}{{ Event.info }}{% endraw %}` -> {{ Event.info }}
    - `{% raw %}{{ Event['info'] }}{% endraw %}` -> {{ Event['info'] }}

2. Jinja2 allows you to easily create list:
```{% raw %}
{% for attribute in Event.Attribute %}
- {{ attribute.value }}
{% endfor %}
{% endraw %}```

Gives:
{% for attribute in Event.Attribute %}
- {{ attribute.value }}
{% endfor %}

3. Jinja2 allows you to add logic
```{% raw %}
{% if "tlp:white" in Event.Tag %}
- This Event has the TLP:WHITE tag
{% else %}
- This Event doesn't have the TLP:WHITE tag
{% endif %}
{% endraw %}```

Gives:
{% if "tlp:white" in Event.Tag %}
- This Event has the TLP:WHITE tag
{% else %}
- This Event doesn't have the TLP:WHITE tag
{% endif %}

##  Jinja2 allows you to modify variables by using filters

3. The `reverse` filter
- `{% raw %}{{ Event.info | reverse }}{% endraw %}` -> {{ Event.info | reverse }}

4. The `format` filter
- `{% raw %}{{ "%s :: %s" | format(Event.Attribute[0].type, Event.Attribute[0].value) }}{% endraw %}` -> {{ "%s :: %s" | format(Event.Attribute[0].type, Event.Attribute[0].value) }}

5.The `groupby` filter
```{% raw %}
{% for type, attributes in Event.Attribute|groupby("type") %}
- {{ type }}{% for attribute in attributes %}
    - {{ attribute.value }}
    {% endfor %}
{% endfor %}
{% endraw %}```

Gives:
{% for type, attributes in Event.Attribute|groupby("type") %}
- {{ type }}{% for attribute in attributes %}
    - {{ attribute.value }}
    {% endfor %}
{% endfor %}
"""


def renderTemplate(data, template=default_template):
    env = SandboxedEnvironment()
    return env.from_string(template).render(data)
