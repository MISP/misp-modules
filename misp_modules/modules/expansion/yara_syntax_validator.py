import json
import yara
import re

misperrors = {"error": "Error"}
mispattributes = {"input": ["yara"], "output": ["text"]}
moduleinfo = {
    "version": "0.1",
    "author": "Dennis Rand",
    "description": "An expansion hover module to perform a syntax check on if yara rules are valid or not.",
    "module-type": ["hover"],
    "name": "YARA Syntax Validator",
    "logo": "yara.png",
    "requirements": ["yara_python python library"],
    "features": (
        "This modules simply takes a YARA rule as input, and checks its syntax. It returns then a confirmation if the"
        " syntax is valid, otherwise the syntax error is displayed."
    ),
    "references": ["http://virustotal.github.io/yara/"],
    "input": "YARA rule attribute.",
    "output": "Text to inform users if their rule is valid.",
}
moduleconfig = []

# List of most uses Modules in yara

YARA_MODULES = {"pe", "math", "cuckoo", "magic", "hash", "dotnet", "elf", "macho"}

# YARA rules can reference internal modules such as `pe`, `math`, `cuckoo`,
# `elf`, etc. Normally, a rule must explicitly import these modules using:
#       import "pe"
#       import "elf"
#
# Even if the YARA rule itself is perfectly valid, it will fail to compile
# if the correct modules are NOT imported. For example, references such as:
#       pe.entry_point
# or   elf.sections
# will raise "undefined identifier" errors unless the appropriate imports
# are present.

def insert_import_module(rule_text, module_name):
    lines = rule_text.strip().splitlines()
    if not any(line.strip().startswith(f'import "{module_name}"') for line in lines):
        return f'import "{module_name}"\n' + rule_text
    return rule_text


# -------------------------------
#  HANDLER NOW DOES VALIDATION LOGIC
# -------------------------------

# -------------------------------------------------------------------------
# To make the validator more user-friendly, we automatically insert missing
# imports when YARA reports an undefined identifier matching a known module.
#
# Additionally, YARA rules sometimes use *external variables*, for example:
#       rule test { condition: filename == "test.exe" }
#
# If these variables are not provided, YARA will also fail, even though the
# rule is syntactically valid. To prevent unnecessary failures, the validator
# automatically assigns dummy values to any missing external variables.
#
# This ensures:
#   - A clean, user-friendly validation process
#   - Correct detection of real syntax errors
#   - No false negatives caused by missing imports or missing externals
# -------------------------------------------------------------------------

def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)
    rule_content = request.get("yara")

    if not rule_content:
        misperrors["error"] = "Yara rule missing"
        return misperrors

    externals = {}
    attempts = 0
    max_attempts = 10   # to prevent from infinite loop
    current_rule_text = rule_content

    while attempts < max_attempts:
        try:
            yara.compile(source=current_rule_text, externals=externals) # some times the compilator needs externals variables
            summary = "Syntax valid"
            break
        except yara.SyntaxError as e:
            error_msg = str(e)

            # try to catch modules or externals variables errors to auto correct it 
            match_id = re.search(r'undefined identifier "(\w+)"', error_msg)
            if match_id:
                var_name = match_id.group(1)

                # Auto-import YARA modules
                if var_name in YARA_MODULES:
                    current_rule_text = insert_import_module(current_rule_text, var_name)
                else:
                    # Treat as external variable
                    externals[var_name] = "example.txt" # a random value so that the compiler does not make an error (most of the time the external variable are in other configs files)

                attempts += 1
                continue

            # Other syntax errors
            summary = "Syntax error: " + error_msg
            break

    else:
        # Max attempts exceeded
        summary = "Syntax error: Max validation attempts exceeded"

    return {"results": [{"types": mispattributes["output"], "values": summary}]}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo


