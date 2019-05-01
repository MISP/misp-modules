import sys
try:
    import yara
except (OSError, ImportError):
    sys.exit("yara is missing, use 'pip3 install -I -r REQUIREMENTS' from the root of this repository to install it.")

# Usage: python3 yara_test.py [yara files]
# with any yara file(s) in order to test if yara library is correctly installed.
# (it is also validating yara syntax)
#
# If no argument is given, this script takes the 2 yara test rules in the same directory
# in order to test if both yara modules we need work properly.

files = sys.argv[1:] if len(sys.argv) > 1 else ['yara_hash_module_test.yara', 'yara_pe_module_test.yara']

for file_ in files:
    try:
        yara.compile(file_)
        status = "Valid syntax"
    except Exception as e:
        status = e
    print("{}: {}".format(file_, status))
