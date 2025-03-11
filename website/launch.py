import os
import argparse
import subprocess
import time
from app_creation import main

import signal
import sys
def signal_handler(sig, frame):
    kill_script()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--init_db", help="Initialise the db if it not exist", action="store_true")
parser.add_argument("-r", "--reload_db", help="Delete and initialise the db", action="store_true")
parser.add_argument("-l", "--launch", help="Launch the app", action="store_true")
parser.add_argument("-ks", "--killscript", help="Kill screen running background", action="store_true")
args = parser.parse_args()

def kill_script():
    r = ["screen", "-ls", "|", "egrep", "[0-9]+.misp_mod", "|", "cut", "-d.", "-f1"]
    process = subprocess.Popen(r, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    if out:
        subprocess.call(["screen", "-X", "-S", "misp_mod", "quit"])

if args.init_db:
    main(init_db=True)
elif args.reload_db:
    main(recreate_db=True)
elif args.launch:
    os.environ.setdefault('FLASKENV', 'development')
    kill_script()
    subprocess.call(["screen", "-dmS", "misp_mod"])
    r = ["screen", "-S", "misp_mod", "-X", "screen", "-t", "misp_modules_server", "bash", "-c", "../env/bin/misp-modules", "-l", "127.0.0.1;", "read x"]
    subprocess.call(r)
    time.sleep(2)
    main(create_module=True)
    main()
elif args.killscript:
    kill_script()