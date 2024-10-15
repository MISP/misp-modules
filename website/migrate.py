import os
import argparse
import subprocess

os.environ.setdefault('FLASKENV', 'development')

parser = argparse.ArgumentParser()
parser.add_argument("-m", "--migrate", help="Initialise the db if it not exist", action="store_true")
parser.add_argument("-u", "--upgrade", help="Delete and initialise the db", action="store_true")
parser.add_argument("-d", "--downgrade", help="Launch the app", action="store_true")
args = parser.parse_args()


if args.migrate:
    subprocess.call(["flask", "db", "migrate"])
elif args.upgrade:
    subprocess.call(["flask", "db", "upgrade"])
elif args.downgrade:
    subprocess.call(["flask", "db", "downgrade"])
