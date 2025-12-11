#!/usr/bin/env python3
import argparse
import os
import subprocess
import time

from dotenv import load_dotenv
from app import create_app, db

# Load environment variables from .env
load_dotenv()

# Create app instance for WSGI servers (Gunicorn, uWSGI, etc.)
# This must be at module level so Gunicorn can find it with "main:app"
app = create_app()


def run_dev():
    """Run misp-modules + Flask dev server"""
    # Only the parent process starts misp-modules
    if os.getenv("WERKZEUG_RUN_MAIN") != "true":
        print("Starting misp-modules...")

        modules_env = os.environ.copy()
        modules_env.pop("VIRTUAL_ENV", None)

        misp_proc = subprocess.Popen(
            ["poetry", "run", "misp-modules", "-l", "127.0.0.1"],
            cwd="..",
            env=modules_env,
        )
        time.sleep(2)

    from app.utils import IS_DEVELOPMENT

    IS_DEVELOPMENT = True

    try:
        print("Starting website in debug mode...")
        app.run(
            host=app.config["FLASK_URL"],
            port=app.config["FLASK_PORT"],
            debug=IS_DEVELOPMENT,
        )
    finally:
        if os.getenv("WERKZEUG_RUN_MAIN") != "true":
            misp_proc.terminate()


def db_init():
    """Initialize the database"""
    from app.utils import gen_admin_password
    from app.utils.init_modules import create_modules_db

    modules_env = os.environ.copy()
    modules_env.pop("VIRTUAL_ENV", None)

    misp_proc = subprocess.Popen(
        ["poetry", "run", "misp-modules", "-l", "127.0.0.1"],
        cwd="..",
        env=modules_env,
    )
    time.sleep(5)

    with app.app_context():
        db.create_all()
        create_modules_db()
        gen_admin_password()
        print("Database initialized.")

    misp_proc.terminate()


def db_migrate():
    subprocess.run(["flask", "db", "migrate"])


def db_upgrade():
    subprocess.run(["flask", "db", "upgrade"])


def db_downgrade():
    subprocess.run(["flask", "db", "downgrade"])


def main():
    parser = argparse.ArgumentParser(description="MISP Modules Website CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- dev ---
    subparsers.add_parser("dev", help="Run misp-modules + website in debug mode")

    # --- db group ---
    db_parser = subparsers.add_parser("db", help="Database operations")
    db_sub = db_parser.add_subparsers(dest="action", required=True)

    db_sub.add_parser("init", help="Initialize the database")
    db_sub.add_parser("migrate", help="Generate a new migration")
    db_sub.add_parser("upgrade", help="Apply migrations")
    db_sub.add_parser("downgrade", help="Revert the last migration")

    args = parser.parse_args()

    # ensure flask commands know where to find the app
    os.environ["FLASK_APP"] = "app:create_app()"

    if args.command == "dev":
        run_dev()

    elif args.command == "db":
        match args.action:
            case "init":
                db_init()
            case "migrate":
                db_migrate()
            case "upgrade":
                db_upgrade()
            case "downgrade":
                db_downgrade()


if __name__ == "__main__":
    main()