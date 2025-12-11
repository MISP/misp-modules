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


# CLI commands using argparse
def main():
    parser = argparse.ArgumentParser(description="MISP Modules Website CLI")
    parser.add_argument(
        "--dev",
        action="store_true",
        help="Run misp-modules and the website in debug mode",
    )
    parser.add_argument(
        "--db-init", action="store_true", help="Initialize the database"
    )
    parser.add_argument(
        "--db-migrate", action="store_true", help="Generate a new database migration"
    )
    parser.add_argument(
        "--db-upgrade", action="store_true", help="Apply database migrations"
    )
    parser.add_argument(
        "--db-downgrade",
        action="store_true",
        help="Revert the latest database migration",
    )
    args = parser.parse_args()

    # Set FLASK_APP for flask db commands
    os.environ["FLASK_APP"] = "app:create_app()"

    if args.dev:
        # Import utils to set development mode
        from app.utils import utils as utils_module

        # Only the FIRST process (the parent) should launch misp‑modules
        if os.getenv("WERKZEUG_RUN_MAIN") != "true":
            print("Starting misp-modules...")

            modules_env = os.environ.copy()
            modules_env.pop("VIRTUAL_ENV", None)

            misp_proc = subprocess.Popen(
                ["poetry", "run", "misp-modules", "-l", "127.0.0.1"],
                cwd="..",
                env=modules_env,
            )
            time.sleep(5)

        # Import utils after app creation to avoid circular imports
        from app.utils import IS_DEVELOPMENT, gen_admin_password
        from app.utils.init_modules import create_modules_db

        IS_DEVELOPMENT = True  # Set global variable in utils.py

        try:
            print("Starting website in debug mode...")
            app.run(
                host=app.config["FLASK_URL"],
                port=app.config["FLASK_PORT"],
                debug=IS_DEVELOPMENT,
            )
        finally:
            # Only parent created misp_proc
            if os.getenv("WERKZEUG_RUN_MAIN") != "true":
                misp_proc.terminate()

    elif args.db_init:
        # Use the already-created app instance
        from app.utils import gen_admin_password
        from app.utils.init_modules import create_modules_db

        with app.app_context():
            db.create_all()
            create_modules_db()
            gen_admin_password()
            print("Database initialized.")
    elif args.db_migrate:
        # Run flask db migrate without creating app
        subprocess.run(["flask", "db", "migrate"])
    elif args.db_upgrade:
        # Run flask db upgrade without creating app
        subprocess.run(["flask", "db", "upgrade"])
    elif args.db_downgrade:
        # Run flask db downgrade without creating app
        subprocess.run(["flask", "db", "downgrade"])
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
