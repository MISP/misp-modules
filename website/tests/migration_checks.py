"""Exercise real SQLite upgrades and the external-tools endpoint on legacy data."""

import os
import subprocess
import sys
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from flask import Flask
from flask_migrate import Migrate, stamp, upgrade
from sqlalchemy import inspect, text
from sqlalchemy.exc import OperationalError

from app import db
from app.external_tools.external_tools import external_tools_blueprint


WEBSITE = Path(__file__).resolve().parents[1]
PREVIOUS_HEAD = "206e0e808b0c"
REPAIR_HEAD = "7f2a9c4d8e61"


class DatabaseMigrationChecks(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory(prefix="misp-migration-")
        self.addCleanup(self.directory.cleanup)
        self.database = Path(self.directory.name) / "website.sqlite"
        self.app = Flask(__name__)
        self.app.config.update(
            TESTING=True,
            SECRET_KEY="migration-regression-test",
            SQLALCHEMY_DATABASE_URI=f"sqlite:///{self.database}",
        )
        db.init_app(self.app)
        Migrate(self.app, db, directory=str(WEBSITE / "migrations"), render_as_batch=True)
        self.app.register_blueprint(external_tools_blueprint)
        self.context = self.app.app_context()
        self.context.push()
        self.addCleanup(self.context.pop)
        self.addCleanup(db.engine.dispose)
        self.addCleanup(db.session.remove)
        db.create_all()
        with db.engine.begin() as connection:
            connection.execute(text(
                "INSERT INTO external_tools (name, url, api_key, is_active) "
                "VALUES ('saved tool', 'https://example.org', 'saved-key', 1)"
            ))
            connection.execute(text("INSERT INTO history (session_id) VALUES (42)"))
            connection.execute(text(
                "INSERT INTO session_db (id, uuid, result) "
                "VALUES (42, 'saved-query', '{}')"
            ))

    def remove_api_key(self):
        with db.engine.begin() as connection:
            connection.execute(text("DROP INDEX ix_external_tools_api_key"))
            connection.execute(text("ALTER TABLE external_tools DROP COLUMN api_key"))

    def assert_repaired(self, expected_key=None):
        response = self.app.test_client().get("/external_tools/list")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), [{
            "id": 1, "name": "saved tool", "url": "https://example.org",
            "api_key": expected_key, "is_active": True,
        }])
        self.assertIn("ix_external_tools_api_key", {
            index["name"] for index in inspect(db.engine).get_indexes("external_tools")
        })
        with db.engine.connect() as connection:
            self.assertEqual(connection.scalar(text("SELECT session_id FROM history")), 42)
            self.assertEqual(connection.scalar(text("SELECT result FROM session_db WHERE uuid = 'saved-query'")), "{}")
            self.assertEqual(connection.scalar(text("SELECT version_num FROM alembic_version")), REPAIR_HEAD)

    def run_cli(self, *arguments, script=None):
        env = os.environ.copy()
        env.update(
            SECRET_KEY="migration-cli-test",
            DATABASE_URI=f"sqlite:///{self.database}",
        )
        # Run outside the checkout: installed mmw and service invocations must
        # find the shipped migrations without relying on the working directory.
        return subprocess.run(
            [sys.executable, str(script or WEBSITE / "main.py"), "db", *arguments],
            cwd=self.directory.name,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_repairs_missing_column_even_when_original_migration_is_stamped(self):
        self.remove_api_key()
        stamp(revision=PREVIOUS_HEAD)
        with self.assertRaisesRegex(OperationalError, "no such column: external_tools.api_key"):
            self.app.test_client().get("/external_tools/list")
        db.session.remove()
        upgrade()
        self.assert_repaired()
        upgrade()
        self.assert_repaired()

    def test_upgrade_from_before_original_api_key_migration(self):
        self.remove_api_key()
        stamp(revision="3a631d400f60")
        upgrade()
        self.assert_repaired()

    def test_upgrade_unversioned_create_all_database(self):
        self.remove_api_key()
        upgrade()
        self.assert_repaired()

    def test_repairs_index_without_changing_saved_key(self):
        with db.engine.begin() as connection:
            connection.execute(text("DROP INDEX ix_external_tools_api_key"))
        stamp(revision=PREVIOUS_HEAD)
        upgrade()
        self.assert_repaired("saved-key")

    def test_current_schema_and_downgrade_preserve_api_keys(self):
        stamp(revision=PREVIOUS_HEAD)
        upgrade()
        self.assert_repaired("saved-key")
        result = self.run_cli("downgrade")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with db.engine.connect() as connection:
            self.assertEqual(connection.scalar(text("SELECT api_key FROM external_tools")), "saved-key")
            self.assertEqual(connection.scalar(text("SELECT version_num FROM alembic_version")), PREVIOUS_HEAD)
        upgrade()
        self.assert_repaired("saved-key")

    def test_cli_upgrade_finds_migrations_outside_website(self):
        self.remove_api_key()
        stamp(revision=PREVIOUS_HEAD)
        result = self.run_cli("upgrade")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_repaired()

    def test_cli_failure_does_not_advance_revision_and_can_be_retried(self):
        self.remove_api_key()
        stamp(revision=PREVIOUS_HEAD)
        # SQLite index names are database-wide. A conflicting index exercises
        # a real DDL failure after the column has been successfully added.
        with db.engine.begin() as connection:
            connection.execute(text("CREATE INDEX ix_external_tools_api_key ON module (name)"))
        result = self.run_cli("upgrade")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("already exists", result.stderr)
        with db.engine.begin() as connection:
            self.assertEqual(connection.scalar(text("SELECT version_num FROM alembic_version")), PREVIOUS_HEAD)
            connection.execute(text("DROP INDEX ix_external_tools_api_key"))
        result = self.run_cli("upgrade")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_repaired()

    def test_installed_wheel_contains_and_runs_migrations(self):
        self.remove_api_key()
        stamp(revision=PREVIOUS_HEAD)
        build = subprocess.run(
            [sys.executable, "-c",
             "from poetry.core.masonry.api import build_wheel; "
             "import sys; build_wheel(sys.argv[1])", self.directory.name],
            cwd=WEBSITE, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        wheel = next(Path(self.directory.name).glob("*.whl"))
        installed = Path(self.directory.name) / "installed"
        with zipfile.ZipFile(wheel) as archive:
            archive.extractall(installed)
        result = self.run_cli("upgrade", script=installed / "main.py")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_repaired()


if __name__ == "__main__":
    unittest.main()
