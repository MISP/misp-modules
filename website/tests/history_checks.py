"""Regression checks for session/saved branch mutations behind the history UI."""
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import preview_server  # Make the website package importable without a module daemon.
from history_samples import SAMPLE_PATHS


class HistoryMutationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = TemporaryDirectory(prefix="misp-history-")
        from flask import Flask
        from app import db
        from app.history.history import history_blueprint
        from app.home import home_blueprint
        cls.app = Flask(__name__)
        cls.app.config.update(SECRET_KEY="local-history-test", SQLALCHEMY_DATABASE_URI=f"sqlite:///{Path(cls.directory.name) / 'history.sqlite'}")
        db.init_app(cls.app)
        cls.app.register_blueprint(history_blueprint)
        cls.app.register_blueprint(home_blueprint)
        with cls.app.app_context():
            db.create_all()

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        self.client = self.app.test_client()
        from history_samples import seed_history_samples
        with self.app.test_request_context():
            seed_history_samples('saved')
        with self.client.session_transaction() as session:
            from copy import deepcopy
            for root in SAMPLE_PATHS:
                session[root['uuid']] = deepcopy(root)
            session['current_query'] = SAMPLE_PATHS[0]['uuid']

    def test_session_later_sibling_is_removed_without_losing_root(self):
        root = SAMPLE_PATHS[0]
        child = root['children'][1]['children'][0]
        response = self.client.get(f"/history/remove_node_session/{child['uuid']}?root_id={root['uuid']}")
        self.assertEqual(response.status_code, 200)
        data = self.client.get('/get_history_session').get_json()
        self.assertEqual(len(data), 3)
        remaining = next(node for node in data if node['uuid'] == root['uuid'])
        self.assertEqual(len(remaining['children']), 2)
        self.assertEqual(remaining['children'][1]['children'], [])
        self.assertEqual(remaining['children'][0], root['children'][0])

    def test_saved_removal_finds_later_root_and_keeps_other_roots(self):
        root = SAMPLE_PATHS[0]
        child = root['children'][1]
        # No scope is also supported for existing clients; do not stop at the
        # first (newer) saved tree that does not contain the requested query.
        response = self.client.get(f"/history/remove_node_tree/{child['uuid']}")
        self.assertEqual(response.status_code, 200)
        roots = self.client.get('/get_history_tree').get_json()
        self.assertEqual(len(roots), 3)
        modified = next(node for node in roots if node['uuid'] == root['uuid'])
        self.assertEqual([node['uuid'] for node in modified['children']], [root['children'][0]['uuid']])
        self.assertEqual(len(self.client.get('/get_history_session').get_json()[0]['children']), 2)
        self.assertEqual(self.client.get('/get_query_info/' + child['uuid']).status_code, 200)

    def test_scope_rejects_query_from_another_investigation(self):
        child = SAMPLE_PATHS[0]['children'][0]
        other = SAMPLE_PATHS[1]['uuid']
        for mode, endpoint in [('session', '/get_history_session'), ('tree', '/get_history_tree')]:
            before = self.client.get(endpoint).get_json()
            response = self.client.get(f"/history/remove_node_{mode}/{child['uuid']}?root_id={other}")
            self.assertEqual(response.status_code, 404)
            self.assertEqual(self.client.get(endpoint).get_json(), before)

    def test_root_removal_clears_current_session_and_preserves_saved_tree(self):
        root = SAMPLE_PATHS[0]['uuid']
        self.assertEqual(self.client.get(f'/history/remove_node_session/{root}?root_id={root}').status_code, 200)
        self.assertEqual(len(self.client.get('/get_history_session').get_json()), 2)
        self.assertEqual(self.client.get('/get_current_query_history').get_json(), {})
        self.assertEqual(len(self.client.get('/get_history_tree').get_json()), 3)

    def test_session_root_at_first_key_can_be_removed(self):
        root = SAMPLE_PATHS[0]
        with self.client.session_transaction() as session:
            session.clear()
            session[root['uuid']] = root
        self.assertEqual(self.client.get('/history/remove_node_session/' + root['uuid']).status_code, 200)
        self.assertEqual(self.client.get('/get_history_session').get_json(), {})

    def test_save_is_idempotent_and_updates_changed_topology(self):
        root = SAMPLE_PATHS[0]
        self.assertEqual(self.client.get('/save_history/' + root['uuid']).get_json()['toast_class'], 'warning-subtle')
        self.client.get('/history/remove_node_session/' + root['children'][1]['uuid'])
        self.assertEqual(self.client.get('/save_history/' + root['uuid']).get_json()['message'], 'Saved tree updated')
        saved = self.client.get('/get_history_tree/' + root['uuid']).get_json()
        self.assertEqual(len(saved['children']), 1)
        self.assertEqual(self.client.get('/save_history/' + root['uuid']).get_json()['toast_class'], 'warning-subtle')


if __name__ == '__main__':
    unittest.main()
