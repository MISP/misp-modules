import json

from flask import session as sess
from sqlalchemy import desc

from app import db
from app.models import History, History_Tree, Session_db
from app.utils import isUUID


def get_session(sid):
    """Return a session by uuid"""
    return Session_db.query.filter_by(uuid=sid).first()


def get_history(page):
    """Return history"""
    histories_list = list()
    histories = History.query.order_by(desc(History.id)).paginate(
        page=page, per_page=20, max_per_page=50
    )
    for history in histories:
        session = Session_db.query.get(history.session_id)
        histories_list.append(session.history_json())
    return histories_list, histories.pages


def get_history_session():
    current_query = sess.get("current_query")
    loc_list = list()
    if current_query:
        # If current query have no children then don't display it
        # It's already save in history
        # Only parent-child tree structure is in flask session
        current_query_value = sess.get(current_query)
        if current_query_value:
            loc_list.append(current_query_value)
    for q in sess:
        if isUUID(q):
            # If query have no children then don't display it
            q_value = sess.get(q)
            if not q == current_query:
                loc_list.append(q_value)

    return loc_list


def get_current_query_history():
    current_query = sess.get("current_query")
    if current_query:
        current_query_value = sess.get(current_query)
        if current_query_value:
            return current_query_value
    return {}


def get_history_session_uuid(history_uuid):
    for q in sess:
        if isUUID(q):
            # If query have no children then don't display it
            q_value = sess.get(q)
            if q == history_uuid:
                return q_value
    return {}


def util_save_history(session):
    loc_dict = dict()
    loc_dict[session["uuid"]] = []

    if "children" in session and session["children"]:
        for child in session["children"]:
            loc_dict[session["uuid"]].append(util_save_history(child))
    return loc_dict


def save_history_core(sid):
    """Save the selected investigation's topology without duplicating queries."""
    if sid not in sess:
        return {"message": "Session not found", "toast_class": "danger-subtle"}
    session = sess[sid]
    topology = util_save_history(session)
    history_tree_db = History_Tree.query.filter_by(session_uuid=session["uuid"]).first()
    if not history_tree_db:
        db.session.add(History_Tree(session_uuid=session["uuid"], tree=json.dumps(topology)))
        message = "Investigation saved"
    elif json.loads(history_tree_db.tree) != topology:
        history_tree_db.tree = json.dumps(topology)
        message = "Saved tree updated"
    else:
        return {"message": "History already saved", "toast_class": "warning-subtle"}
    db.session.commit()
    return {"message": message, "toast_class": "success-subtle"}


def util_get_history_tree(child):
    loc_child = list(child.keys())[0]
    loc_session = get_session(loc_child)
    loc_json = loc_session.history_json()
    loc_json["children"] = list()
    if child[loc_child]:
        for s_child in child[loc_child]:
            loc_json["children"].append(util_get_history_tree(s_child))
    return loc_json


def get_history_tree():
    """Return all histories saved as tree"""
    histories_tree = History_Tree.query.order_by(desc(History_Tree.id))
    loc_dict = list()
    for history_tree in histories_tree:
        tree = json.loads(history_tree.tree)
        loc_session = get_session(history_tree.session_uuid)
        loc_json = loc_session.history_json()
        loc_json["children"] = list()
        for child in tree[history_tree.session_uuid]:
            loc_json["children"].append(util_get_history_tree(child))
        loc_dict.append(loc_json)
    return loc_dict


def get_history_tree_uuid(history_uuid):
    history_tree = History_Tree.query.filter_by(session_uuid=history_uuid).first()
    if history_tree:
        tree = json.loads(history_tree.tree)
        loc_session = get_session(history_tree.session_uuid)
        loc_json = loc_session.history_json()
        loc_json["children"] = list()
        for child in tree[history_tree.session_uuid]:
            loc_json["children"].append(util_get_history_tree(child))
        return loc_json
    return {}


def util_remove_node_session(node_uuid, parent):
    """Remove a descendant and its subtree, searching every sibling branch."""
    children = parent.get("children", [])
    for index, child in enumerate(children):
        if child["uuid"] == node_uuid:
            del children[index]
            return True
        if util_remove_node_session(node_uuid, child):
            return True
    return False


def remove_node_session(node_uuid, root_uuid=None):
    for root_id in list(sess):
        if not isUUID(root_id) or (root_uuid is not None and root_id != root_uuid):
            continue
        root = sess[root_id]
        if root["uuid"] == node_uuid:
            del sess[root_id]
            if sess.get("current_query") == root_id:
                sess.pop("current_query", None)
            return True
        if util_remove_node_session(node_uuid, root):
            # Reassign the root so nested changes persist in the Flask session.
            sess[root_id] = root
            sess.modified = True
            return True
    return False


def util_remove_node_tree(node_uuid, children):
    for index, child in enumerate(children):
        for uuid, descendants in child.items():
            if uuid == node_uuid:
                del children[index]
                return True
            if util_remove_node_tree(node_uuid, descendants):
                return True
    return False


def remove_node_tree(node_uuid, root_uuid=None):
    histories = History_Tree.query.order_by(desc(History_Tree.id))
    if root_uuid is not None:
        histories = histories.filter_by(session_uuid=root_uuid)
    for history_tree in histories:
        topology = json.loads(history_tree.tree)
        if history_tree.session_uuid == node_uuid:
            db.session.delete(history_tree)
            db.session.commit()
            return True
        children = topology.get(history_tree.session_uuid, [])
        if util_remove_node_tree(node_uuid, children):
            history_tree.tree = json.dumps(topology)
            db.session.commit()
            return True
    return False
