import json
from ..utils.utils import isUUID
from .. import db
from ..db_class.db import History,  Session_db, History_Tree
from .. import sess
from flask import session as sess
from sqlalchemy import desc



def get_session(sid):
    """Return a session by uuid"""
    return Session_db.query.filter_by(uuid=sid).first()



def get_history():
    """Return history"""
    histories_list = list()
    histories = History.query.order_by(desc(History.id))
    for history in histories:
        session = Session_db.query.get(history.session_id)
        histories_list.append(session.history_json())
    return histories_list


def util_set_flask_session(parent_id, loc_session, current_session):
    if parent_id == loc_session["uuid"]:
        loc_json = {
            "uuid": current_session.uuid,
            "modules": current_session.modules_list,
            "query": current_session.query,
            "input": current_session.input_query,
            "query_date": current_session.query_date.strftime('%Y-%m-%d')
        }
        loc_session["children"].append(loc_json)
        return True
    elif "children" in loc_session:
        return deep_explore(loc_session["children"], parent_id, current_session)

def deep_explore(session_dict, parent_id, current_session):
    for loc_session in session_dict:
        if not "children" in loc_session:
            loc_session["children"] = list()
        if util_set_flask_session(parent_id, loc_session, current_session):
            return True
    return False

def set_flask_session(current_session, parent_id):
    current_query = sess.get("current_query")
    if not current_query or current_query not in sess:
        loc_json = {
            "uuid": current_session.uuid,
            "modules": current_session.modules_list,
            "query": current_session.query,
            "input": current_session.input_query,
            "query_date": current_session.query_date.strftime('%Y-%m-%d')
        }

        sess["current_query"] = current_session.uuid
        sess[sess.get("current_query")] = loc_json
        sess[sess.get("current_query")]["children"] = list()
    else:
        # sess["uuid"]
        loc_session = sess.get(sess.get("current_query"))
        if not "children" in loc_session:
            loc_session["children"] = list()
        if not util_set_flask_session(parent_id, loc_session, current_session):
            sess["current_query"] = current_session.uuid

def get_history_session():
    current_query = sess.get("current_query")
    loc_list = list()
    if current_query:
        # If current query have no children then don't display it
        # It's already save in history
        # Only parent-child tree structure is in flask session
        current_query_value = sess.get(sess.get("current_query"))
        if current_query_value and current_query_value["children"]:
            loc_list.append(current_query_value)
    for q in sess:
        if isUUID(q):
            # If query have no children then don't display it
            q_value = sess.get(q)
            if q_value["children"]:
                if not q == current_query:
                    loc_list.append(q_value)

    return loc_list




def util_save_history(session):
    loc_dict = dict()
    loc_dict[session["uuid"]] = []

    if "children" in session and session["children"]:
        for child in session["children"]:
            loc_dict[session["uuid"]].append(util_save_history(child))
    return loc_dict


def save_history_core(sid):
    """Save history from session to db"""
    if sid in sess:
        session = sess.get(sid)
        # Doesn't already exist
        history_tree_db = History_Tree.query.filter_by(session_uuid=session["uuid"]).first()
        if not history_tree_db:
            if "children" in session and session["children"]:
                # Get all children before add to db
                loc_dict = util_save_history(session)
                h = History_Tree(
                    session_uuid = session["uuid"],
                    tree=json.dumps(loc_dict)
                )
                db.session.add(h)
                db.session.commit()
                return {"message": "History Save", 'toast_class': "success-subtle"}
            return {"message": "No children", 'toast_class': "warning-subtle"}
        # Save same session but with new value
        elif not json.loads(history_tree_db.tree) == session:
            if "children" in session and session["children"]:
                # Get all children before add to db
                loc_dict = util_save_history(session)
                history_tree_db.tree = json.dumps(loc_dict)
                db.session.commit()
                return {"message": "History updated", 'toast_class': "success-subtle"}
        return {"message": "History already saved", 'toast_class': "warning-subtle"}
    return {"message": "Session not found", 'toast_class': "danger-subtle"}



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
        print(history_tree.session_uuid)
        loc_session = get_session(history_tree.session_uuid)
        loc_json = loc_session.history_json()
        loc_json["children"] = list()
        for child in tree[history_tree.session_uuid]:
            loc_json["children"].append(util_get_history_tree(child))
        loc_dict.append(loc_json)
    return loc_dict
