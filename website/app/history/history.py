import json
from flask import Flask, Blueprint, render_template, request, jsonify
from . import history_core as HistoryModel

history_blueprint = Blueprint(
    'history',
    __name__,
    template_folder='templates',
    static_folder='static'
)


@history_blueprint.route("/history", methods=["GET"])
def history():
    """View all history"""
    return render_template("history.html")

@history_blueprint.route("/get_history", methods=["GET"])
def get_history():
    """Get all history"""
    page = request.args.get('page', 1, type=int)
    histories, nb_pages = HistoryModel.get_history(page)
    return {"history": histories, "nb_pages": nb_pages}

@history_blueprint.route("/history_session", methods=["GET"])
def history_session():
    """View all history"""
    return render_template("history_session.html", tree_view=False)

@history_blueprint.route("/get_history_session", methods=["GET"])
def get_history_session():
    """Get all history"""
    histories = HistoryModel.get_history_session()
    if histories:
        return histories
    return {}

@history_blueprint.route("/save_history/<sid>", methods=["GET"])
def save_history(sid):
    return HistoryModel.save_history_core(sid)


@history_blueprint.route("/history_tree", methods=["GET"])
def history_tree():
    """View all history"""
    return render_template("history_session.html", tree_view=True)

@history_blueprint.route("/get_history_tree", methods=["GET"])
def get_history_tree():
    """Get all history"""
    histories = HistoryModel.get_history_tree()
    if histories:
        return histories
    return {}

@history_blueprint.route("/get_history_tree/<sid>", methods=["GET"])
def get_history_tree_uuid(sid):
    """Get all history"""
    histories = HistoryModel.get_history_tree_uuid(sid)
    if histories:
        return histories
    return {}

@history_blueprint.route("/get_history_session/<sid>", methods=["GET"])
def get_history_session_uuid(sid):
    """Get all history"""
    histories = HistoryModel.get_history_session_uuid(sid)
    if histories:
        return histories
    return {}

@history_blueprint.route("/history/remove_node_session/<sid>", methods=["GET"])
def remove_node_session(sid):
    HistoryModel.remove_node_session(sid)
    return {"message": "Node deleted", "toast_class": "success-subtle"}

@history_blueprint.route("/history/remove_node_tree/<sid>", methods=["GET"])
def remove_node_tree(sid):
    HistoryModel.remove_node_tree(sid)
    return {"message": "Node deleted", "toast_class": "success-subtle"}