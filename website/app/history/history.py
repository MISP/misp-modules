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
    histories = HistoryModel.get_history()
    return histories

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