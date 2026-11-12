from flask import Blueprint, redirect, render_template, request, url_for
from flask import session as sess
from flask_login import current_user

from app.utils import admin_user_active

from . import external_tools_core as ToolModel
from .form import ExternalToolForm

external_tools_blueprint = Blueprint(
    "external_tools", __name__, template_folder="templates", static_folder="static"
)


@external_tools_blueprint.before_request
def authorize_tool_management():
    """Apply the same optional-admin policy as module configuration."""
    sess["admin_user"] = admin_user_active()
    if request.endpoint not in {
        "external_tools.add_external_tool",
        "external_tools.delete_tool",
        "external_tools.change_status",
        "external_tools.change_config",
    }:
        return None
    if sess["admin_user"] and not current_user.is_authenticated:
        if request.endpoint == "external_tools.add_external_tool":
            return redirect(url_for("account.login", next=request.path))
        return {"message": "Permission denied", "toast_class": "danger-subtle"}, 403


@external_tools_blueprint.route("/external_tools", methods=["GET"])
def external_tools():
    """View config page for external tools"""
    sess["admin_user"] = admin_user_active()
    return render_template("external_tools/external_tools_index.html")


@external_tools_blueprint.route("/external_tools/list", methods=["GET"])
def analyzers_data():
    """List all tools"""
    return [tool.to_json() for tool in ToolModel.get_tools()]


@external_tools_blueprint.route("/add_external_tool", methods=["GET", "POST"])
def add_external_tool():
    """Add a new tool"""
    form = ExternalToolForm()
    if form.validate_on_submit():
        if ToolModel.add_tool_core(ToolModel.form_to_dict(form)):
            return redirect("/external_tools")
    return render_template("external_tools/add_external_tool.html", form=form)


@external_tools_blueprint.route("/external_tools/<tid>/delete_tool", methods=["POST"])
def delete_tool(tid):
    """Delete a tool"""
    if ToolModel.get_tool(tid):
        if ToolModel.delete_tool(tid):
            return {"message": "Tool deleted", "toast_class": "success-subtle"}, 200
        return {"message": "Error tool deleted", "toast_class": "danger-subtle"}, 400
    return {"message": "Tool not found", "toast_class": "danger-subtle"}, 404


@external_tools_blueprint.route("/external_tools/change_status", methods=["POST"])
def change_status():
    """Active or disabled a tool"""
    if "tool_id" in request.args:
        res = ToolModel.change_status_core(request.args.get("tool_id"))
        if res:
            return {
                "message": "Tool status changed",
                "toast_class": "success-subtle",
            }, 200
        return {"message": "Something went wrong", "toast_class": "danger-subtle"}, 400
    return {"message": 'Need to pass "tool_id"', "toast_class": "warning-subtle"}, 400


@external_tools_blueprint.route("/external_tools/change_config", methods=["POST"])
def change_config():
    """Change configuration for a tool"""
    payload = request.get_json(silent=True)
    values = payload.get("result_dict") if isinstance(payload, dict) else None
    if not isinstance(values, dict):
        return {
            "message": 'Need to pass "result_dict"',
            "toast_class": "warning-subtle",
        }, 400
    for field in ("tool_id", "tool_name", "tool_url"):
        if not values.get(field):
            return {
                "message": f'Need to pass "{field}"',
                "toast_class": "warning-subtle",
            }, 400
    # Credentials are write-only. Missing or empty means keep the saved key.
    if "tool_api_key" in values and (
        not isinstance(values["tool_api_key"], str) or len(values["tool_api_key"]) > 60
    ):
        return {
            "message": "API key must be a string of at most 60 characters",
            "toast_class": "warning-subtle",
        }, 400
    if ToolModel.change_config_core(values):
        return {"message": "Config changed", "toast_class": "success-subtle"}, 200
    return {"message": "Something went wrong", "toast_class": "danger-subtle"}, 400
