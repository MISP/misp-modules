import json
from flask import Blueprint, render_template, request, jsonify, redirect, session as sess
from ..utils.utils import admin_user_active
from . import external_tools_core as ToolModel
from .form import ExternalToolForm

external_tools_blueprint = Blueprint(
    'external_tools',
    __name__,
    template_folder='templates',
    static_folder='static'
)


@external_tools_blueprint.route("/external_tools", methods=["GET"])
def external_tools():
    """View config page for external tools"""
    sess["admin_user"] = admin_user_active()
    return render_template("external_tools/external_tools_index.html")

@external_tools_blueprint.route("/external_tools/list", methods=['GET'])
def analyzers_data():
    """List all tools"""
    return [tool.to_json() for tool in ToolModel.get_tools()]

@external_tools_blueprint.route("/add_external_tool", methods=['GET', 'POST'])
def add_external_tool():
    """Add a new tool"""
    form = ExternalToolForm()
    if form.validate_on_submit():
        if ToolModel.add_tool_core(ToolModel.form_to_dict(form)):
            return redirect("/external_tools")
    return render_template("external_tools/add_external_tool.html", form=form)


@external_tools_blueprint.route("/external_tools/<tid>/delete_tool", methods=['GET', 'POST'])
def delete_tool(tid):
    """Delete a tool"""
    if ToolModel.get_tool(tid):
        if ToolModel.delete_tool(tid):
            return {"message": "Tool deleted", "toast_class": "success-subtle"}, 200
        return {"message": "Error tool deleted", 'toast_class': "danger-subtle"}, 400
    return {"message": "Tool not found", 'toast_class': "danger-subtle"}, 404



@external_tools_blueprint.route("/external_tools/change_status", methods=['GET', 'POST'])
def change_status():
    """Active or disabled a tool"""
    if "tool_id" in request.args:
        res = ToolModel.change_status_core(request.args.get("tool_id"))
        if res:
            return {'message': 'Tool status changed', 'toast_class': "success-subtle"}, 200
        return {'message': 'Something went wrong', 'toast_class': "danger-subtle"}, 400
    return {'message': 'Need to pass "tool_id"', 'toast_class': "warning-subtle"}, 400


@external_tools_blueprint.route("/external_tools/change_config", methods=['GET', 'POST'])
def change_config():
    """Change configuration for a tool"""
    if "tool_id" in request.json["result_dict"] and request.json["result_dict"]["tool_id"]:
        if "tool_name" in request.json["result_dict"] and request.json["result_dict"]["tool_name"]:
            if "tool_url" in request.json["result_dict"] and request.json["result_dict"]["tool_url"]:
                res = ToolModel.change_config_core(request.json["result_dict"])
                if res:
                    return {'message': 'Config changed', 'toast_class': "success-subtle"}, 200
                return {'message': 'Something went wrong', 'toast_class': "danger-subtle"}, 400
            return {'message': 'Need to pass "tool_url"', 'toast_class': "warning-subtle"}, 400
        return {'message': 'Need to pass "tool_name"', 'toast_class': "warning-subtle"}, 400
    return {'message': 'Need to pass "tool_id"', 'toast_class': "warning-subtle"}, 400


