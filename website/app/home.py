import ast
import json
from flask import Blueprint, render_template, request, jsonify, session as sess
from flask_login import current_user
import requests
from . import session_class as SessionModel
from . import home_core as HomeModel
from .utils.utils import admin_user_active
from .external_tools import external_tools_core as ToolModel

home_blueprint = Blueprint(
    'home',
    __name__,
    template_folder='templates',
    static_folder='static'
)


@home_blueprint.route("/", methods=["GET", "POST"])
def home():
    try:
        del sess["query"]
    except:
        pass
    sess["admin_user"] = bool(admin_user_active())
    if "query" in request.args:
        sess["query"] = ast.literal_eval(request.args.get("query"))
    if "query" in request.form:
        sess["query"] = json.loads(request.form.get("query"))
    return render_template("home.html")

@home_blueprint.route("/get_query", methods=['GET', 'POST'])
def get_query():
    """Get result from flowintel"""
    if "query" in sess:
        return {"query": sess.get("query")}
    return {"message": "No query"}

@home_blueprint.route("/home/<sid>", methods=["GET", "POST"])
def home_query(sid):
    try:
        del sess["query"]
    except:
        pass
    sess["admin_user"] = admin_user_active()
    if "query" in request.args:
        sess["query"] = [request.args.get("query")]
        return render_template("home.html", query=query, sid=sid)
    return render_template("404.html")

@home_blueprint.route("/query/<sid>")
def query(sid):
    sess["admin_user"] = admin_user_active()
    session = HomeModel.get_session(sid)
    flag=False
    modules_list = []
    if session:
        flag = True
        query_loc = json.loads(session.query_enter)
        modules_list = json.loads(session.modules_list)
    else:
        for s in SessionModel.sessions:
            if s.uuid == sid:
                flag = True
                query_loc = s.query
                session=s
                modules_list = session.modules_list
    query_str = ", ".join(query_loc)
    if len(query_str) > 40:
        query_str = query_str[0:40] + "..."
    if flag:
        return render_template("query.html", 
                               query=query_loc, 
                               query_str=query_str,
                               sid=sid, 
                               input_query=session.input_query, 
                               modules=modules_list, 
                               query_date=session.query_date.strftime('%Y-%m-%d %H:%M'))
    return render_template("404.html")



@home_blueprint.route("/get_query_info/<sid>")
def get_query_info(sid):
    """Return info for a query"""
    session = HomeModel.get_session(sid)
    flag=False
    if session:
        flag = True
        query_loc = json.loads(session.query_enter)
        modules_list = json.loads(session.modules_list)
    else:
        for s in SessionModel.sessions:
            if s.uuid == sid:
                flag = True
                query_loc = s.query
                modules_list = s.modules_list
                session=s
    if flag:
        loc_dict = {
            "query": query_loc,
            "input_query": session.input_query,
            "modules": modules_list, 
            "query_date": session.query_date.strftime('%Y-%m-%d %H:%M')
            }
        return loc_dict
    return {"message": "Session not found"}, 404


@home_blueprint.route("/get_modules")
def get_modules():
    """Return all modules available"""
    res = HomeModel.get_modules()

    if "message" in res:
        return res, 404
    return res, 200

@home_blueprint.route("/get_list_misp_attributes")
def get_list_misp_attributes():
    """Return all misp attributes for input and output"""
    res = HomeModel.get_list_misp_attributes()

    if "message" in res:
        return res, 404
    return res, 200

@home_blueprint.route("/run_modules", methods=['POST'])
def run_modules():
    """Run modules"""
    if "query" in request.json:
        if "input" in request.json and request.json["input"]:
            if "modules" in request.json:
                if "query_as_same" in request.json:
                    session = SessionModel.Session_class(request.json, query_as_same=True, parent_id=request.json["parent_id"])
                elif "query_as_params" in request.json:
                    session = SessionModel.Session_class(request.json, query_as_same=True, parent_id=request.json["same_query_id"])
                else:
                    session = SessionModel.Session_class(request.json)
                HomeModel.set_flask_session(session, request.json["parent_id"])
                session.start()
                SessionModel.sessions.append(session)
                return jsonify(session.status()), 201
            return {"message": "Need a module type"}, 400
        return {"message": "Need an input (misp attribute)"}, 400
    return {"message": "Need to type something"}, 400

@home_blueprint.route("/status/<sid>")
def status(sid):
    """Status of <sid> queue"""
    sess = HomeModel.get_session(sid)
    if sess:
        return jsonify(HomeModel.get_status_db(sess))
    else:
        for s in SessionModel.sessions:
            if s.uuid == sid:
                return jsonify(s.status())
    return jsonify({'message': 'Scan session not found'}), 404

@home_blueprint.route("/result/<sid>")
def result(sid):
    """Result of <sid> queue"""
    sess = HomeModel.get_session(sid)
    if sess:
        return jsonify(HomeModel.get_result_db(sess))
    else:
        for s in SessionModel.sessions:
            if s.uuid == sid:
                return jsonify(s.get_result())
    return jsonify({'message': 'Scan session not found'}), 404



@home_blueprint.route("/download/<sid>")
def download(sid):
    """Download a module result as json"""
    sess = HomeModel.get_session(sid)
    if "module" in request.args:
        if sess:
            loc = json.loads(sess.result)
            module = request.args.get("module")
            query = request.args.get("query")
            if query in loc:
                if module in loc[query]:
                    return jsonify(loc[query][module]), 200, {'Content-Disposition': f'attachment; filename={query}-{module}.json'}
            return {"message": "Module not in result", "toast_class": "danger-subtle"}, 400
        else:
            for s in SessionModel.sessions:
                if s.uuid == sid:
                    module = request.args.get("module")
                    if module in s.result:
                        return jsonify(s.result[module]), 200, {'Content-Disposition': f'attachment; filename={s.query}-{module}.json'}
                    return {"message": "Module not in result ", "toast_class": "danger-subtle"}, 400
        return {"message": "Session not found", 'toast_class': "danger-subtle"}, 404
    return {"message": "Need to pass a module", "toast_class": "warning-subtle"}, 400




@home_blueprint.route("/modules_config")
def modules_config():
    """List all modules for configuration"""
    sess["admin_user"] = admin_user_active()
    flag = True
    if sess.get("admin_user"):
        if not current_user.is_authenticated:
            flag = False
    if flag:
        return render_template("modules_config.html")
    return render_template("404.html")
    
    
@home_blueprint.route("/modules_config_data")
def modules_config_data():
    """List all modules for configuration"""
    sess["admin_user"] = admin_user_active()
    flag = True
    if sess.get("admin_user"):
        if not current_user.is_authenticated:
            flag = False
    if flag:
        modules_config = HomeModel.get_modules_config()
        return modules_config, 200
    return {"message": "Permission denied"}, 403
    

@home_blueprint.route("/change_config", methods=["POST"])
def change_config():
    """Change configuation for a module"""
    sess["admin_user"] = admin_user_active()
    flag = True
    if sess.get("admin_user"):
        if not current_user.is_authenticated:
            flag = False  
    if flag:
        if "module_name" in request.json["result_dict"]:
            res = HomeModel.change_config_core(request.json["result_dict"])
            if res:
                return {'message': 'Config changed', 'toast_class': "success-subtle"}, 200
            return {'message': 'Something went wrong', 'toast_class': "danger-subtle"}, 400
        return {'message': 'Need to pass "module_name"', 'toast_class': "warning-subtle"}, 400
    return {'message': 'Permission denied', 'toast_class': "danger-subtle"}, 403

@home_blueprint.route("/change_status", methods=["GET"])
def change_status():
    """Change the status of a module, active or unactive"""
    sess["admin_user"] = admin_user_active()
    flag = True
    if sess.get("admin_user"):
        if not current_user.is_authenticated:
            flag = False
    # if admin is active and user is logon or if admin is not active
    if flag:
        if "module_id" in request.args:
            res = HomeModel.change_status_core(request.args.get("module_id"))
            if res:
                return {'message': 'Module status changed', 'toast_class': "success-subtle"}, 200
            return {'message': 'Something went wrong', 'toast_class': "danger-subtle"}, 400
        return {'message': 'Need to pass "module_id"', 'toast_class': "warning-subtle"}, 400
    return {'message': 'Permission denied', 'toast_class': "danger-subtle"}, 403


@home_blueprint.route("/submit_external_tool", methods=["GET", "POST"])
def submit_external_tool():
    """Submit result to an external tool"""
    sess["admin_user"] = admin_user_active()
    flag = True
    if sess.get("admin_user"):
        if not current_user.is_authenticated:
            flag = False
    # if admin is active and user is logon or if admin is not active
    if flag:
        ext = ToolModel.get_tool(request.json["external_tool_id"])
        if HomeModel.submit_external_tool(request.json["results"], ext):
            return {'message': f'Send to {ext.name} successfully', 'toast_class': "success-subtle"}, 200
        return {'message': 'Something went wrong', 'toast_class': "danger-subtle"}, 400
    return {'message': 'Permission denied', 'toast_class': "danger-subtle"}, 403
