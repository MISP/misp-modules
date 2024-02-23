import json
from flask import Flask, Blueprint, render_template, request, jsonify
from . import home_core as HomeModel
from . import session as SessionModel

home_blueprint = Blueprint(
    'home',
    __name__,
    template_folder='templates',
    static_folder='static'
)


@home_blueprint.route("/")
def home():
    if "query" in request.args:
        return render_template("home.html", query=request.args.get("query"))
    return render_template("home.html")

@home_blueprint.route("/home/<sid>", methods=["GET", "POST"])
def home_query(sid):
    if "query" in request.args:
        query = request.args.get("query")
        return render_template("home.html", query=query, sid=sid)
    return render_template("404.html")

@home_blueprint.route("/query/<sid>")
def query(sid):
    session = HomeModel.get_session(sid)
    flag=False
    if session:
        flag = True
        query_loc = session.query_enter
    else:
        for s in SessionModel.sessions:
            if s.uuid == sid:
                flag = True
                query_loc = s.query
                session=s
    if flag:
        return render_template("query.html", 
                               query=query_loc, 
                               sid=sid, 
                               input_query=session.input_query, 
                               modules=json.loads(session.modules_list), 
                               query_date=session.query_date.strftime('%Y-%m-%d %H:%M'))
    return render_template("404.html")



@home_blueprint.route("/get_query_info/<sid>")
def get_query_info(sid):
    """Return info for a query"""
    session = HomeModel.get_session(sid)
    flag=False
    if session:
        flag = True
        query_loc = session.query_enter
    else:
        for s in SessionModel.sessions:
            if s.uuid == sid:
                flag = True
                query_loc = s.query
                session=s
    if flag:
        loc_dict = {
            "query": query_loc,
            "input_query": session.input_query,
            "modules": json.loads(session.modules_list), 
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
            if module in loc:
                return jsonify(loc[module]), 200, {'Content-Disposition': f'attachment; filename={sess.query_enter.replace(".", "_")}-{module}.json'}
            return {"message": "Module not in result", "toast_class": "danger-subtle"}, 400
        else:
            for s in SessionModel.sessions:
                if s.uuid == sid:
                    module = request.args.get("module")
                    if module in s.result:
                        return jsonify(s.result[module]), 200, {'Content-Disposition': f'attachment; filename={s.query}-{module}.json'}
                    return {"message": "Module not in result", "toast_class": "danger-subtle"}, 400
        return {"message": "Session not found", 'toast_class': "danger-subtle"}, 404
    return {"message": "Need to pass a module", "toast_class": "warning-subtle"}, 400





@home_blueprint.route("/modules_config")
def modules_config():
    """List all modules for configuration"""

    return render_template("modules_config.html")

@home_blueprint.route("/modules_config_data")
def modules_config_data():
    """List all modules for configuration"""

    modules_config = HomeModel.get_modules_config()
    return modules_config, 200


@home_blueprint.route("/change_config", methods=["POST"])
def change_config():
    """Change configuation for a module"""
    if "module_name" in request.json["result_dict"]:
        res = HomeModel.change_config_core(request.json["result_dict"])
        if res:
            return {'message': 'Config changed', 'toast_class': "success-subtle"}, 200
        return {'message': 'Something went wrong', 'toast_class': "danger-subtle"}, 400
    return {'message': 'Need to pass "module_name"', 'toast_class': "warning-subtle"}, 400

@home_blueprint.route("/change_status", methods=["GET"])
def change_status():
    """Change the status of a module, active or unactive"""
    if "module_id" in request.args:
        res = HomeModel.change_status_core(request.args.get("module_id"))
        if res:
            return {'message': 'Module status changed', 'toast_class': "success-subtle"}, 200
        return {'message': 'Something went wrong', 'toast_class': "danger-subtle"}, 400
    return {'message': 'Need to pass "module_id"', 'toast_class': "warning-subtle"}, 400

