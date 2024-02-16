import json
from .utils.utils import query_get_module, isUUID
from . import db
from .db_class.db import History, Module, Config, Module_Config, Session_db, History_Tree
from flask import session as sess
from sqlalchemy import desc


def get_module(mid):
    """Return a module by id"""
    return Module.query.get(mid)

def get_module_by_name(name):
    """Return a module by name"""
    return Module.query.filter_by(name=name).first()

def get_config(cid):
    """Return a config by id"""
    return Config.query.get(cid)

def get_config_by_name(name):
    """Return a config by name"""
    return Config.query.filter_by(name=name).first()

def get_module_config_module(mid):
    """Return a moudle_config by module id"""
    return Module_Config.query.filter_by(module_id=mid).all()

def get_module_config_both(mid, cid):
    """Return a moudle_config by module id and config id"""
    return Module_Config.query.filter_by(module_id=mid, config_id=cid).first()

def get_session(sid):
    """Return a session by uuid"""
    return Session_db.query.filter_by(uuid=sid).first()

def get_modules():
    """Return all modules for expansion and hover types"""
    res = query_get_module()
    if not "message" in res:
        loc_list = list()
        for module in res:
            module_db = get_module_by_name(module["name"])
            module_loc = module
            module_loc["request_on_query"] = module_db.request_on_query
            if module_db.is_active:
                if "expansion" in module["meta"]["module-type"] or "hover" in module["meta"]["module-type"]:
                    if not module_loc in loc_list:
                        loc_list.append(module_loc)
        loc_list.sort(key=lambda x: x["name"])
        return loc_list
    return res


def util_get_attr(module, loc_list):
    """Additional algo for get_list_misp_attributes"""
    if "input" in module["mispattributes"]:
        for input in module["mispattributes"]["input"]:
            if not input in loc_list:
                loc_list.append(input)
    return loc_list

def get_list_misp_attributes():
    """Return all types of attributes used in expansion and hover"""
    res = query_get_module()
    if not "message" in res:
        loc_list = list()

        for module in res:
            if get_module_by_name(module["name"]).is_active:
                if "expansion" in module["meta"]["module-type"] or "hover" in module["meta"]["module-type"]:
                    loc_list = util_get_attr(module, loc_list)
        loc_list.sort()
        return loc_list
    return res


def get_modules_config():
    """Return configs for all modules """
    modules = Module.query.order_by(Module.name).all()
    modules_list = []
    for module in modules:
        loc_module = module.to_json()
        if loc_module["input_attr"]:
            loc_module["input_attr"] = json.loads(loc_module["input_attr"])
        loc_module["config"] = []
        mcs = Module_Config.query.filter_by(module_id=module.id).all()
        for mc in mcs:
            conf = Config.query.get(mc.config_id)
            loc_module["config"].append({conf.name: mc.value})
        modules_list.append(loc_module)
    return modules_list


def change_config_core(request_json):
    """Change config for a module"""
    module = get_module_by_name(request_json["module_name"])
    for element in request_json:
        if not element == "module_name":
            config = get_config_by_name(element)
            if config:
                m_c = get_module_config_both(module.id, config.id)
                m_c.value = request_json[element]
                db.session.commit()
    module.request_on_query = request_json["request_on_query"]
    db.session.commit()
    return True

def change_status_core(module_id):
    """Active or deactive a module"""
    module = get_module(module_id)
    module.is_active = not module.is_active
    db.session.commit()
    return True



##############
# Session DB #
##############

def get_status_db(session):
    """Return status of a session"""
    modules_list = json.loads(session.modules_list)
    result = json.loads(session.result)
    return{
        'id': session.uuid,
        'total': len(modules_list),
        'complete': len(modules_list),
        'remaining': 0,
        'registered': len(result),
        'stopped' : True,
        "nb_errors": session.nb_errors
    }

def get_result_db(session):
    """Return result of a session"""
    return json.loads(session.result)

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
