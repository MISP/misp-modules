from app import db
from app.models import ExternalTools


def get_tool(tool_id):
    """Return a tool by id"""
    return ExternalTools.query.get(tool_id)


def get_tools():
    """Return all External tools"""
    return ExternalTools.query.all()


def change_status_core(tool_id):
    """Active or disabled a tool"""
    an = get_tool(tool_id)
    if an:
        an.is_active = not an.is_active
        db.session.commit()
        return True
    return False


def change_config_core(request_json):
    """Change config for a tool"""
    tool = get_tool(request_json["tool_id"])
    if tool:
        tool.name = request_json["tool_name"]
        tool.url = request_json["tool_url"]
        tool.api_key = request_json["tool_api_key"]
        db.session.commit()
        return True
    return False


def add_tool_core(form_dict):
    tool = ExternalTools(
        name=form_dict["name"],
        url=form_dict["url"],
        api_key=form_dict["api_key"],
        is_active=True,
    )
    db.session.add(tool)
    db.session.commit()
    return True


def delete_tool(tool_id):
    tool = get_tool(tool_id)
    if tool:
        db.session.delete(tool)
        return True
    return False


def form_to_dict(form):
    loc_dict = dict()
    for field in form._fields:
        if field == "files_upload":
            loc_dict[field] = dict()
            loc_dict[field]["data"] = form._fields[field].data
            loc_dict[field]["name"] = form._fields[field].name
        elif not field == "submit" and not field == "csrf_token":
            loc_dict[field] = form._fields[field].data
    return loc_dict
