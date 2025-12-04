import json

from app import db
from app.models import Config, Module, Module_Config
from app.utils import query_get_module


def create_modules_db():
    modules = query_get_module()
    if "message" not in modules:
        for module in modules:
            m = Module.query.filter_by(name=module["name"]).first()
            input_attr = ""
            if "input" in module["mispattributes"]:
                input_attr = json.dumps(module["mispattributes"]["input"])
            if not m:
                m = Module(
                    name=module["name"],
                    description=module["meta"]["description"],
                    is_active=True,
                    request_on_query=False,
                    input_attr=input_attr,
                )
                db.session.add(m)
                db.session.commit()

                if "config" in module["meta"]:
                    for conf in module["meta"]["config"]:
                        c = Config.query.filter_by(name=conf).first()
                        if not c:
                            c = Config(name=conf)
                            db.session.add(c)
                            db.session.commit()

                        mc = Module_Config(module_id=m.id, config_id=c.id)
                        db.session.add(mc)
                        db.session.commit()
    else:
        print("[-] Error contact misp-modules. Please ensure it's running.")
