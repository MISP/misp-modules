import json
import os
from ..db_class.db import db
from ..db_class.db import Module, Config, Module_Config
from .utils import query_get_module


def create_modules_db():
    modules = query_get_module()

    for module in modules:
        m = Module.query.filter_by(name=module["name"]).first()
        if not m:
            m = Module(
                name=module["name"],
                description=module["meta"]["description"],
                is_active=True
            )
            db.session.add(m)
            db.session.commit()


            if "config" in module["meta"]:
                for conf in module["meta"]["config"]:
                    c = Config.query.filter_by(name=conf).first()
                    if not c:
                        c = Config(
                            name = conf
                        )
                        db.session.add(c)
                        db.session.commit()
                
                    mc = Module_Config(
                        module_id=m.id,
                        config_id=c.id
                    )
                    db.session.add(mc)
                    db.session.commit()