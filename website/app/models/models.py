import json

from flask_login import AnonymousUserMixin, UserMixin

from app import db, login_manager


class Module(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, index=True, unique=True)
    description = db.Column(db.String)
    is_active = db.Column(db.Boolean, default=True)
    request_on_query = db.Column(db.Boolean, default=False)
    input_attr = db.Column(db.String)

    def to_json(self):
        json_dict = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "is_active": self.is_active,
            "request_on_query": self.request_on_query,
            "input_attr": self.input_attr,
        }
        return json_dict


class Session_db(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String(36), index=True, unique=True)
    modules_list = db.Column(db.String)
    query_enter = db.Column(db.String)
    input_query = db.Column(db.String)
    config_module = db.Column(db.String)
    result = db.Column(db.String)
    nb_errors = db.Column(db.Integer, index=True)
    query_date = db.Column(db.DateTime, index=True)

    def to_json(self):
        json_dict = {
            "id": self.id,
            "uuid": self.uuid,
            "modules": json.loads(self.modules_list),
            "query_enter": json.loads(self.query_enter),
            "input_query": self.input_query,
            "config_module": json.loads(self.config_module),
            "result": json.loads(self.result),
            "nb_errors": self.nb_errors,
            "query_date": self.query_date.strftime("%Y-%m-%d %H:%M"),
        }
        return json_dict

    def history_json(self):
        json_dict = {
            "uuid": self.uuid,
            "modules": json.loads(self.modules_list),
            "query": json.loads(self.query_enter),
            "input": self.input_query,
            "query_date": self.query_date.strftime("%Y-%m-%d %H:%M"),
        }
        return json_dict


class History(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    session_id = db.Column(db.Integer, index=True)


class History_Tree(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    session_uuid = db.Column(db.String(36), index=True)
    tree = db.Column(db.String)


class Config(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, index=True, unique=True)


class Module_Config(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    module_id = db.Column(db.Integer, index=True)
    config_id = db.Column(db.Integer, index=True)
    value = db.Column(db.String, index=True)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(64), index=True)
    last_name = db.Column(db.String(64), index=True)
    email = db.Column(db.String(64), unique=True, index=True)

    def to_json(self):
        return {
            "id": self.id,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "email": self.email,
        }


class ExternalTools(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(64), index=True)
    url = db.Column(db.String)
    api_key = db.Column(db.String(60), index=True)
    is_active = db.Column(db.Boolean)

    def to_json(self):
        return {
            "id": self.id,
            "url": self.url,
            "name": self.name,
            "api_key": self.api_key,
            "is_active": self.is_active,
        }


class AnonymousUser(AnonymousUserMixin):
    def is_admin(self):
        return False

    def read_only(self):
        return True


login_manager.anonymous_user = AnonymousUser


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
