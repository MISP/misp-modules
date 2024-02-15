from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_migrate import Migrate
from flask_session import Session

from config import config as Config
import os


db = SQLAlchemy()
csrf = CSRFProtect()
migrate = Migrate()
sess = Session()

def create_app():
    app = Flask(__name__)
    config_name = os.environ.get("FLASKENV")

    app.config.from_object(Config[config_name])

    Config[config_name].init_app(app)

    db.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db, render_as_batch=True)
    app.config["SESSION_SQLALCHEMY"] = db
    sess.init_app(app)

    from .home import home_blueprint
    from .history.history import history_blueprint
    app.register_blueprint(home_blueprint, url_prefix="/")
    app.register_blueprint(history_blueprint, url_prefix="/")

    return app
    
