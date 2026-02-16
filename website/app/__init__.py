#!/usr/bin/env python3
import os

from flask import Flask, render_template
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

from dotenv import load_dotenv
load_dotenv()

db = SQLAlchemy()
csrf = CSRFProtect()
migrate = Migrate()
session = Session()
login_manager = LoginManager()


def create_app():
    app = Flask(__name__)

    # Configure app from environment variables
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URI", "sqlite:///misp-module.sqlite"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SESSION_TYPE"] = os.getenv("SESSION_TYPE", "sqlalchemy")
    app.config["SESSION_SQLALCHEMY_TABLE"] = os.getenv(
        "SESSION_SQLALCHEMY_TABLE", "flask_sessions"
    )
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
    app.config["FLASK_URL"] = os.getenv("FLASK_URL", "127.0.0.1")
    app.config["FLASK_PORT"] = int(os.getenv("FLASK_PORT", "7008"))
    app.config["MISP_MODULE"] = os.getenv("MISP_MODULE", "127.0.0.1:6666")

    # Validate critical settings
    if not app.config["SECRET_KEY"]:
        raise ValueError("SECRET_KEY must be set in .env")

    # Initialize extensions
    db.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db, render_as_batch=True)
    app.config["SESSION_SQLALCHEMY"] = db
    session.init_app(app)
    login_manager.login_view = "account.login"
    login_manager.init_app(app)

    # Register blueprints
    from .account.account import account_blueprint
    from .external_tools.external_tools import external_tools_blueprint
    from .history.history import history_blueprint
    from .home import home_blueprint

    app.register_blueprint(home_blueprint, url_prefix="/")
    app.register_blueprint(history_blueprint, url_prefix="/")
    app.register_blueprint(account_blueprint, url_prefix="/")
    app.register_blueprint(external_tools_blueprint, url_prefix="/")
    csrf.exempt(home_blueprint)

    # Register 404 error handler
    @app.errorhandler(404)
    def error_page_not_found(e):
        return render_template("404.html"), 404

    return app
