from app import create_app, db
from flask import render_template
import os
from app.utils.init_modules import create_modules_db

from app.utils.utils import gen_admin_password

os.environ.setdefault('FLASKENV', 'development')

app = create_app()

@app.errorhandler(404)
def error_page_not_found(e):
    return render_template('404.html'), 404


def main(init_db=False, recreate_db=False, delete_db=False, create_module=False):
    if init_db:
        with app.app_context():
            db.create_all()
    elif recreate_db:
        with app.app_context():
            db.drop_all()
            db.create_all()
    elif delete_db:
        with app.app_context():
            db.drop_all()
    elif create_module:
        with app.app_context():
            create_modules_db()
    else:
        gen_admin_password()
        app.run(host=app.config.get("FLASK_URL"), port=app.config.get("FLASK_PORT") , use_reloader=False)
