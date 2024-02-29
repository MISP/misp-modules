class Config:
    SECRET_KEY = 'SECRET_KEY_ENV_VAR_NOT_SET'
    
    FLASK_URL = '127.0.0.1'
    FLASK_PORT = 7008
    MISP_MODULE = '127.0.0.1:6666'
    ADMIN_USER = False
    ADMIN_PASSWORD = Password1234

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///misp-module.sqlite"
    SESSION_TYPE = "sqlalchemy"
    SESSION_SQLALCHEMY_TABLE = "flask_sessions"

    @classmethod
    def init_app(cls, app):
        print('THIS APP IS IN DEBUG MODE. \
                YOU SHOULD NOT SEE THIS IN PRODUCTION.')

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///misp-module-test.sqlite"
    WTF_CSRF_ENABLED = False


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
