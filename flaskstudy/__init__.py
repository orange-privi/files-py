from flask import Flask


def create_app():

    app = Flask(__name__)

    from .views.order import od
    from .views.account import ac
    from .views.files import file_bp
    from .views.index import index_bp

    app.register_blueprint(file_bp)

    app.register_blueprint(od)
    app.register_blueprint(ac)

    app.register_blueprint(index_bp)

    return app