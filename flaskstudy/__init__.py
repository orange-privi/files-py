from flask import Flask


def create_app():

    app = Flask(__name__)

    from .views.order import od
    from .views.account import ac

    app.register_blueprint(od)
    app.register_blueprint(ac)


    return app