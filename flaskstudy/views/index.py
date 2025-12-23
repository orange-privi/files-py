from flask import Blueprint, render_template

index_bp = Blueprint('index', __name__)

@index_bp.route('/')
def index():
    print("index")
    return 'login'


@index_bp.route('/navbar')
def navbar():
    return render_template('navbar.html')

