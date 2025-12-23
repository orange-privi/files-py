from flask import Blueprint, request, render_template

file_bp = Blueprint('files', __name__)



@file_bp.route('/files', methods=['GET', 'POST'])
def files_list():
    """
    文件列表接口
    :return:
    """
    if request.method == 'GET':
        return render_template('files.html')

    token = request.headers.get('Authorization')

    if not token:
        return render_template('login.html', error="未登录")


    pass
