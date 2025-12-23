from flask import Blueprint, render_template, request, redirect

ac = Blueprint('account', __name__)


@ac.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    role = request.form.get('role')
    username = request.form.get('username')
    password = request.form.get('password')
    print(f"role, username, password: {role}, {username}, {password}")

    # 数据库校验
    import pymysql
    # mysql2.sqlpub.com:3307	yanjl009	3FiRjrZHPsW8wC1Z	webos009
    conn = pymysql.connect(host='mysql2.sqlpub.com', port=3307, user='yan009',
                           passwd='3FiRjrZHPsW8wC1Z', db='webos009')
    cur = conn.cursor()
    # 校验用户名密码是否正确
    #sql = f"select * from user_info where role='{username}' and password='{password}'"
    cur.execute("select * from user_info where role=%s and mobile=%s and password=%s", (role, username, password))
    user_dict = cur.fetchone()
    print(f"user_dict: {user_dict}")
    cur.close()
    conn.close()

    if user_dict :
        # 校验通过，登录成功
        return redirect('/files')

    # 校验失败，登录失败
    return render_template('login.html', error="密码错误")


@ac.route('/users')
def users():

    return 'users'