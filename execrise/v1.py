from flask import Flask,request, jsonify

app = Flask(__name__)

# http://127.0.0.1:5000/index
# 默认只支持GET
@app.route("/index", methods=["POST", "GET"])
def index():
    # 获取请求参数
    age = request.args.get("age")
    pwd = request.args.get("pwd")
    print(age, pwd)

    # 获取POST请求体参数
    name = request.form.get("username")
    passwd = request.form.get("passwd")
    print(f"username={name}, passwd={passwd}")

    # 获取json参数
    #json_data = request.json
    #print(json_data)

    return jsonify({"status":True, "data":"data"})

# POST请求体参数, GET 可 省略
@app.route("/login", methods=["POST", "GET"])
def login():

    return "login"



if __name__ == '__main__':
    # 可选指定端口 和 绑定主机
    app.run(host='0.0.0.0', port=5000)
