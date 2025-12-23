import hashlib

from flask import Flask,request, jsonify


app = Flask(__name__)

@app.route("/bili", methods=['POST'])
def bili():
    '''
    请求json格式：{"ordered_string":"123"}
    :return:
    '''
    # 获取POST请求体参数
    ordered_string = request.json.get("ordered_string")
    if not ordered_string:
        return jsonify({"status":False, "msg":"ordered_string is empty"})
    obj = hashlib.md5(ordered_string.encode('utf-8'))
    sign = obj.hexdigest()


    return jsonify({"status":True, "data":sign})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
