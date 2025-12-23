import hashlib

from flask import Flask, request, jsonify

app = Flask(__name__)

def get_user_dict():
    # 构造字典
    info_dict = {}
    with open("db.txt", mode='r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            token, name = line.split(',')
            info_dict[token] = name
    return info_dict


@app.route('/bili' ,methods=['GET','POST'])
def bili():
    '''
    请求json格式：{"ordered_string":"123"}
    url携带token：/bili?token=ee1ca408-de2f-499e-b29a-69e29a25eac6
    :return:
    '''
    token = request.args.get('token')
    print(f"token={token}")
    if not token:
        return jsonify({"status":False, "msg":"token is empty"})

    user_dict = get_user_dict()
    if token not in user_dict:
        return jsonify({"status":False, "msg":"token is not exist"})


    # 获取POST请求体参数
    ordered_string = request.json.get("ordered_string")
    if not ordered_string:
        return jsonify({"status":False, "msg":"ordered_string is empty"})
    obj = hashlib.md5(ordered_string.encode('utf-8'))
    sign = obj.hexdigest()

    return jsonify({"status": True, "data": sign})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)