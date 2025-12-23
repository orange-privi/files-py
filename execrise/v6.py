from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/task', methods=['GET', 'POST'])
def task():
    """
    任务接口
    :return:
    """
    order_str = request.json.get("ordered_string")
    if not order_str:
        return jsonify({"status":False, "msg":"ordered_string is empty"})
