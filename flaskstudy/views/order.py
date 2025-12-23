from flask import Blueprint, request, render_template

od = Blueprint('order', __name__)



@od.route('/order', methods=['GET', 'POST'])
def order_list():
    """
    订单列表接口
    :return:
    """
    if request.method == 'GET':
        return render_template('order.html')

    pass


@od.route('/order/create', methods=['GET', 'POST'])
def order_create():

    pass


