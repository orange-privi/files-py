from flask import Blueprint

od = Blueprint('order', __name__)



@od.route('/order', methods=['GET', 'POST'])
def order_list():
    """
    订单列表接口
    :return:
    """
    pass


@od.route('/order/create', methods=['GET', 'POST'])
def order_create():

    pass


