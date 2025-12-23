from dbutils.pooled_db import PooledDB
from flask import Flask
import pymysql

app = Flask(__name__)

#Myssql 连接池
POOL = PooledDB(
    creator=pymysql, # 连接数据库的模块
    maxconnections=5, # 最大连接数,0和None表示不限制连接数
    mincached=2, # 初始化时，连接池至少创建的空闲连接，0表示不创建
    maxcached=3, # 连接池最多创建的空闲连接数，0和None表示不限制连接数
    blocking=True, # 连接池没有连接时，是否阻塞等待,False时，不等待并报错
    setsession=[],
    ping=0, # 0 不检查, 1 检查连接可用

    # 数据库连接参数
    host='localhost',
    port=3306,
    user='root',
    password='123456',
    database='test',
    charset='utf8',
)

def fetch_one(sql, params):
    conn = POOL.connection()
    cursor = conn.cursor()
    cursor.execute(sql, params)
    conn.commit()
    result = cursor.fetchone()
    cursor.close()
    # 交还给连接池
    conn.close()
    return result



