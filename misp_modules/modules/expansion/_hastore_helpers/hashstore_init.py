#!/usr/bin/env python3
# -*- coding: utf-8 -*
#pip install mysql-connector==2.1.6

import mysql.connector
import redis


sql = """SELECT sha2((CASE WHEN attributes.value2 = '' THEN attributes.value1 ELSE CONCAT(attributes.value1, '|', attributes.value2) END), 256) AS hashvalue, attributes.uuid FROM attributes;"""

# check misp conf
paramMysql = {
    'host': 'localhost',
    'user': 'misp_user',
    'password': 'misp_password',
    'database': 'misp_database'
}
# configure a new database to store hashstore data
paramRedis = {
    'host': '127.0.0.1',
    'port': 6379,
    'db': 7,
    'decode_responses': True,
    'charset': 'utf-8'
}


conn = mysql.connector.connect(**paramMysql)
hashStore = redis.Redis(**paramRedis)
cursor = conn.cursor()
cursor.execute(sql)
rows = cursor.fetchall()
for row in rows:
    hashStore.sadd(row[0], row[1].decode("utf-8"))

print('done')
conn.close()
