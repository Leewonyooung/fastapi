import pymysql

vet_academy = 'svc.sel4.cloudtype.app'

home = '127.0.0.1'

def connect():
    conn = pymysql.connect(
        host=vet_academy,
        user='root',
        password='qwer1234',
        charset='utf8',
        db='veterinarian',
        port=32176
    )
    return conn