import os
import json
import base64
import sqlite3
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def get_string(local_state):
    with open(local_state, 'r', encoding='utf-8') as f:
        s = json.load(f)['os_crypt']['encrypted_key']
    return s


def decrypt_string(key, data):
    nonce, cipherbytes = data[3:15], data[15:]
    aesgcm = AESGCM(key)
    plainbytes = aesgcm.decrypt(nonce, cipherbytes, None)
    plaintext = plainbytes.decode('utf-8')
    return plaintext


def get_cookie_from_chrome(host,folder_path ):
    cookie_path = os.path.join(folder_path,'Cookies')
    local_state_key_path = os.path.join(folder_path, 'local_state_key.txt')
 
    sql = "select host_key,name,encrypted_value from cookies where host_key='%s'" % host

    with sqlite3.connect(cookie_path) as conn:
        cu = conn.cursor()
        res = cu.execute(sql).fetchall()
        cu.close()
        cookies = {}
        f = open(local_state_key_path, 'r')
        key = f.readlines()
        key =  base64.b64decode(key[0])
        for host_key, name, encrypted_value in res:
            if encrypted_value[0:3] == b'v10':
                cookies[name] = decrypt_string(key, encrypted_value)

        cookies = json.dumps(cookies)
        print(cookies)
        return cookies
get_cookie_from_chrome(sys.argv[1],sys.argv[2])

