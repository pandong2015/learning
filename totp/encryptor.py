from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, DES
import totp
import base64
import time

class des:
    def __init__(self, *args, **kwargs):
        return super().__init__(*args, **kwargs)

    def ecrypt(self, secretKey, content):
        generator = DES.new(secretKey, DES.MODE_ECB) 
        pad = 8 - len(content) % 8
        padStr=''
        for i in range(pad):
            padStr = padStr + chr(pad)
        content = content + padStr
        return generator.encrypt(content.encode())

    def decrypt(self, secretKey, content):
        generator = DES.new(secretKey, DES.MODE_ECB) 
        result = generator.decrypt(content)
        pad=result[len(result)-1]
        return result[0:len(result)-pad].decode()
