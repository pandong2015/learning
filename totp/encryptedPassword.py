import totp
import base64
import time
import encryptor
import random
import string

class EncryptorPassword:
    def __init__(self, *args, **kwargs):
        return super().__init__(*args, **kwargs)

    def secretKey(self, key):
        return base64.b32encode(key.encode())

    def des(self):
        return encryptor.des()

    def otp(self, secretKey, totpSize):
        return totp.TOTP(secretKey, int(totpSize))

    def randomword(self,length):
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for i in range(length))

    def client(self, beginTime, secretKey, totpSize, ttl, baseKey, content):
        otp = self.otp(secretKey, totpSize)
        otpresult = otp.truncate(otp.tc(beginTime, ttl))
        desSecretKey = baseKey+ otpresult.encode()
        return self.des().decrypt(desSecretKey, content)

    def server(self, beginTime, secretKey, totpSize, ttl, baseKey, content):
        otp = self.otp(secretKey, totpSize)
        otpresult = otp.truncate(otp.tc(beginTime, ttl))
        desSecretKey = baseKey+ otpresult.encode()
        return self.des().ecrypt(desSecretKey, content)

totoSize = 4
ttl = 30
key = 'encrypted password'
ep = EncryptorPassword()
secretKey = ep.secretKey(key)
baseKey =ep.randomword(4).encode()
content = 'test content'

def main(beginTime, second):
    print('等待',second,'秒')
    ecryptContent = ep.server(beginTime, secretKey, totoSize, ttl, baseKey, content)
    time.sleep(second)
    decryptContent = ep.client(beginTime, secretKey, totoSize, ttl, baseKey, ecryptContent)
    print('decrypt result: ',decryptContent)

if __name__ == "__main__":
    beginTime = int(time.time())
    main(beginTime, 29)
    beginTime = int(time.time())
    main(beginTime, 30)
    beginTime = int(time.time())
    main(beginTime, 31)
