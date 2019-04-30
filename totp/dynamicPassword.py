import totp
import base64
import time

class DynamicPasswor:

    def __init__(self, *args, **kwargs):
        return super().__init__(*args, **kwargs)

    def secretKey(self, key):
        return base64.b32encode(key.encode())

    def otp(self, secretKey, totpSize):
        return totp.TOTP(secretKey, int(totpSize))

    def client(self, beginTime, secretKey, totpSize, ttl):
        otp = self.otp(secretKey, totpSize)
        return otp.truncate(otp.tc(beginTime, ttl))

    def server(self, beginTime, secretKey, totpSize, ttl):
        otp = self.otp(secretKey, totpSize)
        return otp.truncate(otp.tc(beginTime, ttl))

totoSize = 6
ttl = 30
key = 'dynamic password'
dp = DynamicPasswor()
secretKey = dp.secretKey(key)

def main(beginTime, second):
    print('等待',second,'秒')
    clientDP = dp.client(beginTime, secretKey, totoSize, ttl)
    time.sleep(int(second))
    serverDP = dp.server(beginTime, secretKey, totoSize, ttl)
    print('client: ', clientDP, ', server: ', serverDP, ', compare: ', (clientDP==serverDP))    

if __name__ == "__main__":
    beginTime = int(time.time())
    main(beginTime, 5)
    beginTime = int(time.time())
    main(beginTime, 29)
    beginTime = int(time.time())
    main(beginTime, 31)