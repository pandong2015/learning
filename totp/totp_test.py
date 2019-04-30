import totp
import base64

secretKey = base64.b32encode(b'My secret key')
t = totp.TOTP(secretKey, 4)
time = t.tc(60)    # 此处时间单位为秒
result=t.truncate(time)
print(result)