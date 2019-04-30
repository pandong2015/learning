import binascii
import hmac
import time
from hashlib import sha256

class TOTP:
    
    def __init__(self, key, codeDigits):
        self.key = key
        self.codeDigits = codeDigits

    def truncate(self, time):
        time = time.rjust(16,'0')
        bigint = binascii.unhexlify(hex(int('10'+time, 16))[2:])
        msg = bigint[1:len(bigint)]
        h = hmac.new(self.key, msg, sha256).digest()
        offset = h[len(h)-1] & 0xf
        binary = (h[offset] & 0x7f) << 24
        binary = binary | ((h[offset+1] & 0xff)<<16)
        binary = binary | ((h[offset+2] & 0xff)<<8)
        binary = binary | (h[offset+3] & 0xff)
        otp = binary % (10 ** self.codeDigits)
        return str(otp).rjust(self.codeDigits, '0')

    def tc(self, ttl):
        return self.tc(0, ttl)

    def tc(self, begintime, ttl):
        return format(int((time.time()-int(begintime))/int(ttl)),'x').upper()