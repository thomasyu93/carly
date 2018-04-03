import base64
import hashlib
import time
from Crypto import Random
from Crypto.Cipher import AES, DES

class AESCipher(object):
    """
    A classical AES Cipher. Can use any size of data and any size of password thanks to padding.
    Also ensure the coherence and the type of the data with a unicode to byte converter.
    """
    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(AESCipher.str_to_bytes(key)).digest()

    @staticmethod
    def str_to_bytes(data):
        u_type = type(b''.decode('utf8'))
        if isinstance(data, u_type):
            return data.encode('utf8')
        return data

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * AESCipher.str_to_bytes(chr(self.bs - len(s) % self.bs))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt(self, raw):
        raw = self._pad(AESCipher.str_to_bytes(raw))
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')


class DESCipher(object):
    """
    A classical AES Cipher. Can use any size of data and any size of password thanks to padding.
    Also ensure the coherence and the type of the data with a unicode to byte converter.
    """
    def __init__(self, key):
        self.bs = 8
        self.key = b'byte key'

    @staticmethod
    def str_to_bytes(data):
        u_type = type(b''.decode('utf8'))
        if isinstance(data, u_type):
            return data.encode('utf8')
        return data

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * DESCipher.str_to_bytes(chr(self.bs - len(s) % self.bs))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt(self, raw):
        raw = self._pad(DESCipher.str_to_bytes(raw))
        iv = Random.new().read(DES.block_size)
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:DES.block_size]
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[DES.block_size:])).decode('utf-8')


class CaesarCipher(object):
    def __init__(self):
        self.key = 'abcdefghijklmnopqrstuvwxyz'

    def encrypt(self,offset, plaintext):
        result = ''

        for l in plaintext.lower():
            try:
                i = (self.key.index(l) + offset) % 26
                result += self.key[i]
            except ValueError:
                result += l
        return result.lower()

    def decrypt(self,offset, enc):
        result = ''

        for l in enc:
            try:
                i = (self.key.index(l) - offset) % 26
                result += self.key[i]
            except ValueError:
                result += l

        return result

    def crack(self, ciphertext):
        for i in range(1,26):
            string = ""
            for char in ciphertext:
                if(ord(char) + i > 122):
                    charc = (ord(char) + i) - 26
                    string =  string + chr(charc)
                else:
                   charc = ord(char) + i
                   string =  string + chr(charc)

            print(string)

class VigCipher(object):
    def __init__(self,key):
        self.key=key
        self.universe = [c for c in (chr(i) for i in range(32,127))]
        self.uni_len = len(self.universe)

    def vign(self, txt='', key='', typ='d'):
        if not txt:
            print('Needs text.')
            return
        if not key:
            print('Needs key.')
            return
        if typ not in ('d', 'e'):
            print('Type must be "d" or "e".')
            return
        if any(t not in self.universe for t in key):
            print('Invalid characters in the key. Must only use ASCII symbols.')
            return

        ret_txt = ''
        k_len = len(key)

        for i, l in enumerate(txt):
            if l not in self.universe:
                ret_txt += l
            else:
                txt_idx = self.universe.index(l)

                k = key[i % k_len]
                key_idx = self.universe.index(k)
                if typ == 'd':
                    key_idx *= -1

                code = self.universe[(txt_idx + key_idx) % self.uni_len]

                ret_txt += code

        return ret_txt

print (ord('z'))
print (ord('a'))


print("-----------------------\nCaesarCipher\n-----------------------")
startTime = time.time()
cipher = CaesarCipher()
encrypted = cipher.encrypt(3, 'helloworld')
print(encrypted)
decrypted=cipher.decrypt(3,encrypted)
print(decrypted)
endTime = time.time()
print(endTime - startTime)
cipher.crack(encrypted)

'''
print("\n-----------------------\nVigCipher\n-----------------------")
startTime = time.time()
cipher = VigCipher('asdfasdf')
encrypted = cipher.vign('hello world', 'testing', 'e')
print(encrypted)
decrypted=cipher.vign(encrypted, 'testing', 'd')
print(decrypted)
endTime = time.time()
print(endTime - startTime)

print("\n-----------------------\nDESCipher\n-----------------------")
startTime = time.time()
cipher = DESCipher(key= b"test")
encrypted = cipher.encrypt("Hello World")
print (encrypted)
new_cipher = DESCipher(key='test')
decrypted = new_cipher.decrypt(str(encrypted))
print(decrypted)
endTime = time.time()
print(endTime - startTime)

print("\n-----------------------\nAESCipher\n-----------------------")
startTime = time.time()
cipher = AESCipher(key= b"test")
encrypted = cipher.encrypt("Hello World")
print (encrypted)
new_cipher = AESCipher(key='test')
decrypted = new_cipher.decrypt(str(encrypted))
print(decrypted)
endTime = time.time()
print(endTime - startTime)

'''
