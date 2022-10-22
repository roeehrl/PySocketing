import Crypto.Cipher
from Crypto.PublicKey import RSA
import base64

def gen_rsa():
    key = RSA.generate(1024)
    return (key.export_key(), key.public_key().export_key())

def enc64 (key):
    return base64.b64encode(key).decode('ascii')


        