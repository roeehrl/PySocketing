
from ast import Str
import string
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import base64
from Crypto.Util.Padding import pad



def gen_rsa() -> tuple: 
    """generate rsa key, returns tuple containing full key and public key only"""
    key = RSA.generate(1024)
    return (key.export_key(format="DER"), key.public_key().export_key(format="DER"))

def enc64 (key) -> str:
    """encrypt data to base64 string"""
    return base64.b64encode(key).decode('ascii')

def encrypt_content(content ,sym_key) -> bytes:
    """encrypt file content with given aes key. returns bytes"""
    cipher = AES.new(sym_key, AES.MODE_CBC,bytes(16))
   
    if isinstance(content, str):
        enc_content = cipher.encrypt(pad(content.encode('ascii'),block_size=AES.block_size))
    else:
        enc_content = cipher.encrypt(pad(content,block_size=AES.block_size))


    return enc_content

