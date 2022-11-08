from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64

def decrypt_sym_key(enc_session_key): 
    """only for client use. decrypts the session key with the stored private key """
    with open("me.info",'r') as file:
        key_string = file.readlines()[2]
   
    print(f"encrypted {enc_session_key}")
    private_key = RSA.import_key(dec64(key_string))
    print(f"pk: { private_key.public_key().export_key('DER')}")
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    return session_key

def dec64 (key_str:str) -> bytes:
    """dercrypts base64 string and returns bytes"""
    return base64.b64decode(key_str.encode('ascii'))
