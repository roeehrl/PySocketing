from datetime import datetime
from http import client
from logging import exception
from pydoc import cli
import sqlite3
import uuid
import encryptor
import decryptor
import codecs



class db: 

    def __init__(self,db_name):
        """constructor of the server db. create 'file'.db only if the db does not exist already"""
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name)
        self.cur = self.conn.cursor()
        print ("Opened database successfully")

        try:
            self.cur.execute('''CREATE TABLE CLIENTS
                    (ID binary(128) PRIMARY KEY     NOT NULL,
                    NAME           char(127)    NOT NULL,
                    PUBLICKEY            binary(160)     NOT NULL,
                    LASTSEEN        TEXT,
                    AES          binary(32));''')

            print ("Table created successfully")

        except:
            print("table clients already exists")

        try:
            self.cur.execute('''CREATE TABLE FILES
                    (ID binary(128) PRIMARY KEY     NOT NULL,
                    FILENAME           char(255)    NOT NULL,
                    PATH            char(255)     NOT NULL,
                    Verified        int );''')

            print ("Table created successfully")

        except:
            print("table files already exists")

        self.conn.close()

    def add_client(self, client_id, client_name, client_pub_key, client_last_seen, client_aes) -> bool:
        """save a new client to the db, returns true if succeeded"""
        indicator = False
        self.conn = sqlite3.connect(self.db_name)
        self.cur = self.conn.cursor()

        try:
            self.cur.execute(""" INSERT INTO clients VALUES (?,?,?,?,?) """, (memoryview(client_id), client_name, memoryview(decryptor.dec64(client_pub_key)), client_last_seen ,memoryview(client_aes)))
            indicator = True

            self.conn.commit()
        
        except:
            print("failed to add client")
        
        self.conn.close()

        return indicator

    def add_file(self, client_id, name, path, verified) -> bool:
        """save a new file to the db, returns true if succeeded"""

        indicator = False
        self.conn = sqlite3.connect(self.db_name)
        self.cur = self.conn.cursor()

        try:
            self.cur.execute(f""" INSERT INTO files VALUES ({str(client_id)[1:]}, '{name}', '{path}', '{verified}') """)
            indicator = True

            self.conn.commit()
        
        except:
            print("failed to add file")
        
        self.conn.close()

        return indicator
    
    def get_uuid(self, name):
        """returns the uuid of a registered client. if not found returns None"""
        
        self.conn = sqlite3.connect(self.db_name)
        self.cur = self.conn.cursor()

        selector = f""" SELECT id FROM clients WHERE name='{name}' """
        res = self.cur.execute(selector)
        id = res.fetchone()
        if(id):
            client_id = id[0]

        else:
            client_id = None
    
        self.conn.close()


        return client_id
    
    def get_sym_key(self, client_id) -> bytes:
        """returns the aes symmetric key of a registered client. if not found returns None"""


        self.conn = sqlite3.connect(self.db_name)
        self.cur = self.conn.cursor()

        
        res = self.cur.execute(f""" SELECT aes FROM clients WHERE id=(?) """,(memoryview(client_id),))
        aes = res.fetchone()
        if(aes):
            client_aes = aes[0]
        else:
            client_aes = None
    
        self.conn.close()


        return client_aes

    def get_pk(self, client_id) -> bytes: #needs to be tested!!
        """returns the public key  of a registered client. if not found returns None"""


        self.conn = sqlite3.connect(self.db_name)
        self.cur = self.conn.cursor()

        
        res = self.cur.execute(f""" SELECT publickey FROM clients WHERE id=(?) """,(memoryview(client_id),))
        pk = res.fetchone() #method returns tuple
        if(pk):
            client_pk = pk[0]
        else:
            client_pk = None
    
        self.conn.close()


        return client_pk


if __name__ == "__main__":
    """for testing purposes only!"""
    database = db("test.db")
    id = uuid.uuid1().bytes
    print(id)
    id_client = str(id)[1:]
    print(id_client)

    name = 'testname'
    key, pub_key = encryptor.gen_rsa()
    client_key = str(pub_key)[1:]
    last_seen = datetime.now()
    aes = str(b'12345678')[1:]


    database.add_client(id_client,name,client_key,last_seen,aes)
    