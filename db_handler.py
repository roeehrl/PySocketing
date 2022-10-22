import sqlite3

conn = sqlite3.connect('server.db')
print ("Opened database successfully")

try:
    conn.execute('''CREATE TABLE CLIENTS
            (ID binary(128) PRIMARY KEY     NOT NULL,
            NAME           char(127)    NOT NULL,
            PUBLICKEY            binary(160)     NOT NULL,
            LASTSEEN        datetime,
            AES          binary(256));''')

    print ("Table created successfully")

except:
    print("table clients already exists")

try:
    conn.execute('''CREATE TABLE FILES
            (ID binary(128) PRIMARY KEY     NOT NULL,
            FILENAME           char(255)    NOT NULL,
            PATH            char(255)     NOT NULL,
            Verified        int );''')

    print ("Table created successfully")

except:
    print("table files already exists")