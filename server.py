from ast import Bytes
from asyncio.constants import SENDFILE_FALLBACK_READBUFFER_SIZE
from ctypes import Union, sizeof
from datetime import datetime
from http import client
import socket, selectors,types,sys,io
from io import BytesIO
from typing import Any, List, Literal, Tuple
from settings import get_port
import uuid
from lazy_property import lazy_property
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import zlib
import decryptor, encryptor
from Crypto.Util.Padding import pad, unpad
from db_handler import db
import os




LOCALHOST = "127.0.0.1" #for testing purposes only
SAVE_PATH = "server/files"

class server:

    def __init__(self):
        #creation of selector object to handle all sockets
        self.sel = selectors.DefaultSelector()
          #initializing 
        host, port = LOCALHOST,int(get_port())
        #creation of listening socket of tcp/ipv4 
        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsock.bind((host, port))
        lsock.listen()
        print(f"Listening on {(host, port)}")
        #won't block >1 connections
        lsock.setblocking(False)
        self.version = b'3'
        #register the listening socket to the IO selector handler
        self.sel.register(lsock, selectors.EVENT_READ, data=None)
        self.server_db = db("server.db") #create db if not already created
        self.files_path  = os.path.join(os.getcwd(), SAVE_PATH) #set the path to save files.
        print(self.files_path)
        try:
            os.mkdir(self.files_path)
            print("created files directory")
        except OSError as error:
            print(error)    

        try:
            #forever loop for incoming connections
            while True:
                #events collects all IO events in the sel selector object
                events = self.sel.select(timeout=None)
                #iterate over the events, mask describes the kind of event anticipated
                for key, mask in events:
                    #if there is an event with no data, it is a new connection yet handled. send to accept method in order to handle
                    if key.data is None:
                        #fileobj contains the physical object (socket)
                        self.accept_wrapper(key.fileobj)
                    else:
                        #if there is an event with data, it means it has been handled and is a known connection socket in need of service.
                        self.service_connection(key, mask)

        except KeyboardInterrupt:
            print("Caught keyboard interrupt, exiting")
        finally:
            self.sel.close()

    class con_client: #sub_class for connected clients

        class client_file: #sub class for current in-memory handled file for connected client
            def __init__(self,name,content) -> None:
                self.name:str = name
                self.content:Bytes = content
                self.size = len(content)
                self.verified = False
           

            @lazy_property 
            def crc(self): #returns the crc at first call. will not be run again unless file is changed
                return zlib.crc32(self.content)


        
        def __init__(self,version,name,public_key='',client_id=None) -> None: #constructor for the client
            self.version = version
            self.name = name
            self.registered = False

            if(client_id): 
                self.client_id = client_id


        
        @lazy_property
        def client_id(self): #returns the uuid at first call. will not run again.
            return uuid.uuid1().bytes

        def set_pk(self,pk) -> Any: #setting the public key for the client, method returrns the symetric key encrypted with public key
            
            self.pk = pk
            if(isinstance(self.pk,str)):
                key = RSA.import_key(decryptor.dec64(pk))
                print(f"the pk: {decryptor.dec64(pk)}")

            else:
                key = RSA.import_key(pk)
                print(f"the pk: {pk}")

            cipher_rsa = PKCS1_OAEP.new(key)
            try:
                if(self.session_key):
                    pass
            except AttributeError:
                print("client has no session key set yet.")
                self.session_key = get_random_bytes(16)
            enc_session_key = cipher_rsa.encrypt(self.session_key)

            print(f"send enc session:  {enc_session_key} ")
            return enc_session_key
        
        def set_file(self,name: bytes,content): #this is called when a file is received. creates in-memory representation for current file per client
         
            text = name.decode('ascii')
            str_name = text.rstrip('\x00')
            cipher = AES.new(self.session_key, AES.MODE_CBC, bytes(16))
            dec_contnet = unpad(cipher.decrypt(content),AES.block_size)


            self.current_file = self.client_file(str_name, dec_contnet)
            

        


        def __str__(self): #returns string describing the client
            desc = f"client id: {self.client_id.hex()} \nversion: {self.version} \nname: {self.name} \n"
            try:
                desc += f" pk: {self.pk}"
            except AttributeError:
                pass
            
            return desc

    def register_client(self, client: con_client) -> bool: #server method. called in order to save client details to DB. returns client was not already registered.
        flag = False
        if(client.registered is False):
            client_id = client.client_id
            name = client.name
            pub_key = client.pk
            last_seen = datetime.now()
            key = client.session_key
            client.registered = self.server_db.add_client(client_id,name,pub_key,last_seen,key)
            flag = True
      
        
        
        return flag 
         

    def save_file(self,file: con_client.client_file): #server helper method. called in order to create file from its in-memory representation and saves it to server physical directory. returns a string describing file path on server directory
        name = file.name
        content = file.content
        path = f"{self.files_path}/{name}"
        with open(path,'w') as write_file:
            cursor = write_file.buffer
            cursor.seek(0)
            print("file is of length: " + str(cursor.write(content)))

        
        return path

    def register_file(self, client: con_client)-> bool: #server method. called in order to save file metadata to DB.
        client_id = client.client_id
        name = client.current_file.name
        path_name = self.save_file(client.current_file)
        verified = client.current_file.verified

        return self.server_db.add_file(client_id,name,path_name,verified)

    def accept_wrapper(self, sock):
        '''accepts a new client socket connecting and registering it to selector'''
        #conn gets a socket object representing the client, addr is its address:port
        conn, addr = sock.accept()  # Should be ready to read
        print(f"Accepted connection from {addr}")
        conn.setblocking(False)
        #init data object for selector object holding client socket
        data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"",my_client=None)
        #setting the mask: we wan't to be informed once client socket is ready to either read or write
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        #register the client socket with its mask and data to selector object
        self.sel.register(conn, events, data=data)

    def service_connection(self,key, mask):
        """called when the accepted socket is ready to be treated. method will handle cases of receiving info from the socket and sending info back.
        if the socket is ready to be treated but sends no data it means it is dead and the session will disconnect"""
        #retrieve info from socket ready
        sock = key.fileobj
        data = key.data
        #if socket is sending data:
        if mask & selectors.EVENT_READ:
            recv_data = sock.recv(1024)  # Should be ready to read
            if recv_data:
                data.inb += recv_data
                lines, payload_size = self.stream_decoder(recv_data) #raw bytes are sent to stream deocder in ordet to get logical representation of data and payload size
                total = payload_size + 23 #holds expected data size
                counter =1
                pos = 1024

                while pos < total: #will be called as long received data is smaller than expected data size
                    recv = sock.recv(1024)
                    pos = 1024*counter
                    lines = self.stream_decoder(recv,lines,pos) #sent received additional bytes to be added to payload data
                    counter +=1

                #lines and size are now populated. here we decide what to do based on request type. 

                code1 = str(lines[2][0]) 
                code2 = str(lines[2][1])
                req = code1 + '0' + code2 #req holds the request code to be queried upon by 'match' operator
                match req: #what to do in each code case adhereing to protocol specifications.
                    case '1100':
                        name = str(lines[4],encoding='ascii').split('!')[0]
                        if(self.server_db.get_uuid(name)): #check if this client has already been issued a uuid in the past
                            data.client = self.con_client( #create a in-memomry representation for the serviced client
                                version=int(lines[1]),
                                name = name,
                                client_id = self.server_db.get_uuid(name),
                            )
                            data.client.registered = True
                        else: #if the client was never registered to server
                            data.client = self.con_client(
                                version=int(lines[1]),
                                name=name
                                )
                        data.outb = self.constructResponse('2100',data.client.client_id) #as the protocol specifies

                    case '1101':
                        if(data.client.registered): #check if client is registered in DB
                            data.client.session_key = self.server_db.get_sym_key(data.client.client_id)
                            pk = self.server_db.get_pk(data.client.client_id) #to implement! need to create a get uuid accepting the client as a server method!!!!!
                            sym_key = data.client.set_pk(pk) #set the client object with its pk in order to receive a session key encrypted with it
                        else: 
                            sym_key = data.client.set_pk(str(lines[4],encoding='ascii').split('!')[1]) #inital set of client received pk to get the session's symmetric key

                        data.outb = self.constructResponse('2102',data.client.client_id,sym_key,client=data.client) #as the protocol specifies.
                        print("current client info: \n" + str(data.client)) #just for testing purposes
                    
                    case '1103':
                        file_size = int.from_bytes(lines[4][16:20],'little') #decode expected file size
                        print(f"file size: {file_size}") #just for testing
                        data.client.set_file(lines[4][20:275],lines[4][275:file_size + 275]) #call client method to create in-memory file representation for serviced client
                        data.outb = self.constructResponse('2103',data.client.client_id,sym_key=None,file=data.client.current_file,client = data.client) #as the protocol specifies
                    
                    case '1104':
                        print(f"checksum is valid")
                        data.client.current_file.verfied = True #set the file validated propery to true
                        self.register_file(data.client)
                        data.outb = self.constructResponse('2104',data.client.client_id)
                    
                    case '1105':
                        print(f"checksum is invalid, receiving file once again") 
                        #repeat case 1103
                        file_size = int.from_bytes(lines[4][16:20],'little') 
                        print(f"file size: {file_size}")
                        data.client.set_file(lines[4][20:275],lines[4][275:file_size + 275])
                        data.outb = self.constructResponse('2103',data.client.client_id,sym_key=None,file=data.client.current_file,client = data.client)
                    
                    case '1106':
                        print(f"checksum is invalid")
                   
            #no data sent means socket is dead
            else:
                print(f"Closing connection to {data.addr}")
                self.sel.unregister(sock)
                sock.close()

        #if we want to send info to socket
        if mask & selectors.EVENT_WRITE:
            if data.outb: #if there is data inside data.out then start sending.
               sent = sock.sendall(data.outb)
               data.outb = None
    



    def stream_decoder(self,stream:Bytes,lines = None,pos=0) -> Tuple: 
       
        """server method. called once received information from socket. 
        decoder reads incoming bytes and returns a tuple containing a list of lines 
        each representing a protocol header and the last is the payload.
        other tuple object is the size of payload size"""
        
        decoder = io.BytesIO(stream)
        if lines is None: #if this is the first bytes per received information
            lines = []
            decoder.seek(0)
            view = decoder.read()
            lines.append(view[:16]) #client_id - 0
            lines.append(view[16]) #version - 1
            lines.append(view[17:19]) #code - 2
            lines.append(view[19:23]) #payload_size - 3
            size = int.from_bytes(lines[3],byteorder='little') + 23
            lines.append(view[23:]) #payload - 4
        
        else: #if these are additional bytes needed to be concatinated upon already received information. ie payload data.
            decoder.seek(0)
            view = decoder.read()
            lines[4][pos] += view[0:]

        return lines, size

   

    def constructResponse(self, res_no ,client_id,sym_key=None,file: con_client.client_file = None,client: con_client=None) -> Bytes:
        """called in order to construct physical byte stream to be sent per response code."""
        def response(res_no1):
            bin_stream.write(int(res_no1[:2]).to_bytes(1,'little'))
            bin_stream.write(int(res_no1[2:]).to_bytes(1,'little'))
        
        bin_stream = io.BytesIO()
        bin_stream.write(self.version)
        
      
        payload = io.BytesIO()
      
        match res_no:
            case '2100': #registered, sending id
                payload.write(client_id)
     
            case '2102': #pk accepted, sending aes
                flag = self.register_client(client)
                if(flag):
                    payload.write(client_id)
                    payload.write(sym_key)
                else:
                    res_no = '2101'
                    payload.write(client_id)
                    payload.write(sym_key)

            case '2103': #received file, sending crc
               
               
                payload.write(client_id) #15
                payload.write(len(encryptor.encrypt_content(file.content,client.session_key)).to_bytes(length=4, byteorder='little')) #19
                payload.write(file.name.encode(encoding='ascii'))
                padding = 255 - len(file.name.encode(encoding='ascii')) 
                payload.write(bytes(padding)) #274
                crc_bytes = int(file.crc).to_bytes(4,'little')
                payload.write(crc_bytes)
                
              
            
            case '2104': #crc is valid, thankyou
                pass


            
        response(res_no)
        payload.seek(0)
        bin_stream.write(((len(payload.getbuffer()))).to_bytes(length=4,byteorder='little'))
        bin_stream.write(payload.read())

        bin_stream.seek(0)
        return bin_stream.read()
                

if __name__ == "__main__":
    """for testing purposes only."""
    s = server()