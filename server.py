from ast import Bytes
from http import client
import socket, selectors,types,sys,io
from io import BytesIO
from typing import Any, List, Literal
from settings import get_port
import uuid
from lazy_property import lazy_property


LOCALHOST = "127.0.0.1"


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

        try:
            #forever loop for incoming connections
            while True:
                #events collects all IO events in the sel selector object
                events = self.sel.select(timeout=None)
                #iterate over the events, mask describes the kind of event anticipated
                for key, mask in events:
                    #if there is an event with no data, it is a new connection yet handled. send to accept in order to handle
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

    class con_client:
        
        def __init__(self,version,name,public_key='') -> None:
            self.version = version
            self.name = name
        
        @lazy_property
        def client_id(self):
            return uuid.uuid1().bytes

        def set_pk(self,pk) -> Any:
            self.pk = pk
            aes = ''
            return aes
        


        def __str__(self):
            desc = f"client id: {self.client_id.hex()} \nversion: {self.version} \nname: {self.name} \n"
            try:
                desc += f" pk: {self.pk}"
            except AttributeError:
                pass
            
            return desc


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
        #retrieve info from socket ready
        sock = key.fileobj
        data = key.data
        #if socket is sending data:
        if mask & selectors.EVENT_READ:
            recv_data = sock.recv(1024)  # Should be ready to read
            if recv_data:
                data.inb += recv_data
                lines = self.stream_decoder(recv_data)
                code1 = str(lines[2][0])
                code2 = str(lines[2][1])
                req = code1 + '0' + code2
                if req == '1100':
                    
                    data.client = self.con_client(
                        version=int(lines[1]),
                        name = str(lines[4],encoding='ascii').split('!')[0]
                        )
                    data.outb = self.constructResponse('2100',data.client.client_id)
                    print(str(data.client))

                if req == '1101':
                    aes = data.client.set_pk(str(lines[4],encoding='ascii').split('!')[1])
                    print(str(data.client))

            #no data sent means socket is dead
            else:
                print(f"Closing connection to {data.addr}")
                self.sel.unregister(sock)
                sock.close()
        #if we want to send info to socket
        if mask & selectors.EVENT_WRITE:
            if data.outb:
               sent = sock.sendall(data.outb)
               data.outb = None
    
    def stream_decoder(self,stream:Bytes) -> List[Bytes]:
        decoder = io.BytesIO(stream)
        lines = []
        decoder.seek(0)
        view = decoder.read()
        lines.append(view[:16]) #client_id
        lines.append(view[16]) #version
        lines.append(view[17:19]) #code
        lines.append(view[19:23]) #payload_size
        size = int.from_bytes(lines[3],byteorder='little') + 23
        lines.append(view[23:size]) #payload

        return lines

   

    def constructResponse(self, res_no ,client_id,pk=None,file = None) -> Bytes:
        bin_stream = io.BytesIO()
        bin_stream.write(self.version)
        bin_stream.write(int(res_no[:2]).to_bytes(1,'little'))
        bin_stream.write(int(res_no[2:]).to_bytes(1,'little'))
      
        payload = io.BytesIO()
        if file:
            file_name = ''
            new_file = self.encrypt_file(file)
            lines = new_file.readlines()
            file_content = ''
            for line in lines:
                content += line


        match res_no:
            case '2100': #registered, sending id
                payload.write(client_id)
            case '2102': #pk accepted, sending aes
                payload.write(client_id)
                payload.write(pk)
            case '2103': #received file, sending crc
                payload.write(client_id)

            
            case '1104', '1105', '1106':
                payload.write(self.client_id.encode(encoding='ascii'))
                payload.write(file_name.encode(encoding='ascii'))

        payload.seek(0)
        bin_stream.write(((len(payload.getbuffer()))).to_bytes(length=4,byteorder='little'))
        bin_stream.write(payload.read())

        bin_stream.seek(0)
        return bin_stream.read()
                

if __name__ == "__main__":
    s = server()