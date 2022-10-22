from ast import Bytes
from binhex import hexbin
from ctypes import sizeof
import selectors
import socket
import io
from sys import byteorder
from typing import List, Literal
import encryptor
from lazy_property import lazy_property

class client: 
    def __init__(self, client_id='unregistered',version = 3):
        print("Initiating client setup")
        self.sel = selectors.DefaultSelector()

        self.csock = socket.socket()
        self.server_address = ''
        self.server_port = 1234 #default port
        self.version = version
        self.sel.register(self.csock, selectors.EVENT_READ, data=None)

        try:
            with open("transfer.info") as init_file:
                print(f"reading {init_file.name} content")
                lines = init_file.readlines()
                counter = 0
                try:
                    for line in lines:
                        if counter == 0:
                        
                            self.server_address = line.split(':')[0]
                          
                            self.server_port = int((line.split(':')[1])[0:])
                            print(f"server info: {self.server_address}:{self.server_port}")                        
                            
                        if counter == 1:
                            self.name = line[:len(line)-1] +"!"
                        
                        if counter == 2:
                            self.file_path = line
                        

                        counter += 1
                except:
                    print("the file is corrupt. quitting...")
                    quit()                    

            self.csock.connect((self.server_address,self.server_port))

        except FileNotFoundError:
            print("file not found")
            quit()
        except ConnectionRefusedError:
            print(f"unable to connect to {self.server_address} at {self.server_port}, connection refused.")
            quit()
        
        self.lines = []
        self.client_id = client_id

        while True:
            try:
                with open ('me.info') as info_file:
                    self.switcher()
                        
            except:
                print("me.info file not found, sending registeration request")
                self.sendRequest('1100')
                self.switcher()

    @lazy_property
    def key(self):
        return encryptor.gen_rsa()

    def stream_decoder(self,stream:Bytes) -> List[Bytes]:
        decoder = io.BytesIO(stream)
        lines = []
        decoder.seek(0)
        view = decoder.read()
        lines.append(view[0]) #server_version
        lines.append(view[1:3]) #code
        lines.append(view[3:7]) #payload_size
        size = int.from_bytes(lines[2],byteorder='little') + 7
        lines.append(view[7:size]) #payload

        return lines

    def switcher(self):
        lines = self.stream_decoder(self.csock.recv(1024))
        code1 = str(lines[1][0])
        code2 = str(lines[1][1])
        req = code1 + '0' + code2

        match req:
            case '2100':
                print('got 2100')
                self.client_id = lines[3][:17].hex()
                print(f"obtained my client id: {self.client_id}")
                print(f"creating me.info file")
                self.createFile()
                self.sendRequest('1101')
                self.switcher()



    
    def sendRequest(self,code):
        stream = self.constructRequest(code)
        print(self.csock.sendall(stream))
        print(f"sent request {code}")

    def encrypt_file(self):
        pass
    

    def createFile(self):
        lines = []
        lines.append(self.name.split('!')[0]+'\n')
        lines.append(self.client_id+'\n')
        lines.append(encryptor.enc64(self.key[0]))
        with open('me.info',mode='w') as file:
            file.writelines(lines)

    def constructRequest(self, req_no ,file = None) -> Bytes:
        bin_stream = io.BytesIO()
        try:
            padding = bin_stream.write(bytes.fromhex(self.client_id))
        except ValueError:
            padding = bin_stream.write(bytes(16))

        if padding < 16:
            bin_stream.write(bytes(16-padding))
        bin_stream.write((self.version).to_bytes(1,'little'))
        bin_stream.write(int(req_no[:2]).to_bytes(1,'little'))
        bin_stream.write(int(req_no[2:]).to_bytes(1,'little'))

        payload = io.BytesIO()
        if file:
            file_name = ''
            new_file = self.encrypt_file(file)
            lines = new_file.readlines()
            file_content = ''
            for line in lines:
                content += line


        match req_no:
            case '1100':
                payload.write(self.name.encode(encoding='ascii'))
            case '1101':
                payload.write(self.name.encode(encoding='ascii'))
                payload.write(encryptor.enc64(self.key[1]).encode(encoding='ascii'))
            case '1103':
                payload.write(self.client_id.encode(encoding='ascii'))
                payload.write(sizeof(new_file).to_bytes(byteorder='little'))
                payload.write(file_name.encode(encoding='ascii'))
                payload.write(file_content.encode())
            
            case '1104', '1105', '1106':
                payload.write(self.client_id.encode(encoding='ascii'))
                payload.write(file_name.encode(encoding='ascii'))

        payload.seek(0)
        bin_stream.write(((len(payload.getbuffer()))).to_bytes(length=4,byteorder='little'))
        bin_stream.write(payload.read())

        bin_stream.seek(0)
        return bin_stream.read()

if __name__ == "__main__":
    c = client()







