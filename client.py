from ast import Bytes
from binhex import hexbin
from ctypes import sizeof
import selectors
import socket
import io
from sys import byteorder
from typing import List, Literal
import encryptor, decryptor
from lazy_property import lazy_property
import zlib



#file is not documented. testing file for Roee. DO NOT BUNDLE TO FINALIZED PROJECT!

class client: 
    """written for test purposes onnly"""
    class client_file:
        def __init__(self,name,enc_content,enc_size,dec_content) -> None:
            self.name:str = name
            self.enc_content:Bytes = enc_content
            self.enc_size:int = enc_size
            self.dec_content:Bytes = dec_content


           

        @lazy_property
        def crc(self):
            return zlib.crc32(self.dec_content.encode('ascii'))

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
                    self.prompt()
                        
            except FileNotFoundError:
                print("me.info file not found")
                self.prompt()
            
            except FileExistsError:
                print("me.info file exists")
                pass

    @lazy_property
    def key(self):
        return encryptor.gen_rsa()

    def prompt(self):
        print("what would you like to do? \n1 - register \n2 - send file \n3 - end session\n")
        choice = input("type your choice: ")
        match choice:
            case '1':
                self.sendRequest('1100')
                self.switcher()

            case '2':
                self.sendRequest('1103')
                self.switcher()

            case '3':
                pass

    def stream_decoder(self,stream:Bytes) -> List[Bytes]:
        decoder = io.BytesIO(stream)
        lines = []
        decoder.seek(0)
        view = decoder.read()
       
        lines.append(view[0]) #server_version
        lines.append(view[1:3]) #code
        lines.append(view[3:7]) #payload_size
        size = int.from_bytes(lines[2],byteorder='little') + 7
        try:
            lines.append(view[7:size]) #payload 3
        
        except IndexError:
            print("no payload received.")
            pass

        return lines

    def switcher(self):
        lines = self.stream_decoder(self.csock.recv(1024))
        code1 = str(lines[1][0])
        code2 = str(lines[1][1])
        req = code1 + '0' + code2

        match req:
            case '2100':
                print('got 2100')
                self.client_id = lines[3][:16].hex()
                print(f"obtained my client id: {self.client_id}")
                print(f"creating me.info file")
                self.createFile()
                self.sendRequest('1101')
                self.switcher()

            case '2101':
                print('got 2101, registeration failure')
                sym = lines[3][16:]
                print(f"enc_sym: {sym}")
                self.sym_key = decryptor.decrypt_sym_key(lines[3][16:])
                print(f"aes from server: {self.sym_key}")
                self.prompt()




            case '2102':
                print('got 2102, registered succesfully')
                print(lines[3][17:])
                self.sym_key = decryptor.decrypt_sym_key(lines[3][16:])
                print(f"aes from server: {self.sym_key}")
                self.prompt()

               
            
            case '2103':
                print('got 2103')
                got_crc = lines[3][275:280]
                int_got_crc = int.from_bytes(got_crc,'little')
                print(self.current_file.crc)
                print(int_got_crc)
                if self.current_file.crc == int_got_crc:
                    print("crc confirmed")
                    self.sendRequest('1104')

                else:
                    print("crc not valid")

                self.switcher()

            case '2104':
                print('got 2104')
                self.prompt()



    
    def sendRequest(self,code):
        stream = self.constructRequest(code)
        print(f"sent request {code}")
        self.csock.sendall(stream)
        self.switcher()



    def createFile(self):
        lines = []
        lines.append(self.name.split('!')[0]+'\n') #write name to file
        lines.append(self.client_id+'\n') #write guid to file
        lines.append(encryptor.enc64(self.key[0])) #write private_key to file

        
        with open('me.info',mode='w') as file:
            file.writelines(lines)


    def constructRequest(self, req_no) -> Bytes:
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
    
        match req_no:
            case '1100':
                payload.write(self.name.encode(encoding='ascii'))

            case '1101':
                payload.write(self.name.encode(encoding='ascii'))
                
                payload.write(encryptor.enc64(self.key[1]).encode('ascii'))
                print('sending public_key: ')
                print((self.key[1]))
                print(encryptor.enc64(self.key[1]).encode(encoding='ascii'))

            case '1103':
                if self.file_path:
                    try:
                        with open(self.file_path,'r') as file:
                            content = file.read()
                            enc_content = encryptor.encrypt_content(content,self.sym_key)
                            size = len(enc_content)
                            self.current_file = self.client_file(name = file.name, enc_content = enc_content ,enc_size = size, dec_content=content)
                            
                    except FileNotFoundError:
                        print("file to send not found")
                        return
                
                payload.write(bytes.fromhex(self.client_id)) # 15
                payload.write(self.current_file.enc_size.to_bytes(4,byteorder='little')) # 19
                print(self.current_file.enc_size)
                payload.write(self.current_file.name.encode(encoding='ascii')) 
                name_size = len(self.current_file.name.encode(encoding='ascii'))
                padding = 255-name_size
                payload.write(bytes(padding)) # 274
                payload.write(self.current_file.enc_content)
                print(f"raw content to server: {self.current_file.enc_content}")
            
            case '1104', '1105', '1106':
               payload.write(self.client_id.encode(encoding='ascii')) # 15
               

        payload.seek(0)
        bin_stream.write(((len(payload.getbuffer()))).to_bytes(length=4,byteorder='little'))
        bin_stream.write(payload.read())

        bin_stream.seek(0)
        return bin_stream.read()

if __name__ == "__main__":
    c = client()







