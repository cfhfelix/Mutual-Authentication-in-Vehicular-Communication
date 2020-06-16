import socket
import json
from funcs.authentication_Serve import *

AS = Authentication_Server()

address = ('127.0.0.1', 1234)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(address)

while True: 
    option, addr = s.recvfrom(2048)
    if not option:
        print("client has exist")
        break
    option = option.decode()
    #收到 client 要做甚麼動作 
    print("Option:", option, "from", addr)
    if(option == "R") :
        regmsg, addr = s.recvfrom(2048)
        regmsg = regmsg.decode()
        regmsg = json.loads(regmsg)  #json解碼
        ID = regmsg["ID"]
        PW = regmsg["PW"]
        print(regmsg)
        
        B, C, D, ID = AS.Protocol_run(ID, PW)
               
        regresult = {}
        regresult['ID'] = regmsg["ID"]#ID
        regresult['B'] = B
        regresult['C'] = C
        regresult['D'] = D
        regresult = json.dumps(regresult) #轉為json格式
        print("-------------------------")  # 準備接收ID、PW
        print("Registration Procedure")
        print("AS PSK is {}".format(AS.PSK))
        print("B      is {}".format(B))
        print("C      is {}".format(C))
        print("D      is {}".format(D))
        print("-------------------------")
        s.sendto(regresult.encode(), addr)

        
s.close()
