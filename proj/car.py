import socket
import json
import threading
from _thread import *
from funcs.obu_object import *
from funcs.encrypt_tool import *
from funcs.options_method import *

class Car:
    def __init__(self, name):
        self.name = ""

        self.server_port = 8080

        self.client_port = 8080

        self.addr_AS = ('127.0.0.1', 1234)  # AS 用
        self.socket_AS = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.addr_LE = ('127.0.0.1', 5678)  # LE 用
        self.socket_LE = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#### --------- server --------   ######
    def server_create(self, port):
        self.server_port = port
    def server_connect(self, addr_port):
        addr_ser = ('127.0.0.1', addr_port)  # 與其他V溝通用(這邊是server的角色)
        s_ser = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s_ser.bind(addr_ser)



#### --------- client --------   ######

    def client_create(self, port):
        self.client_port = port
    def client_connect(self, addr_port):
        return False


#### --------- func --------   ######

    def Registration(self, name):  ##與AS註冊
        print("-------------------------")
        print("Registration Procedure")
        print("-------------------------")
        option = "R"
        self.socket_AS.sendto(option.encode(), self.addr_AS)
        print("Input ID and Password :")
        identity = {}
        temp_ID = input("ID = ")
        identity['ID'] = SHA512(temp_ID)
        identity['PW'] = input("PW = ")
        # OBU_name = input("name = ")
        regmsg = json.dumps(identity)  # 轉為json格式
        self.socket_AS.sendto(regmsg.encode(), self.addr_AS)

        regresult, addr = self.socket_AS.recvfrom(2048)
        # print(regresult)
        regresult = regresult.decode()
        regresult = json.loads(regresult)  # json解碼
        B = regresult['B']
        C = regresult['C']
        D = regresult['D']
        ID = regresult['ID']

        NEW_OBU = OBU_object(B, C, D, ID, name)
        s.close()
        return NEW_OBU

    def Login(self,OBU):  # 本地端以OBU登入驗證
        print("-------------------------")
        print("Login Procedure")
        print("-------------------------")
        print("Input ID and Password :")
        logid = input("ID = ")
        logpw = input("PW = ")
        if OBU.User_Check(SHA512(logid), logpw):
            return True
        else:
            return False

    def Authentication(self, OBU):
        print("-------------------------")
        print("Authentication Procedure")
        print("-------------------------")
        option = "A"
        self.socket_LE.sendto(option.encode(), self.addr_LE)  # 告訴LE要做A還是C

        AID_i, M1, M2, D = OBU.SendToLE()  # Auth(1)

        authreq = {}
        authreq['AID_i'] = AID_i
        authreq['M1'] = M1
        authreq['M2'] = M2
        authreq['D'] = D
        authreq = json.dumps(authreq)  # 轉為json格式
        self.socket_LE.sendto(authreq.encode(), self.addr_LE)

        authresult, addr =  self.socket_LE.recvfrom(2048)
        authresult = authresult.decode()
        authresult = json.loads(authresult)  # json解碼
        AIDj = authresult['AID_j']
        M3 = authresult['M3']
        M4 = authresult['M4']
        M5 = authresult['M5']

        skmsg = {}
        skmsg['checkmsg'] = OBU.ReceiveFromLE(AIDj, M3, M4, M5)  # Auth(5)
        skmsg = json.dumps(skmsg)  # 轉為json格式
        self.socket_LE.sendto(skmsg.encode(), self.addr_LE)

        # 得知自己是否驗證成功(接收LE傳來的訊息)
        authfin, addr =  self.socket_LE.recvfrom(2048)
        authfin = authfin.decode()
        if (authfin == "OK"):
            print("Authentication Success!")
        else:
            print("Authentication BYE QQ")

