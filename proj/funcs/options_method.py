import socket
import json
from funcs.obu_object import *
from funcs.encrypt_tool import *

#address = ('192.168.1.102', 1234)
address = ('127.0.0.1', 1234)    # AS 用
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

addr_LE = ('127.0.0.1', 5678)    # LE 用
s_LE = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def Registration(name):  ##與AS註冊
    print("-------------------------")
    print("Registration Procedure")
    print("-------------------------") 
    option = "R"
    s.sendto(option.encode(), address) 
    print("Input ID and Password :")
    identity = {}
    temp_ID = input("ID = ")
    identity['ID'] = SHA512(temp_ID)
    identity['PW'] = input("PW = ")
    #OBU_name = input("name = ")
    regmsg = json.dumps(identity) #轉為json格式
    s.sendto(regmsg.encode(), address)

    regresult, addr = s.recvfrom(2048)
    #print(regresult)
    regresult = regresult.decode()
    regresult = json.loads(regresult)  #json解碼
    B = regresult['B']
    C = regresult['C']
    D = regresult['D']
    ID = regresult['ID']

    NEW_OBU = OBU_object(B, C, D, ID, name)
    s.close()
    return NEW_OBU

def Login(OBU): #本地端以OBU登入驗證
    print("-------------------------")
    print("Please Login first")
    print("-------------------------")
    print("Login Procedure")
    print("-------------------------")
    print("Input ID and Password :")
    logid = input("ID = ")
    logpw = input("PW = ")
    if OBU.User_Check(SHA512(logid), logpw):
        return True
    else :
        return False

def Authentication(OBU):
    print("-------------------------")
    print("Authentication Procedure")
    print("-------------------------")
    option = "A"
    s_LE.sendto(option.encode(), addr_LE) #告訴LE要做A還是C

    AID_i, M1, M2, D = OBU.SendToLE() #Auth(1)
    
    authreq = {}
    authreq['AID_i'] = AID_i
    authreq['M1'] = M1
    authreq['M2'] = M2
    authreq['D'] = D
    authreq = json.dumps(authreq) #轉為json格式
    s_LE.sendto(authreq.encode(), addr_LE)
    
    authresult, addr = s_LE.recvfrom(2048)
    authresult = authresult.decode()
    authresult = json.loads(authresult)  #json解碼
    AIDj = authresult['AID_j']
    M3 = authresult['M3']
    M4 = authresult['M4']
    M5 = authresult['M5']

    skmsg = {}
    skmsg['checkmsg'] = OBU.ReceiveFromLE(AIDj, M3, M4, M5) #Auth(5)
    skmsg = json.dumps(skmsg) #轉為json格式
    s_LE.sendto(skmsg.encode(), addr_LE)

    #得知自己是否驗證成功(接收LE傳來的訊息)
    authfin, addr = s_LE.recvfrom(2048)
    authfin = authfin.decode()
    if(authfin == "OK") :
        print("Authentication Success!")
    else : 
        print("Authentication BYE QQ")

