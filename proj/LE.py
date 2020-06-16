#LE or another TV
import socket
import json
from funcs.law_execute import *

addr_tov = ('127.0.0.1', 5678)  #與MV連線用
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(addr_tov)

LE = Law_execute()   #宣告LE物件

while True:
    option, addr = s.recvfrom(2048)
    if not option:
        print("client has exist")
        break
    option = option.decode()
    #收到 client 要做甚麼動作 
    #print("Option:", option, "from", addr)
    
##########################################################
    if(option[0] == "A") :
        print("-------------------------")
        print("Authentication Procedure")
        print("-------------------------")
        authreq, addr = s.recvfrom(2048)
        authreq = authreq.decode()
        authreq = json.loads(authreq)  #json解碼
        AID_i = authreq["AID_i"]
        M1 = authreq["M1"]
        M2 = authreq["M2"]
        D = authreq["D"]
        
        AID_j, M3, M4, M5 = LE.check_Protocol(AID_i, M1, M2, D)    #LE(3)
                
        authresult = {}
        authresult['AID_j'] = AID_j
        authresult['M3'] = M3
        authresult['M4'] = M4
        authresult['M5'] = M5
        authresult = json.dumps(authresult) #轉為json格式
        s.sendto(authresult.encode(), addr)
        


        ##收到 SK 並存起來
        skmsg, addr = s.recvfrom(2048)
        skmsg = skmsg.decode()
        skmsg = json.loads(skmsg)  #json解碼
        checkmsg = skmsg['checkmsg']
        if(LE.Check_Nonce_2(checkmsg)) :  #LE(7)
            print("Authentication Success!")
            s.sendto("OK".encode(), addr)
        else:
            print("Authentication BYE QQ")
            s.sendto("NO".encode(), addr)
            break

##########################################################
    elif(option[0] == "C") :
        print("Communication Procedure\n")
        comreq, addr = s.recvfrom(2048)
        comreq = comreq.decode()
        comreq = json.loads(comreq)  #json解碼

        AIDi = comreq['AIDi']
        M1 = comreq['M1']
        M2 = comreq['M2']

        #---call function #### 帶入 AIDi, M1, M2 回傳 AIDj, M3, M4

        comresult = {}
        comresult['AIDj'] = "AIDj"
        comresult['M3'] = "M3"
        comresult['M4'] = "M4"
        comresult = json.dumps(comresult) #轉為json格式
        s.sendto(comresult.encode(), addr)
        

        skmsgCom, addr = s.recvfrom(2048)
        skmsgCom = skmsgCom.decode()
        skmsgCom = json.loads(skmsgCom)  #json解碼
        skmsgCom['SKijCom'] = "SKijCom"
        skmsgCom['hN4'] = "hN4"
        #---call function #### 帶入 hN4 回傳 check 結果
        
s.close()
