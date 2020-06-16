#MV
import socket
import json
import threading
from _thread import *
from funcs.obu_object import *
from funcs.encrypt_tool import *
from funcs.options_method import *

addr_ser = ('127.0.0.1', 9012)  #與其他V溝通用(這邊是server的角色)
s_ser = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s_ser.bind(addr_ser)

addr_cli = ('127.0.0.1', 3456)  #與其他V溝通用(這邊是client的角色)
s_cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

###

        
while True:
    #要做甚麼動作
    print("R: Registration #only performed once")
    print("A: Authentication")
    print("C: Communication")
    print("S: Server Mode")
    print("***Please input option")
    option = input()
    if not option:
        break
    
################################################################
    if(option == "R") :
        CAT = Registration("CAT")    ##註冊並將資訊存入OBU
        
###############################################################
    elif(option == "A") :
        if Login(CAT) :
            Authentication(CAT)
        else :
            print("Login fail!")
            #break
        
###############################################################
    elif(option == "C") :
        print("-------------------------")
        print("Communication Procedure - client")
        print("-------------------------")
        ##---call function #### 回傳 AIDi, M1, M2
        s_cli.sendto(option.encode(), addr_cli) #告訴LE要做A還是C
        AID_i, M1, M2 = CAT.client_TV_TV_first_connect()
        comreq = {}
        comreq['AID_i'] = AID_i
        comreq['M1'] = M1
        comreq['M2'] = M2
        comreq = json.dumps(comreq) #轉為json格式
        s_cli.sendto(comreq.encode(), addr_cli)
        print("already send!")

        comresult, addr = s_cli.recvfrom(2048)
        comresult = comresult.decode()
        comresult = json.loads(comresult)  #json解碼
        AID_j = comresult['AID_j']
        M3 = comresult['M3']
        M4 = comresult['M4']
        ##---call function #### 代入 AIDj, M3, M4 回傳 SKijCom, hN4
        Msg = CAT.client_TVtoTV_second_connect(AID_j, M3, M4)
        
        skmsgCom = {}
        skmsgCom['Msg'] = Msg
        skmsgCom = json.dumps(skmsgCom) #轉為json格式
        s_cli.sendto(skmsgCom.encode(), addr)

        checkfin, addr = s_cli.recvfrom(2048)
        checkfin = checkfin.decode()
        if( checkfin == "OK"):
            print("connect success\n")
        elif( checkfin == "NO" ):
            print("connect fail\n")
        
###############################################################      
    elif(option == "S") :
        print("-------------------------")
        print("Communication Procedure - server")
        print("-------------------------")
        while True:
            comreq, addr = s_ser.recvfrom(2048)
            comreq = comreq.decode()
            comreq = json.loads(comreq)  #json解碼

            
            AID_i = comreq['AID_i']
            M1 = comreq['M1']
            M2 = comreq['M2']

            AID_j, M3, M4 = CAT.server_TVtoTV_first_connect(AID_i, M1, M2)
             
            comresult = {}
            comresult['AID_j'] = AID_j
            comresult['M3'] = M3
            comresult['M4'] = M4
            comresult = json.dumps(comresult) #轉為json格式
            s_ser.sendto(comresult.encode(), addr)

            skmsgCom, addr = s_ser.recvfrom(2048)
            skmsgCom = skmsgCom.decode()
            skmsgCom = json.loads(skmsgCom)  #json解碼
            Msg = skmsgCom['Msg']
            if (CAT.Server_final_check(Msg)):
                s_ser.sendto("OK".encode(), addr)
                print("connect success\n")
                s.close()
            else :
                s_ser.sendto("NO".encode(), addr)
                print("connect fail\n")



    

