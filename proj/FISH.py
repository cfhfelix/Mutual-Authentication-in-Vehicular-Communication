#MV
import socket
import json
from funcs.obu_object import *
from funcs.encrypt_tool import *
from funcs.options_method import *


addr_cli = ('127.0.0.1', 3456)  #與其他V溝通用(這邊是client的角色)
s_cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)



while True:
    #要做甚麼動作
    print("R: Registration #only performed once")
    print("A: Authentication with TV")
    print("C: Communication")
    print("***Please input option")
    option = input()
    if not option:
        break
    
################################################################
    if(option == "R") :
        FISH = Registration("FISH")    ##註冊並將資訊存入OBU
        
###############################################################
    elif(option == "A") :
        if Login(FISH) :
            print("-------------------------")
            print("Authentication Procedure")
            print("-------------------------")
            option = "A"
            s_cli.sendto(option.encode(), addr_cli) #告訴LE要做A還是C

            AID_i, M1, M2, D = FISH.SendToLE() #Auth(1)
            
            authreq = {}
            authreq['AID_i'] = AID_i
            authreq['M1'] = M1
            authreq['M2'] = M2
            authreq['D'] = D
            authreq = json.dumps(authreq) #轉為json格式
            s_cli.sendto(authreq.encode(), addr_cli)
            
            authresult, addr = s_cli.recvfrom(2048)
            authresult = authresult.decode()
            authresult = json.loads(authresult)  #json解碼
            AIDj = authresult['AID_j']
            M3 = authresult['M3']
            M4 = authresult['M4']
            M5 = authresult['M5']

            skmsg = {}
            skmsg['checkmsg'] = FISH.ReceiveFromLE(AIDj, M3, M4, M5) #Auth(5)
            skmsg = json.dumps(skmsg) #轉為json格式
            s_cli.sendto(skmsg.encode(), addr_cli)

            #得知自己是否驗證成功(接收LE傳來的訊息)
            authfin, addr = s_cli.recvfrom(2048)
            authfin = authfin.decode()
            if(authfin == "OK") :
                print("Authentication Success!")
            else : 
                print("Authentication BYE QQ")
        else :
            print("Login fail!")
            #break
        
###############################################################
    elif(option == "C") :
        print("-------------------------")
        print("Communication Procedure")
        print("-------------------------")
        ##---call function #### 回傳 AIDi, M1, M2
        s_cli.sendto(option.encode(), addr_cli) #告訴LE要做A還是C
        AID_i, M1, M2 = FISH.client_TV_TV_first_connect()
        comreq = {}
        comreq['AID_i'] = AID_i
        comreq['M1'] = M1
        comreq['M2'] = M2
        comreq = json.dumps(comreq) #轉為json格式
        s_cli.sendto(comreq.encode(), addr_cli)

        comresult, addr = s_cli.recvfrom(2048)
        comresult = comresult.decode()
        comresult = json.loads(comresult)  #json解碼
        AID_j = comresult['AID_j']
        M3 = comresult['M3']
        M4 = comresult['M4']
        ##---call function #### 代入 AIDj, M3, M4 回傳 SKijCom, hN4
        Msg = FISH.client_TVtoTV_second_connect(AID_j, M3, M4)
        
        skmsgCom = {}
        skmsgCom['Msg'] = Msg
        skmsgCom = json.dumps(skmsgCom) #轉為json格式
        s_cli.sendto(skmsgCom.encode(), addr)

        checkfin, addr = s_cli.recvfrom(2048)
        checkfin = checkfin.decode()
        if(checkfin == "OK"):
            print("connect success\n")
        elif(checkfin == "NO"):
            print("connect fail\n")
        
# s_ser.close()
s_cli.close()
