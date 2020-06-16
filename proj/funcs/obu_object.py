
from funcs.encrypt_tool import *
from funcs.authentication_Serve import  *

class OBU_object :
    def __init__(self, B, C, D, ID, Name):
        self.Name = Name
        self.ID = ID
        self.B  = B
        self.C  = C
        self.D  = D
        self.Nonce_1 = ""
        self.SK_LE = ""
        print("------------OBU-------------")
        print("Create a new OBU")
        print("ID is {}".format(ID))
        print("Name is {}".format(Name))
        ## if have mean TV,and can become LE
        self.A = ""
        self.PSK = ""


        ## warning: The parameter is for TV and TV
        self.Nonce_3 = ""
        self.Nonce_4 = ""
        self.SK_OBU_server = ""
        self.SK_OBU_client = ""

        ## become LE
        self.N2 = ""
        self.SK_LE_OBU = ""
    def Print_init_msg(self):
        print("-------------------------")
        print("new  OBU                 ")
        print("-------------------------")

    def check_ID(self, ID):
        ## check id
        if ID == self.ID :
            return True
        return False
    def check_B(self, ID,PW):
        ## check h(PW) xor C == B
        PW_hash = SHA512(PW)
        Xor_s  = XOR_String(PW_hash,self.C)
        if Xor_s == self.B :
            return True
        return False
    def User_Check(self, ID,PW):
        if ( self.check_B(ID,PW) and self.check_ID(ID) ) :
            print("Login Success")
            print( "{:8} is login".format(self.Name))
            return True
        print(ID, " " + PW + " is false" )
        return False

    ## OBU to LE
    def SendToLE(self):
        try:
            self.Nonce_1 = Generate_Nonce()     ## generate Nonce
            B_hash = SHA512(self.B)             ## h(B)
            M1 = XOR_String(B_hash, self.Nonce_1)   ## M1 = h(B) xor N1
            Nonce_1_hash = SHA512(self.Nonce_1)   ## h(Nonce)
            AID_i = XOR_String(Nonce_1_hash,self.ID)  ## AID_i = h(N1) xor ID
            M2 = SHA512(self.Nonce_1 + AID_i + self.D)

            print("------------OBU-------------")
            print("Start authenicate with LE")
            print("AID_i : {}".format(AID_i))
            print("M1    : {}".format(M1))
            print("M2    : {}".format(M2))
            print("OBU Nonce1 : {}".format( self.Nonce_1) )
            return (AID_i, M1, M2, self.D)
        except:
            print("Some problem in OBU_SendToLE , CryCry")
            return False

    ## LE to OBU
    def ReceiveFromLE(self, AID_j, M3, M4, M5):
        try:
            Nonce_1_hash2 = SHA512( SHA512(self.Nonce_1)) ## h^2(N1)
            N2 = XOR_String(M3,Nonce_1_hash2)             ## N2 = M3 xor h^2(N1)
            second_check_string = SHA512(M4 + N2 + AID_j)
            if second_check_string != M5 :
                print("some proble in ReceiveFromLE second check")
                return False
            # print("ID = {}".format(self.ID))
            ID_hash = SHA512(self.ID)                     ## h(ID)
            self.A = XOR_String(M4, ID_hash)              ## A = M4 xor h(ID)
                                                          # and Keep A in OBU
            # print("A = {}".format(self.A))
            self.SK_LE = SHA512(self.Nonce_1 + N2 )          ## SK = H(N1|| N2)
            N2_hash = SHA512(N2)                          ## h(N2)
            Msg = XOR_String(self.SK_LE,N2_hash)             ## SK xor h(n2)

            self.PSK = XOR_String(self.A,self.D)               ## PSK = A xor D
            # print(self.PSK)                                              ## The key point why TV can auth the MV
            print("------------OBU-------------")
            print("Start authenicate with LE")
            print("OBU AID_i : {}".format( self.ID))
            print("LE AID_j : {}".format(AID_j))
            print("LE Nonce2 : {}".format(N2))
            print("Session key    : {}".format(self.SK_LE))
            print("PSK    : {}".format(self.PSK))
            return Msg

        except:
            print("Some problem in OBU_ReceiveFromLE , CryCry")
            return False

    ## client    OBU TV to OBU TV
    def client_TV_TV_first_connect(self):
        try:
            self.Nonce_3 = Generate_Nonce()                  ## Generate N3
            # print(self.PSK)
            # print(self.Nonce_3)
            AID_i = XOR_String(self.Nonce_3, self.ID)        ## AID = N3 xor ID
            M1 = XOR_String(self.PSK,self.Nonce_3)                ## M1 = PSK xor N3
            M2 = XOR_String(self.PSK, SHA512(AID_i+ self.Nonce_3)) ## M2 = PSK xor h(AID||N3)

            print("OBU AID : {}".format( AID_i ) )
            print("OUB Nonce3 {}".format(self.Nonce_3))
            print("M1 : {}".format(M1))
            print("M2 : {}".format(M2))

            return (AID_i, M1, M2)
        except:
            print("Some problem in OBU_TVtoMV , CryCry")
            return False
    def client_TVtoTV_second_connect(self,AID_j,M3, M4):
        N4 = XOR_String(M3, self.PSK)  ## N3 = M1 xorPSK
        AID_i_plus_N4_hN3_hash_client = XOR_String(M4, self.PSK)  ## client: h(AID_i || N4|| h(N3)) = M3 xor PSK
        AID_i_plus_N4_hN3_hash_server = SHA512(AID_j + N4 + SHA512(self.Nonce_3))  ## server: h(AID_i ||  N4|| h(N3))
        if AID_i_plus_N4_hN3_hash_server != AID_i_plus_N4_hN3_hash_client:  ## check
            print("some proble in client_TVtoTV_second_connect check")
            return False
        self.SK_OBU_client = SHA512(self.Nonce_3 + N4 + self.PSK)  ## SK = h(N3||N4||PSK)
        Msg = XOR_String( self.SK_OBU_client, SHA512(N4))     ## SK xor h(N4)
        print("Session key : {}".format(self.SK_OBU_client))
        print("Msg : {}".format(Msg))
        return Msg


    ## server MV to OBU TV
    def server_TVtoTV_first_connect(self,AID_i, M1, M2):
        N3 = XOR_String(M1,self.PSK) ## N3 = M1 xor PSK
        # print("-------")
        # print(self.PSK)
        # print(N3)
        AID_i_plus_N3_hash_client = XOR_String(M2,self.PSK)  ## client: h(AID_i || N3) = M2 xor PSK
        AID_i_plus_N3_hash_server = SHA512(AID_i+ N3)  ## server: h(AID_i || N3)
        if AID_i_plus_N3_hash_client != AID_i_plus_N3_hash_server:
            print("some proble in server_TVtoTV_first_connect check")
            return False
        self.Nonce_4 = Generate_Nonce()        ## Generate N4
        AID_j = XOR_String( self.Nonce_4,self.ID) ## AID_j = N4 xor ID
        M3 = XOR_String(self.PSK,self.Nonce_4)  ## M3 = PSK xor N4
        N3_hash = SHA512( N3 )   ## h(N3)
        M4 = XOR_String(self.PSK ,SHA512(AID_j + self.Nonce_4 + N3_hash)) ## M4 = PSK xor h(AID_j || N4 || h(N3))
        self.SK_OBU_server = SHA512( N3 + self.Nonce_4 + self.PSK )    ## SK = h( N3|| N3|| PSK)
        print("---------- OBU TV process -----------")
        print("AID_i {} try to connect".format(AID_i))
        print("OBU TV Nonce3   : {}".format(N3))
        print("M3    : {}".format(M3))
        print("M4    : {}".format(M4))
        return (AID_j,M3,M4)

    def Server_final_check(self, Msg):
        N4_hash_client = XOR_String(self.SK_OBU_server,Msg)  ## client : h(N4) = SK xor Msg
        N4_hash_server = SHA512(self.Nonce_4)
        if N4_hash_server == N4_hash_client:
            print("Session key : {}".format(self.SK_OBU_server))
            print("OBU connected success")
            return True
        return False


    ## OBU become LE

    def check_Protocol(self, AID_i, M1, M2, D):
        ## if return false , mean some proble in first check
        first_check = False
        A = XOR_String(D, self.PSK)  ## A = D xor PSK
        # print(self.PSK)
        # print("A = {}".format(A))
        A_hash1 = SHA512(A)  ## h(A)
        A_hash2 = SHA512(A_hash1)  ## h^2(A)
        N1 = XOR_String(M1, A_hash2)  ## find N1   N1 = M1 xor h^2(A)
        N1_hash = SHA512(N1)  ## h(N1)
        ID = XOR_String(AID_i, N1_hash)  ## ID = AID xor h(N1)
        # print("ID = {}".format(ID))
        first_check_string = SHA512(N1 + AID_i + D)  ## check h(N1||AID||D) _
        if first_check_string != M2:
            first_check = True
            print("some proble in LE first check")
            return False
        #### first check
        self.N2 = Generate_Nonce()  ## generate Nonce
        AID_j = XOR_String(ID, self.N2)  ## AID_j = ID xor N2
        self.SK_LE_OBU = SHA512(N1 + self.N2)  ## SK = h(N1||N2)
        N1_hash2 = SHA512(N1_hash)  ## h^2(N1)
        M3 = XOR_String(self.N2, N1_hash2)  ## M3 = N2 xor h^2(N1)
        ID_hash = SHA512(ID)  ## h(ID)
        M4 = XOR_String(A, ID_hash)  ## M4 = A xor h(ID)
        M5 = SHA512(M4 + self.N2 + AID_j)
        print("{} is authenicated".format(AID_i))
        print("OBU MV Nonce1 : {}".format( N1) )
        print("Gerenate a Nonce2 : {}".format(self.N2) )
        print("OBU MV AID_i : {}".format(AID_i ))
        print("OBU TV AID_j : {}".format(AID_j) )
        print("M3    : {}".format(M3))
        print("M4    : {}".format(M4))
        print("M5    : {}".format(M5))
        return (AID_j, M3, M4, M5)

        ### step(7)

    def Check_Nonce_2(self, Msg):
        ## check h(N2)
        ## Msg = SK xor h(N2)
        ## h(N2) = SK xor Msg
        ## hint: h(N2) means N2_hash_client
        # print(self.SK_LE)
        N2_hash_client = XOR_String(Msg, self.SK_LE_OBU)
        N2_hash = SHA512(self.N2)
        # print(N2_hash_client)
        # print(N2_hash)
        if N2_hash_client == N2_hash:
            print("---------- OBU TV process -----------")
            print("Authenciation Success")
            print("Session key : {}".format(self.SK))
            return True
        return False

    ## =======
    def getPSK(self):
        return self.PSK



