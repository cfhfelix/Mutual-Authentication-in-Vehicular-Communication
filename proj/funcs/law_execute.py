import hashlib
from funcs.encrypt_tool import *



class Law_execute:
    def __init__(self):
        ## PSK is preshare among LEs and the AS
        ## x is a secret key protected by the AS
        ## PSK and x is random string
        self.PSK = "6ae0801fb489ef5e2b552344203830cdb1379e3111a755b2459509574fc8cb32aa5f3e5b3d11ef598147602821303f8a8e8b55952944eca5633aa30975045ef0"

        self.N2 = ""
        self.SK = ""

        self.Print_init_msg()
    def Print_init_msg(self):
        print("-------------------------")
        print("Law Execute Server on    ")
        print("-------------------------")
    def check_Protocol(self,AID_i,M1,M2,D):
        ## if return false , mean some proble in first check
        first_check = False
        A = XOR_String( D,self.PSK)                    ## A = D xor PSK
        # print(self.PSK)
        # print("A = {}".format(A))
        A_hash1 = SHA512(A)                           ## h(A)
        A_hash2 = SHA512(A_hash1)                     ## h^2(A)
        N1  = XOR_String(M1,A_hash2)                  ## find N1   N1 = M1 xor h^2(A)
        N1_hash = SHA512(N1)                          ## h(N1)
        ID = XOR_String(AID_i, N1_hash)               ## ID = AID xor h(N1)
        # print("ID = {}".format(ID))
        first_check_string = SHA512( N1+AID_i+D)  ## check h(N1||AID||D) _
        if first_check_string != M2 :
            first_check = True
            print("some proble in LE first check")
            return False
        #### first check


        self.N2 = Generate_Nonce()                    ## generate Nonce
        AID_j = XOR_String( ID,self.N2)                     ## AID_j = ID xor N2
        self.SK = SHA512( N1 + self.N2 )                        ## SK = h(N1||N2)
        N1_hash2 = SHA512(N1_hash)                    ## h^2(N1)
        M3 = XOR_String( self.N2, N1_hash2)                  ## M3 = N2 xor h^2(N1)
        ID_hash = SHA512(ID)                          ## h(ID)
        M4 = XOR_String( A, ID_hash)                  ## M4 = A xor h(ID)
        M5 = SHA512( M4 + self.N2 + AID_j)
        print("---------- LE process -----------" )
        print("{} is authenicated".format(AID_i))
        print("PSK : {}".format(self.PSK))
        print("OBU Nonce1 : {}".format( N1) )
        print("Gerenate a Nonce2 : {}".format(self.N2) )
        print("OBU AID_i : {}".format(AID_i ))
        print("LE AID_j : {}".format(AID_j) )
        print("M3    : {}".format(M3))
        print("M4    : {}".format(M4))
        print("M5    : {}".format(M5))
        return (AID_j,M3,M4,M5)

     ### step(7)
    def Check_Nonce_2(self,Msg):
        ## check h(N2)
        ## Msg = SK xor h(N2)
        ## h(N2) = SK xor Msg
        ## hint: h(N2) means N2_hash_client
        N2_hash_client = XOR_String(Msg,self.SK)
        N2_hash = SHA512(self.N2)
        if N2_hash_client == N2_hash :
            print("---------- LE process -----------")
            print("Authenciation Success")
            print("Session key : {}".format(self.SK))
            return True
        return False


        
















