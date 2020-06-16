import hashlib
from funcs.encrypt_tool import *
import funcs.obu_object

class Authentication_Server :
    def __init__(self):
        ## PSK is preshare among LEs and the AS
        ## x is a secret key protected by the AS
        ## PSK and x is random string
        self.PSK = "6ae0801fb489ef5e2b552344203830cdb1379e3111a755b2459509574fc8cb32aa5f3e5b3d11ef598147602821303f8a8e8b55952944eca5633aa30975045ef0"
        self.x   = "102ace8c3b3e9c377a6dc410466a75504b96a5465edaba5d9713309d129008470f160bda8e49149c02a15b34d236d329054e220b548ad1dc6fecc11edefb931a"

        self.Print_init_msg()
    def Print_init_msg(self):
        print("-------------------------")
        print("Authentication Server On ")
        print("-------------------------")


    def Protocol_run(self, ID, PW):
        ## A = h(ID || x)
        ## B = h(A
        ## C = h(PW) xor B
        ## D = PSK xor A
        A = SHA512(ID + self.x )
        B = SHA512(A)
        PW_hash = SHA512(PW)
        C = XOR_String(PW_hash,B)
        D = XOR_String( self.PSK,A)
        return B, C, D, ID

if __name__ == '__main__' :
     AS = Authentication_Server()
     B,C,D, ID = AS.Protocol_run("cat2","1234562")
     print( "ID  is  {:<}".format( ID ))
     print( "B   is {:<}".format(B) )
     print( "C   is {:<}".format(C))
     print ("D   is {:<}".format(D) )






