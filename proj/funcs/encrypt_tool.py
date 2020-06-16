import hashlib
import random
def SHA512( string_input ):
    ### use SHA512
    ### need Unicode-objects must be encoded before hashing
    byte_string = hashlib.sha3_512( (string_input).encode("utf-8") )
    hex_string =  byte_string.hexdigest()
    return  hex_string
def XOR_String(a,b) :
    ## len need same
    xorWord = lambda ss, cc: ''.join(chr(ord(s) ^ ord(c)) for s, c in zip(ss, cc * 100))
    c = xorWord(a,b)
    return c
def Generate_Nonce():
    a = random.randint(100000,10000000)
    nonce = SHA512(str(a))
    return nonce







