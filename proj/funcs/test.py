# -*-coding:utf-8-*-
from obu_object import OBU_object
from authentication_Serve import *
from law_execute import *
if __name__ == '__main__':
    # print("this is test")
    AS = Authentication_Server()
    cat_init = AS.Protocol_run(SHA512("cat"),"1234562")
    OBU_cat = OBU_object(cat_init[0], cat_init[1], cat_init[2], cat_init[3],"cat")

    dog_init = AS.Protocol_run( SHA512("dog"), "NMSL")
    OBU_dog = OBU_object(dog_init[0], dog_init[1], dog_init[2], dog_init[3],"dog")

    fish_init = AS.Protocol_run(SHA512("fish"), "fishadmin")
    OBU_fish = OBU_object(fish_init[0], fish_init[1], fish_init[2], fish_init[3], "fish")
    LE = Law_execute()
    if OBU_cat.User_Check( SHA512("cat"),"1234562"): ## login
        ## 初始註冊成功 我有一台車車了
        ## 下一步先與LE連線
        OBU_cat_LE = OBU_cat.SendToLE()
        cat_LE_OBU = LE.check_Protocol(OBU_cat_LE[0],OBU_cat_LE[1], OBU_cat_LE[2],OBU_cat_LE[3])
        cat_OBU_LE_Msg = OBU_cat.ReceiveFromLE(cat_LE_OBU[0],cat_LE_OBU[1],cat_LE_OBU[2],cat_LE_OBU[3])
        if LE.Check_Nonce_2(cat_OBU_LE_Msg):
            ## 到這邊表示了OBU和LE認證合法
            # print(OBU_cat.getPSK())
            print("OK cat")
        OBU_dog_LE = OBU_dog.SendToLE()
        dog_LE_OBU = LE.check_Protocol(OBU_dog_LE[0], OBU_dog_LE[1], OBU_dog_LE[2], OBU_dog_LE[3])
        dog_OBU_LE_Msg = OBU_dog.ReceiveFromLE(dog_LE_OBU[0], dog_LE_OBU[1], dog_LE_OBU[2], dog_LE_OBU[3])
        if LE.Check_Nonce_2(dog_OBU_LE_Msg):
            ## 到這邊表示了OBU和LE認證合法
            # print(OBU_dog.getPSK())
            print("OK dog")

        ## 有了cat和dog兩台合法車 測試相互連線的問題
        ## client : cat , server:dog
        OBU_cat_to_OBU_dog_first = OBU_cat.client_TV_TV_first_connect()
        OBU_dog_to_OBU_cat_connect = OBU_dog.server_TVtoTV_first_connect(OBU_cat_to_OBU_dog_first[0],OBU_cat_to_OBU_dog_first[1],OBU_cat_to_OBU_dog_first[2])
        OBU_cat_Msg = OBU_cat.client_TVtoTV_second_connect(OBU_dog_to_OBU_cat_connect[0],OBU_dog_to_OBU_cat_connect[1],OBU_dog_to_OBU_cat_connect[2])
        if OBU_dog.Server_final_check(OBU_cat_Msg) :
            print("connect success")
        # print("cat2","1234562 is right" )
        #
        OBU_fish_MV = OBU_fish.SendToLE()
        fish_MV_OBU = OBU_cat.check_Protocol(OBU_fish_MV[0], OBU_fish_MV[1], OBU_fish_MV[2], OBU_fish_MV[3])
        fish_OBU_MV_Msg = OBU_fish.ReceiveFromLE(fish_MV_OBU[0], fish_MV_OBU[1], fish_MV_OBU[2], fish_MV_OBU[3])
        if OBU_cat.Check_Nonce_2(fish_OBU_MV_Msg):
            print("OK fish")

        ## fish 和 dog兩台合法車 測試相互連線的問題
        ## client : fish, server:dog
        OBU_fish_to_OBU_dog_first = OBU_fish.client_TV_TV_first_connect()
        OBU_dog_to_OBU_fish_connect = OBU_dog.server_TVtoTV_first_connect(OBU_fish_to_OBU_dog_first[0],
                                                                         OBU_fish_to_OBU_dog_first[1],
                                                                         OBU_fish_to_OBU_dog_first[2])
        OBU_fish_Msg = OBU_fish.client_TVtoTV_second_connect(OBU_dog_to_OBU_fish_connect[0], OBU_dog_to_OBU_fish_connect[1],
                                                           OBU_dog_to_OBU_fish_connect[2])
        if OBU_dog.Server_final_check(OBU_fish_Msg):
            print("Fish and dog connect success")
    else :
        print("cat2","1234562 is false" )




