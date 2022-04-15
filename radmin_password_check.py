# -*-  coding = utf-8 -*-
# @Time : 2022/4/13 17:00
# @Autor : xbaogua
# @File : radmin_password_check.py
# @Reference : https://www.synacktiv.com/publications/cracking-radmin-server-3-passwords.html

import hashlib


def read_reg(value):
    key = list(map(lambda x: int(x, 16), [value[i:i + 2] for i in range(0, len(value), 2)]))
    # key = list(map(lambda x: int(x, 16), value.replace(" ", "").replace("\n", "").replace("\\", "").split(",")))

    content = {}
    i = 0
    while i < len(key):
        dtyp = key[i + 1] * 0x100 + key[i]
        dlen = key[i + 2] * 0x100 + key[i + 3]
        i += 4
        content[dtyp] = (bytes(key[i:i + dlen]))
        i += dlen

    username = content[16]
    modulus = content[48]
    g = content[64]
    salt = content[80]
    hashh = content[96]

    print("Username :", username.replace(b"\x00", b""))
    print("Modulus :", modulus.hex())
    print("Generator :", g.hex())
    print("Salt :", salt.hex())
    print("Verifier :", hashh.hex())

    return username, modulus, g, salt, hashh


def to_utf16(st):
    newar = []
    for l in st:
        newar.append(l)
        newar.append(0)
    return bytes(newar)


def generator_hash(username, modulus, g, salt, password):
    modulus = int(modulus.hex(), 16)
    g = int(g.hex(), 16)
    password = to_utf16(password.encode('utf-8'))

    #
    concat = username + b":" + password
    shahash = hashlib.sha1(salt + hashlib.sha1(concat).digest()).digest()
    Verifier = hex(pow(g, int(shahash.hex(), 16), modulus))[2:]
    #
    print(f"======Generator======\nVerifier : {Verifier}")
    #
    return Verifier


def compare_ver(reg_ver, gen_ver):
    reg_ver = reg_ver.hex()
    return reg_ver == gen_ver


def radmin_check(reg_value, user_password):
    username, modulus, g, salt, hashh = read_reg(reg_value)
    # 生成hash
    gener_ver = generator_hash(username=username, modulus=modulus, g=g, salt=salt, password=user_password)
    #
    check_res = compare_ver(hashh, gener_ver)
    #
    user_name = username.replace(b"\x00", b"").decode("utf-8")
    if check_res:
        print(f"username is {user_name} , password is {user_password} !!!")
    else:
        print(f"{user_password} is not password")
    #
    return check_res, user_name, user_password


if __name__ == "__main__":
    # 查询注册表
    # REG QUERY "HKLM\SOFTWARE\WOW6432Node\Radmin\v3.0\Server\Parameters\Radmin Security\1"
    value = "1000000E7800620061006F00670075006100300001009847FC7E0F891DFD5D02F19D587D8F77AEC0B980D4304B0113B406F23E2CEC58CAFCA04A53E36FB68E0C3BFF92CF335786B0DBE60DFE4178EF2FCD2A4DD09947FFD8DF96FD0F9E2981A32DA95503342ECA9F08062CBDD4AC2D7CDF810DB4DB96DB70102266261CD3F8BDD56A102FC6CEEDBBA5EAE99E6127BDD952F7A0D18A79021C881AE63EC4B3590387F548598F2CB8F90DEA36FC4F80C5473FDB6B0C6BDB0FDBAF4601F560DD149167EA125DB8AD34FD0FD45350DEC72CFB3B528BA2332D6091ACEA89DFD06C9C4D18F697245BD2AC9278B92BFE7DBAFAA0C43B40A71F1930EBC4FD24C9E5A2E5A4CCF5D7F51544D70B2BCA4AF5B8D37B379FD7740A682F400000010550000020FE6CFC09B18AC2BA7DB4EFA19A293C1E3BFB1A0BBCC3535D450496584B55B8D4600001007DFA176965CAD694181753D8226DA4DDDC46DB3EA043BFF053A67D44C054EE9D9BF75F76097B9D8C2417781CBF555D2C11919E23240594C4AECB8361F6BDC3839012B0962724123C39D7A3B1162F703D8388E4FD485D6162B0E734FB27A6252F2793C06CBD184B42CB660006E07C026FA4096EA595624F780A897AC3EDEA143FF146D4013E2D7E85B49FC733911B9EED49945E35CCD3C21C6AC7AF7963096007165C05C91576FBFE10494A2E260A19B0D6F98F677621DF9F79847AE08BCE1F9D1BB202CD49C64A13C239B33FC618A1BEE4E60C5DA221A885AF5EFFC01561CF909E4C552F43C4B1869C34DED4D73EA6BC97AD342A272EFF7A987203A0193617B220000004FF010000"
    #

    radmin_check(reg_value=value, user_password="radmin!@#123")
