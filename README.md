# Python-Obfuscate
A tool to obfuscate python code
# Usage
```shell
git clone https://github.com/hahbiubiubiu/Python-Obfuscate.git
cd Python-Obfuscate
python obfuscate.py <your py file>
```
# How to obfuscate
1. String -> Encode a string using base64
2. Variable -> random name
3. Attribute -> using gc

# Effect
original code：
```python
import base64
import random

MIX_C = []
for i in range(4):
    MIX_C.append([])
    for _ in range(4):
        MIX_C[i].append(random.randint(0, 256))
I_MIXC = []
for i in range(4):
    I_MIXC.append([])
    for _ in range(4):
        I_MIXC[i].append(random.randint(0, 256))
RCON = []
for _ in range(16):
    RCON.append(random.randint(0, 256) << 24)
S_BOX = []
for i in range(16):
    S_BOX.append([])
    for _ in range(16):
        S_BOX[i].append(random.randint(0, 255))
I_SBOX = []
for i in range(16):
    I_SBOX.append([])
    for _ in range(16):
        I_SBOX[i].append(random.randint(0, 255))

def gen_key():
    k = []
    for _ in range(16):
        k.append(random.randint(0, 255))
    return bytes(k)

def gen_iv():
    k = []
    for _ in range(16):
        k.append(random.randint(0, 255))
    return bytes(k)

def SubBytes(State):
    # 字节替换
    s = []
    for _ in State:
        s.append(S_BOX[_ >> 4][_ & 0xF])
    return s

def SubBytes_Inv(State):
    # 字节逆替换
    s = []
    for _ in State:
        s.append(I_SBOX[_ >> 4][_ & 0xF])
    return s

def ShiftRows(S):
    # 行移位
    return [
        S[0], S[5], S[10], S[15],
        S[4], S[9], S[14], S[3],
        S[8], S[13], S[2], S[7],
        S[12], S[1], S[6], S[11]
    ]

def ShiftRows_Inv(S):
    # 逆行移位
    return [
        S[0], S[13], S[10], S[7],
        S[4], S[1], S[14], S[11],
        S[8], S[5], S[2], S[15],
        S[12], S[9], S[6], S[3]
    ]

def _16bytes_xor(_16bytes_1, _16bytes_2):
    r = []
    for i in range(16):
        r.append(_16bytes_1[i] ^ _16bytes_2[i])
    return r

def _16bytes2num(_16bytes):
    # 16字节转数字
    return int.from_bytes(_16bytes, byteorder='big')

def num_2_16bytes(num):
    # 数字转16字节
    return num.to_bytes(16, byteorder='big')

def mod(poly):
    # poly模多项式mod
    while poly.bit_length() > 8:
        poly ^= 283 << poly.bit_length() - 9
    return poly

def mul(poly1, poly2):
    # 多项式相乘
    result = 0
    for index in range(poly2.bit_length()):
        if poly2 & (1 << index):
            result ^= poly1 << index
    return result

def Matrix_Mul(M1, M2):  # M1 = MIX_C  M2 = State
    # 用于列混合的矩阵相乘
    M = [0] * 16
    for row in range(4):
        for col in range(4):
            for Round in range(4):
                M[row + col * 4] ^= mul(M1[row][Round], M2[Round + col * 4])
            M[row + col * 4] = mod(M[row + col * 4])
    return M

def MixColumns(State):
    # 列混合
    return Matrix_Mul(MIX_C, State)

def MixColumns_Inv(State):
    # 逆列混合
    return Matrix_Mul(I_MIXC, State)

def RotWord(_4byte_block):
    # 用于生成轮密钥的字移位
    return ((_4byte_block & 0xffffff) << 8) + (_4byte_block >> 24)

def SubWord(_4byte_block):
    # 用于生成密钥的字节替换
    result = 0
    for position in range(4):
        i = _4byte_block >> position * 8 + 4 & 0xf
        j = _4byte_block >> position * 8 & 0xf
        result ^= S_BOX[i][j] << position * 8
    return result


def round_key_generator(_16bytes_key):
    # 轮密钥产生
    _16bytes_key = _16bytes2num(_16bytes_key)
    w = [
        _16bytes_key >> 96,
        _16bytes_key >> 64 & 0xFFFFFFFF,
        _16bytes_key >> 32 & 0xFFFFFFFF,
        _16bytes_key & 0xFFFFFFFF
    ] + [0] * 40
    for i in range(4, 44):
        temp = w[i - 1]
        if not i % 4:
            temp = SubWord(RotWord(temp)) ^ RCON[i // 4 - 1]
        w[i] = w[i - 4] ^ temp

    r = []
    for i in range(11):
        r.append(num_2_16bytes(
            sum([w[4 * i] << 96, w[4 * i + 1] << 64, w[4 * i + 2] << 32, w[4 * i + 3]])
        ))
    return r

def AddRoundKey(State, RoundKeys, index):
    # 异或轮密钥
    return _16bytes_xor(State, RoundKeys[index])

def aes_encrypt(plaintext_list, RoundKeys):
    State = plaintext_list
    State = AddRoundKey(State, RoundKeys, 0)
    for Round in range(1, 10):
        State = SubBytes(State)
        State = ShiftRows(State)
        State = MixColumns(State)
        State = AddRoundKey(State, RoundKeys, Round)
    State = SubBytes(State)
    State = ShiftRows(State)
    State = AddRoundKey(State, RoundKeys, 10)
    return State

def aes_decrypt(ciphertext_list, RoundKeys):
    State = ciphertext_list
    # print(State, RoundKeys)
    State = AddRoundKey(State, RoundKeys, 10)
    for Round in range(1, 10):
        State = ShiftRows_Inv(State)
        State = SubBytes_Inv(State)
        State = AddRoundKey(State, RoundKeys, 10 - Round)
        State = MixColumns_Inv(State)
    State = ShiftRows_Inv(State)
    State = SubBytes_Inv(State)
    State = AddRoundKey(State, RoundKeys, 0)
    return State

def AES_CBC(plaintext, Key, IV, enc=True):
    result = []
    ptext_list = []
    ptext_len = len(plaintext)
    for i in range(ptext_len // 16):
        ptext_list.append(plaintext[i * 16: (i + 1) * 16])
    if ptext_len % 16 != 0:
        lack_bytes = 16 - (ptext_len % 16)
        temp = plaintext[(ptext_len // 16) * 16:] + bytes([lack_bytes] * lack_bytes)
        ptext_list.append(temp)
    RoundKeys = round_key_generator(Key)
    if enc:
        for ptext16bytes in ptext_list:
            # print(ptext16bytes, IV)
            temp = _16bytes_xor(ptext16bytes, IV)
            IV = aes_encrypt(temp, RoundKeys)
            result += IV
            # print(result)
        return bytes(result)
    else:
        for ptext16bytes in ptext_list:
            temp = aes_decrypt(ptext16bytes, RoundKeys)
            temp = _16bytes_xor(temp, IV)
            IV = ptext16bytes
            result += temp
            # print(result)
        return bytes(result)

def main():
    flag = input('> Please input your flag:\n> ')
    c = [...]
    key = gen_key()
    iv = gen_iv()
    # print('key:', key)
    # print('iv:', iv)
    plaintext = flag.encode()
    ciphertext = AES_CBC(plaintext, key, iv)
    ciphertext1 = base64.b64encode(ciphertext).decode()
    result = []
    for i in range(len(ciphertext1) - 1):
        cc = ciphertext1[i]
        if cc.islower():
            result.append((ord(cc) * ord(ciphertext1[i + 1])) & 0xFF)
        elif cc.isupper():
            result.append((ord(cc) - ord(ciphertext1[i + 1])) & 0xFF)
        elif cc.isdigit():
            result.append((ord(cc) + ord(ciphertext1[i + 1])) & 0xFF)
        else:
            result.append(ord(cc) ^ ord(ciphertext1[i + 1]))
    for i in range(len(result)):
        if result[i] != c[i]:
            print('> error')
            break
    else:
        print('> right')


if __name__ == '__main__':
    main()
```
obfusecatd code：
```python
oo00oo00o0oo00oo00o00oo0o = __import__(chr(103) + chr(99), globals(),
    locals(), [], 0)
ooo00000ooo0000oo0o00000o = __import__(chr(98) + (chr(97) + chr(115) + chr(
    101) + chr(54) + chr(52)), globals(), locals(), [], 0)
o0o000oo000o0o000oo000oo0 = __import__(chr(114) + (chr(97) + chr(110) + chr
    (100) + chr(111) + chr(109)), globals(), locals(), [], 0)
o0ooooo0o0ooo0o00o0o00000 = getattr(__builtins__, chr(103) + (chr(101) +
    chr(116) + chr(97) + chr(116) + chr(116) + chr(114)))
o0o000o0oo00o000oo0oo0o00 = o0ooooo0o0ooo0o00o0o00000(__builtins__, chr(115
    ) + (chr(116) + chr(114)))
oooo0o00o0oo00o0o000000oo = o0ooooo0o0ooo0o00o0o00000(__builtins__, chr(98) +
    (chr(121) + chr(116) + chr(101) + chr(115)))
oooo0o0ooooo00o0ooo0o0ooo = o0ooooo0o0ooo0o00o0o00000(ooo00000ooo0000oo0o00000o
    , chr(98) + (chr(54) + chr(52) + chr(100) + chr(101) + chr(99) + chr(
    111) + chr(100) + chr(101)))
o000ooo00000oo00oooooo0oo = o0ooooo0o0ooo0o00o0o00000(__builtins__, chr(114
    ) + (chr(97) + chr(110) + chr(103) + chr(101)))
o00000o00o0oo0000oo00oo0o = o0ooooo0o0ooo0o00o0o00000(o0o000oo000o0o000oo000oo0
    , chr(114) + (chr(97) + chr(110) + chr(100) + chr(105) + chr(110) + chr
    (116)))
oo0ooooo0o00000o00o00o0o0 = o0ooooo0o0ooo0o00o0o00000(__builtins__, chr(105
    ) + (chr(110) + chr(116)))
o00o000ooo00oo00o0o000o00 = o0ooooo0o0ooo0o00o0o00000(__builtins__, chr(115
    ) + (chr(117) + chr(109)))
oo0o00oooo0o0o00oooo00o00 = o0ooooo0o0ooo0o00o0o00000(__builtins__, chr(108
    ) + (chr(101) + chr(110)))
o0oo000000o0o0o00oo0oooo0 = o0ooooo0o0ooo0o00o0o00000(__builtins__, chr(105
    ) + (chr(110) + chr(112) + chr(117) + chr(116)))
o00oo0ooo0o000oo00ooooooo = o0ooooo0o0ooo0o00o0o00000(ooo00000ooo0000oo0o00000o
    , chr(98) + (chr(54) + chr(52) + chr(101) + chr(110) + chr(99) + chr(
    111) + chr(100) + chr(101)))
o0oooo00ooo00000o00ooo00o = o0ooooo0o0ooo0o00o0o00000(__builtins__, chr(111
    ) + (chr(114) + chr(100)))
o0o000ooo00000000oo0000o0 = o0ooooo0o0ooo0o00o0o00000(__builtins__, chr(112
    ) + (chr(114) + chr(105) + chr(110) + chr(116)))
o000oo0oo000000000o0o0o00 = o0ooooo0o0ooo0o00o0o00000(oo00oo00o0oo00oo00o00oo0o
    , chr(103) + (chr(101) + chr(116) + chr(95) + chr(114) + chr(101) + chr
    (102) + chr(101) + chr(114) + chr(101) + chr(110) + chr(116) + chr(115)))
o000oo0oo000000000o0o0o00(o0o000o0oo00o000oo0oo0o00.__dict__)[0][chr(111) +
    (chr(48) + chr(48) + chr(111) + chr(111) + chr(111) + chr(111) + chr(48
    ) + chr(48) + chr(48) + chr(111) + chr(111) + chr(48) + chr(111) + chr(
    111) + chr(48) + chr(48) + chr(111) + chr(111) + chr(111) + chr(111) +
    chr(48) + chr(48) + chr(48) + chr(111))] = o000oo0oo000000000o0o0o00(
    o0o000o0oo00o000oo0oo0o00.__dict__)[0][chr(101) + (chr(110) + chr(99) +
    chr(111) + chr(100) + chr(101))]
o000oo0oo000000000o0o0o00(oooo0o00o0oo00o0o000000oo.__dict__)[0][chr(111) +
    (chr(48) + chr(48) + chr(48) + chr(111) + chr(48) + chr(48) + chr(111) +
    chr(48) + chr(111) + chr(111) + chr(48) + chr(111) + chr(111) + chr(111
    ) + chr(48) + chr(111) + chr(111) + chr(48) + chr(48) + chr(48) + chr(
    48) + chr(111) + chr(48) + chr(48))] = o000oo0oo000000000o0o0o00(
    oooo0o00o0oo00o0o000000oo.__dict__)[0][chr(109) + (chr(97) + chr(107) +
    chr(101) + chr(116) + chr(114) + chr(97) + chr(110) + chr(115))]
o000oo0oo000000000o0o0o00(o0o000o0oo00o000oo0oo0o00.__dict__)[0][chr(111) +
    (chr(48) + chr(48) + chr(48) + chr(111) + chr(48) + chr(48) + chr(111) +
    chr(48) + chr(111) + chr(111) + chr(48) + chr(111) + chr(111) + chr(111
    ) + chr(48) + chr(111) + chr(111) + chr(48) + chr(48) + chr(48) + chr(
    48) + chr(111) + chr(48) + chr(48))] = o000oo0oo000000000o0o0o00(
    o0o000o0oo00o000oo0oo0o00.__dict__)[0][chr(109) + (chr(97) + chr(107) +
    chr(101) + chr(116) + chr(114) + chr(97) + chr(110) + chr(115))]
o000oo0oo000000000o0o0o00(oooo0o00o0oo00o0o000000oo.__dict__)[0][chr(111) +
    (chr(48) + chr(48) + chr(48) + chr(111) + chr(111) + chr(111) + chr(48) +
    chr(48) + chr(48) + chr(48) + chr(48) + chr(48) + chr(48) + chr(111) +
    chr(111) + chr(111) + chr(111) + chr(48) + chr(48) + chr(111) + chr(111
    ) + chr(111) + chr(111) + chr(48))] = o000oo0oo000000000o0o0o00(
    oooo0o00o0oo00o0o000000oo.__dict__)[0][chr(100) + (chr(101) + chr(99) +
    chr(111) + chr(100) + chr(101))]
o000oo0oo000000000o0o0o00(oooo0o00o0oo00o0o000000oo.__dict__)[0][chr(111) +
    (chr(48) + chr(111) + chr(48) + chr(111) + chr(111) + chr(48) + chr(48) +
    chr(111) + chr(111) + chr(111) + chr(48) + chr(48) + chr(48) + chr(48) +
    chr(111) + chr(48) + chr(48) + chr(111) + chr(48) + chr(48) + chr(48) +
    chr(48) + chr(48) + chr(48))] = o000oo0oo000000000o0o0o00(
    oooo0o00o0oo00o0o000000oo.__dict__)[0][chr(116) + (chr(114) + chr(97) +
    chr(110) + chr(115) + chr(108) + chr(97) + chr(116) + chr(101))]
o000oo0oo000000000o0o0o00(o0o000o0oo00o000oo0oo0o00.__dict__)[0][chr(111) +
    (chr(48) + chr(111) + chr(48) + chr(111) + chr(111) + chr(48) + chr(48) +
    chr(111) + chr(111) + chr(111) + chr(48) + chr(48) + chr(48) + chr(48) +
    chr(111) + chr(48) + chr(48) + chr(111) + chr(48) + chr(48) + chr(48) +
    chr(48) + chr(48) + chr(48))] = o000oo0oo000000000o0o0o00(
    o0o000o0oo00o000oo0oo0o00.__dict__)[0][chr(116) + (chr(114) + chr(97) +
    chr(110) + chr(115) + chr(108) + chr(97) + chr(116) + chr(101))]
o000oo0oo000000000o0o0o00(oo0ooooo0o00000o00o00o0o0.__dict__)[0][chr(111) +
    (chr(48) + chr(48) + chr(48) + chr(48) + chr(48) + chr(111) + chr(111) +
    chr(111) + chr(111) + chr(48) + chr(111) + chr(111) + chr(48) + chr(111
    ) + chr(48) + chr(48) + chr(111) + chr(48) + chr(111) + chr(48) + chr(
    48) + chr(48) + chr(111) + chr(111))] = o000oo0oo000000000o0o0o00(
    oo0ooooo0o00000o00o00o0o0.__dict__)[0][chr(102) + (chr(114) + chr(111) +
    chr(109) + chr(95) + chr(98) + chr(121) + chr(116) + chr(101) + chr(115))]
o000oo0oo000000000o0o0o00(oo0ooooo0o00000o00o00o0o0.__dict__)[0][chr(111) +
    (chr(111) + chr(111) + chr(111) + chr(111) + chr(111) + chr(48) + chr(
    48) + chr(48) + chr(111) + chr(111) + chr(111) + chr(111) + chr(48) +
    chr(48) + chr(48) + chr(48) + chr(111) + chr(48) + chr(111) + chr(111) +
    chr(48) + chr(48) + chr(48) + chr(111))] = o000oo0oo000000000o0o0o00(
    oo0ooooo0o00000o00o00o0o0.__dict__)[0][chr(116) + (chr(111) + chr(95) +
    chr(98) + chr(121) + chr(116) + chr(101) + chr(115))]
o000oo0oo000000000o0o0o00(oo0ooooo0o00000o00o00o0o0.__dict__)[0][chr(111) +
    (chr(111) + chr(48) + chr(48) + chr(48) + chr(111) + chr(111) + chr(111
    ) + chr(48) + chr(48) + chr(48) + chr(48) + chr(48) + chr(48) + chr(48) +
    chr(48) + chr(48) + chr(111) + chr(48) + chr(111) + chr(48) + chr(48) +
    chr(111) + chr(48) + chr(111))] = o000oo0oo000000000o0o0o00(
    oo0ooooo0o00000o00o00o0o0.__dict__)[0][chr(98) + (chr(105) + chr(116) +
    chr(95) + chr(108) + chr(101) + chr(110) + chr(103) + chr(116) + chr(104))]
o000oo0oo000000000o0o0o00(oooo0o00o0oo00o0o000000oo.__dict__)[0][chr(111) +
    (chr(48) + chr(111) + chr(111) + chr(111) + chr(48) + chr(111) + chr(48
    ) + chr(111) + chr(111) + chr(48) + chr(48) + chr(48) + chr(48) + chr(
    111) + chr(48) + chr(48) + chr(111) + chr(48) + chr(48) + chr(111) +
    chr(48) + chr(48) + chr(48) + chr(48))] = o000oo0oo000000000o0o0o00(
    oooo0o00o0oo00o0o000000oo.__dict__)[0][chr(105) + (chr(115) + chr(108) +
    chr(111) + chr(119) + chr(101) + chr(114))]
o000oo0oo000000000o0o0o00(o0o000o0oo00o000oo0oo0o00.__dict__)[0][chr(111) +
    (chr(48) + chr(111) + chr(111) + chr(111) + chr(48) + chr(111) + chr(48
    ) + chr(111) + chr(111) + chr(48) + chr(48) + chr(48) + chr(48) + chr(
    111) + chr(48) + chr(48) + chr(111) + chr(48) + chr(48) + chr(111) +
    chr(48) + chr(48) + chr(48) + chr(48))] = o000oo0oo000000000o0o0o00(
    o0o000o0oo00o000oo0oo0o00.__dict__)[0][chr(105) + (chr(115) + chr(108) +
    chr(111) + chr(119) + chr(101) + chr(114))]
o000oo0oo000000000o0o0o00(oooo0o00o0oo00o0o000000oo.__dict__)[0][chr(111) +
    (chr(111) + chr(48) + chr(111) + chr(48) + chr(111) + chr(111) + chr(
    111) + chr(111) + chr(111) + chr(111) + chr(111) + chr(48) + chr(111) +
    chr(111) + chr(111) + chr(111) + chr(48) + chr(48) + chr(48) + chr(111) +
    chr(111) + chr(48) + chr(111) + chr(111))] = o000oo0oo000000000o0o0o00(
    oooo0o00o0oo00o0o000000oo.__dict__)[0][chr(105) + (chr(115) + chr(117) +
    chr(112) + chr(112) + chr(101) + chr(114))]
o000oo0oo000000000o0o0o00(o0o000o0oo00o000oo0oo0o00.__dict__)[0][chr(111) +
    (chr(111) + chr(48) + chr(111) + chr(48) + chr(111) + chr(111) + chr(
    111) + chr(111) + chr(111) + chr(111) + chr(111) + chr(48) + chr(111) +
    chr(111) + chr(111) + chr(111) + chr(48) + chr(48) + chr(48) + chr(111) +
    chr(111) + chr(48) + chr(111) + chr(111))] = o000oo0oo000000000o0o0o00(
    o0o000o0oo00o000oo0oo0o00.__dict__)[0][chr(105) + (chr(115) + chr(117) +
    chr(112) + chr(112) + chr(101) + chr(114))]
o000oo0oo000000000o0o0o00(oooo0o00o0oo00o0o000000oo.__dict__)[0][chr(111) +
    (chr(111) + chr(48) + chr(111) + chr(111) + chr(111) + chr(111) + chr(
    48) + chr(48) + chr(111) + chr(48) + chr(111) + chr(111) + chr(48) +
    chr(111) + chr(48) + chr(48) + chr(111) + chr(48) + chr(48) + chr(48) +
    chr(48) + chr(48) + chr(111) + chr(48))] = o000oo0oo000000000o0o0o00(
    oooo0o00o0oo00o0o000000oo.__dict__)[0][chr(105) + (chr(115) + chr(100) +
    chr(105) + chr(103) + chr(105) + chr(116))]
o000oo0oo000000000o0o0o00(o0o000o0oo00o000oo0oo0o00.__dict__)[0][chr(111) +
    (chr(111) + chr(48) + chr(111) + chr(111) + chr(111) + chr(111) + chr(
    48) + chr(48) + chr(111) + chr(48) + chr(111) + chr(111) + chr(48) +
    chr(111) + chr(48) + chr(48) + chr(111) + chr(48) + chr(48) + chr(48) +
    chr(48) + chr(48) + chr(111) + chr(48))] = o000oo0oo000000000o0o0o00(
    o0o000o0oo00o000oo0oo0o00.__dict__)[0][chr(105) + (chr(115) + chr(100) +
    chr(105) + chr(103) + chr(105) + chr(116))]


def oo00ooo0o00ooooooooo00000(oo00o0o0o00o00oo00o00ooo0):
    ooo00oo0oo0ooooooo000oo0o = (
        '-_+!1@2#3$4%5^6&7*8(9)0qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFG'.
        o00oooo000oo0oo00oooo000o())
    o0oo000oo0o00oo0ooo0ooo0o = (
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.
        o00oooo000oo0oo00oooo000o())
    o00oooo0o0o0ooo0o0ooo00oo = (oooo0o00o0oo00o0o000000oo.
        o000o00o0oo0ooo0oo0000o00(ooo00oo0oo0ooooooo000oo0o,
        o0oo000oo0o00oo0ooo0ooo0o))
    return oooo0o0ooooo00o0ooo0o0ooo(oo00o0o0o00o00oo00o00ooo0.
        o0o0oo00ooo0000o00o000000(o00oooo0o0o0ooo0o0ooo00oo)
        ).o000ooo0000000oooo00oooo0()



oooo00o00oo00ooo0oooo0o0o = []
for o00000o00o000o0o00o00oooo in o000ooo00000oo00oooooo0oo(4):
    oooo00o00oo00ooo0oooo0o0o.append([])
    for ooo0000o0o000oo0000ooo00o in o000ooo00000oo00oooooo0oo(4):
        oooo00o00oo00ooo0oooo0o0o[o00000o00o000o0o00o00oooo].append(
            o00000o00o0oo0000oo00oo0o(0, 256))
oo0o0000000oooooo0o00o0oo = []
for o00000o00o000o0o00o00oooo in o000ooo00000oo00oooooo0oo(4):
    oo0o0000000oooooo0o00o0oo.append([])
    for ooo0000o0o000oo0000ooo00o in o000ooo00000oo00oooooo0oo(4):
        oo0o0000000oooooo0o00o0oo[o00000o00o000o0o00o00oooo].append(
            o00000o00o0oo0000oo00oo0o(0, 256))
o0ooo0o00o0o00ooo00o0o0oo = []
for ooo0000o0o000oo0000ooo00o in o000ooo00000oo00oooooo0oo(16):
    o0ooo0o00o0o00ooo00o0o0oo.append(o00000o00o0oo0000oo00oo0o(0, 256) << 24)
ooo00000o00oo0oo000oo0oo0 = []
for o00000o00o000o0o00o00oooo in o000ooo00000oo00oooooo0oo(16):
    ooo00000o00oo0oo000oo0oo0.append([])
    for ooo0000o0o000oo0000ooo00o in o000ooo00000oo00oooooo0oo(16):
        ooo00000o00oo0oo000oo0oo0[o00000o00o000o0o00o00oooo].append(
            o00000o00o0oo0000oo00oo0o(0, 255))
o0oo00o000o00ooo0ooo000oo = []
for o00000o00o000o0o00o00oooo in o000ooo00000oo00oooooo0oo(16):
    o0oo00o000o00ooo0ooo000oo.append([])
    for ooo0000o0o000oo0000ooo00o in o000ooo00000oo00oooooo0oo(16):
        o0oo00o000o00ooo0ooo000oo[o00000o00o000o0o00o00oooo].append(
            o00000o00o0oo0000oo00oo0o(0, 255))


def ooo0oo0o0oo000o0o00oooo00():
    o0o000000o00o0oo0o0o0oo0o = []
    for ooo0000o0o000oo0000ooo00o in o000ooo00000oo00oooooo0oo(16):
        o0o000000o00o0oo0o0o0oo0o.append(o00000o00o0oo0000oo00oo0o(0, 255))
    return oooo0o00o0oo00o0o000000oo(o0o000000o00o0oo0o0o0oo0o)


def ooooo0ooo0oo0oo000ooo000o():
    oooo0o000ooooooooooo00ooo = []
    for ooo0000o0o000oo0000ooo00o in o000ooo00000oo00oooooo0oo(16):
        oooo0o000ooooooooooo00ooo.append(o00000o00o0oo0000oo00oo0o(0, 255))
    return oooo0o00o0oo00o0o000000oo(oooo0o000ooooooooooo00ooo)


def oo0o0o0o000o0oo00o0oo0ooo(ooo00oooo000ooo0o0o0o000o):
    o0oo00oo00o0o0o00oo00oo00 = []
    for ooo0000o0o000oo0000ooo00o in ooo00oooo000ooo0o0o0o000o:
        o0oo00oo00o0o0o00oo00oo00.append(ooo00000o00oo0oo000oo0oo0[
            ooo0000o0o000oo0000ooo00o >> 4][ooo0000o0o000oo0000ooo00o & 15])
    return o0oo00oo00o0o0o00oo00oo00


def o000o00ooo0oo0oo0oo000oo0(oo00oo00oo000oooo0oo00o0o):
    o00000ooo0oo00o0o0o00o0o0 = []
    for ooo0000o0o000oo0000ooo00o in oo00oo00oo000oooo0oo00o0o:
        o00000ooo0oo00o0o0o00o0o0.append(o0oo00o000o00ooo0ooo000oo[
            ooo0000o0o000oo0000ooo00o >> 4][ooo0000o0o000oo0000ooo00o & 15])
    return o00000ooo0oo00o0o0o00o0o0


def oooooooooo00oo0o0oo0oooo0(oo0ooo000o000ooo0ooo0o000):
    return [oo0ooo000o000ooo0ooo0o000[0], oo0ooo000o000ooo0ooo0o000[5],
        oo0ooo000o000ooo0ooo0o000[10], oo0ooo000o000ooo0ooo0o000[15],
        oo0ooo000o000ooo0ooo0o000[4], oo0ooo000o000ooo0ooo0o000[9],
        oo0ooo000o000ooo0ooo0o000[14], oo0ooo000o000ooo0ooo0o000[3],
        oo0ooo000o000ooo0ooo0o000[8], oo0ooo000o000ooo0ooo0o000[13],
        oo0ooo000o000ooo0ooo0o000[2], oo0ooo000o000ooo0ooo0o000[7],
        oo0ooo000o000ooo0ooo0o000[12], oo0ooo000o000ooo0ooo0o000[1],
        oo0ooo000o000ooo0ooo0o000[6], oo0ooo000o000ooo0ooo0o000[11]]


def o0ooo0000oo0o0oooo0oo00o0(ooo000o0000o0000o00oo000o):
    return [ooo000o0000o0000o00oo000o[0], ooo000o0000o0000o00oo000o[13],
        ooo000o0000o0000o00oo000o[10], ooo000o0000o0000o00oo000o[7],
        ooo000o0000o0000o00oo000o[4], ooo000o0000o0000o00oo000o[1],
        ooo000o0000o0000o00oo000o[14], ooo000o0000o0000o00oo000o[11],
        ooo000o0000o0000o00oo000o[8], ooo000o0000o0000o00oo000o[5],
        ooo000o0000o0000o00oo000o[2], ooo000o0000o0000o00oo000o[15],
        ooo000o0000o0000o00oo000o[12], ooo000o0000o0000o00oo000o[9],
        ooo000o0000o0000o00oo000o[6], ooo000o0000o0000o00oo000o[3]]


def oooooo0o00oo00o00o0oooooo(oo00o0oooo0o0ooo0oo00o000,
    oo000ooo00o0o0o0000oo0o00):
    ooo00o0oooo00o0o00000oo0o = []
    for o00000o00o000o0o00o00oooo in o000ooo00000oo00oooooo0oo(16):
        ooo00o0oooo00o0o00000oo0o.append(oo00o0oooo0o0ooo0oo00o000[
            o00000o00o000o0o00o00oooo] ^ oo000ooo00o0o0o0000oo0o00[
            o00000o00o000o0o00o00oooo])
    return ooo00o0oooo00o0o00000oo0o


def oo000o00000oo0oo00o00o0oo(ooo0o0ooo0oo0o0oooooo0000):
    return oo0ooooo0o00000o00o00o0o0.o00000oooo0oo0o00o0o000oo(
        ooo0o0ooo0oo0o0oooooo0000, byteorder=oo00ooo0o00ooooooooo00000('whgj'))


def o0oo0o00o0oo0oo0ooo0oo0o0(o0o0oo0o00oooo0o0ooo00o00):
    return o0o0oo0o00oooo0o0ooo00o00.oooooo000oooo0000o0oo000o(16,
        byteorder=oo00ooo0o00ooooooooo00000('whgj'))


def oo0ooooo0o00oo0o0oooo000o(ooo0oo0oo000o0ooo0o00oo00):
    while ooo0oo0oo000o0ooo0o00oo00.oo000ooo000000000o0o00o0o() > 8:
        ooo0oo0oo000o0ooo0o00oo00 ^= (283 << ooo0oo0oo000o0ooo0o00oo00.
            oo000ooo000000000o0o00o0o() - 9)
    return ooo0oo0oo000o0ooo0o00oo00


def ooooo00o000oo0oo0o00o0ooo(o0oooo00000oo00o00o0oo0oo,
    oo0o00o0oo0000o0o0oo00000):
    oo0o00000000o00ooooo00000 = 0
    for ooooo0o0o0o000ooo000000o0 in o000ooo00000oo00oooooo0oo(
        oo0o00o0oo0000o0o0oo00000.oo000ooo000000000o0o00o0o()):
        if oo0o00o0oo0000o0o0oo00000 & 1 << ooooo0o0o0o000ooo000000o0:
            oo0o00000000o00ooooo00000 ^= (o0oooo00000oo00o00o0oo0oo <<
                ooooo0o0o0o000ooo000000o0)
    return oo0o00000000o00ooooo00000


def ooooo00ooo0oo0oo0000000oo(ooo00o00o0oo000o0oo00ooo0,
    ooooo0ooo00o00o0ooo000ooo):
    ooo0o00oooo00o0o00o0000oo = [0] * 16
    for ooo0o00o0oo00o00oo00oo0o0 in o000ooo00000oo00oooooo0oo(4):
        for ooo00oo000o00ooooooo0oooo in o000ooo00000oo00oooooo0oo(4):
            for o00o0oo00o00o00oo0o0o0oo0 in o000ooo00000oo00oooooo0oo(4):
                ooo0o00oooo00o0o00o0000oo[ooo0o00o0oo00o00oo00oo0o0 + 
                    ooo00oo000o00ooooooo0oooo * 4
                    ] ^= ooooo00o000oo0oo0o00o0ooo(ooo00o00o0oo000o0oo00ooo0
                    [ooo0o00o0oo00o00oo00oo0o0][o00o0oo00o00o00oo0o0o0oo0],
                    ooooo0ooo00o00o0ooo000ooo[o00o0oo00o00o00oo0o0o0oo0 + 
                    ooo00oo000o00ooooooo0oooo * 4])
            ooo0o00oooo00o0o00o0000oo[ooo0o00o0oo00o00oo00oo0o0 + 
                ooo00oo000o00ooooooo0oooo * 4] = oo0ooooo0o00oo0o0oooo000o(
                ooo0o00oooo00o0o00o0000oo[ooo0o00o0oo00o00oo00oo0o0 + 
                ooo00oo000o00ooooooo0oooo * 4])
    return ooo0o00oooo00o0o00o0000oo


def ooo0oo0oo0oooo0oooo0000oo(o00ooo0o0000oo0ooo0ooooo0):
    return ooooo00ooo0oo0oo0000000oo(oooo00o00oo00ooo0oooo0o0o,
        o00ooo0o0000oo0ooo0ooooo0)


def o00oo000o0000o0ooooooo0oo(oo000000o00oo00o0o0oooo00):
    return ooooo00ooo0oo0oo0000000oo(oo0o0000000oooooo0o00o0oo,
        oo000000o00oo00o0o0oooo00)


def o00oo0o0oo0000oo00o00oooo(o0000o0o0o00ooo0o00o00o00):
    return ((o0000o0o0o00ooo0o00o00o00 & 16777215) << 8) + (
        o0000o0o0o00ooo0o00o00o00 >> 24)


def ooo0ooo0o0o0oooo0oooo0oo0(oooooo0000oooo000o0ooo000):
    oo000oo0000ooo0o00ooo0oo0 = 0
    for oo0oooo0000o0000ooooooo0o in o000ooo00000oo00oooooo0oo(4):
        o00000o00o000o0o00o00oooo = (oooooo0000oooo000o0ooo000 >> 
            oo0oooo0000o0000ooooooo0o * 8 + 4 & 15)
        ooo0ooooo00o00000ooo0o0oo = (oooooo0000oooo000o0ooo000 >> 
            oo0oooo0000o0000ooooooo0o * 8 & 15)
        oo000oo0000ooo0o00ooo0oo0 ^= ooo00000o00oo0oo000oo0oo0[
            o00000o00o000o0o00o00oooo][ooo0ooooo00o00000ooo0o0oo
            ] << oo0oooo0000o0000ooooooo0o * 8
    return oo000oo0000ooo0o00ooo0oo0


def ooo0o0oo0000o00o000oooo0o(o00o00o00o0000000oo00o000):
    o00o00o00o0000000oo00o000 = oo000o00000oo0oo00o00o0oo(
        o00o00o00o0000000oo00o000)
    o000o0ooo000oo00o0o0o0ooo = [o00o00o00o0000000oo00o000 >> 96, 
        o00o00o00o0000000oo00o000 >> 64 & 4294967295, 
        o00o00o00o0000000oo00o000 >> 32 & 4294967295, 
        o00o00o00o0000000oo00o000 & 4294967295] + [0] * 40
    for o00000o00o000o0o00o00oooo in o000ooo00000oo00oooooo0oo(4, 44):
        o0o00o00oo0o0ooo0o0o00oo0 = o000o0ooo000oo00o0o0o0ooo[
            o00000o00o000o0o00o00oooo - 1]
        if not o00000o00o000o0o00o00oooo % 4:
            o0o00o00oo0o0ooo0o0o00oo0 = ooo0ooo0o0o0oooo0oooo0oo0(
                o00oo0o0oo0000oo00o00oooo(o0o00o00oo0o0ooo0o0o00oo0)
                ) ^ o0ooo0o00o0o00ooo00o0o0oo[o00000o00o000o0o00o00oooo // 
                4 - 1]
        o000o0ooo000oo00o0o0o0ooo[o00000o00o000o0o00o00oooo
            ] = o000o0ooo000oo00o0o0o0ooo[o00000o00o000o0o00o00oooo - 4
            ] ^ o0o00o00oo0o0ooo0o0o00oo0
    o0oo00oo00oo000o0000o0oo0 = []
    for o00000o00o000o0o00o00oooo in o000ooo00000oo00oooooo0oo(11):
        o0oo00oo00oo000o0000o0oo0.append(o0oo0o00o0oo0oo0ooo0oo0o0(
            o00o000ooo00oo00o0o000o00([o000o0ooo000oo00o0o0o0ooo[4 *
            o00000o00o000o0o00o00oooo] << 96, o000o0ooo000oo00o0o0o0ooo[4 *
            o00000o00o000o0o00o00oooo + 1] << 64, o000o0ooo000oo00o0o0o0ooo
            [4 * o00000o00o000o0o00o00oooo + 2] << 32,
            o000o0ooo000oo00o0o0o0ooo[4 * o00000o00o000o0o00o00oooo + 3]])))
    return o0oo00oo00oo000o0000o0oo0


def o0ooooo0oo0o0ooo000oo0000(o00o000ooo0o0oo00o0o0oo0o,
    o0ooo00oo00o000ooo0o0ooo0, o00oo0o0o00o0oo0000ooooo0):
    return oooooo0o00oo00o00o0oooooo(o00o000ooo0o0oo00o0o0oo0o,
        o0ooo00oo00o000ooo0o0ooo0[o00oo0o0o00o0oo0000ooooo0])


def o0000o0o000000oo000oo000o(o00o0ooo00o00oo00oooo00o0,
    oo0000o0o0o00000o000oo0o0):
    ooooo0o0oo0ooooo0o0ooo00o = o00o0ooo00o00oo00oooo00o0
    ooooo0o0oo0ooooo0o0ooo00o = o0ooooo0oo0o0ooo000oo0000(
        ooooo0o0oo0ooooo0o0ooo00o, oo0000o0o0o00000o000oo0o0, 0)
    for o0oo0o00oo0oo000oo0o0000o in o000ooo00000oo00oooooo0oo(1, 10):
        ooooo0o0oo0ooooo0o0ooo00o = oo0o0o0o000o0oo00o0oo0ooo(
            ooooo0o0oo0ooooo0o0ooo00o)
        ooooo0o0oo0ooooo0o0ooo00o = oooooooooo00oo0o0oo0oooo0(
            ooooo0o0oo0ooooo0o0ooo00o)
        ooooo0o0oo0ooooo0o0ooo00o = ooo0oo0oo0oooo0oooo0000oo(
            ooooo0o0oo0ooooo0o0ooo00o)
        ooooo0o0oo0ooooo0o0ooo00o = o0ooooo0oo0o0ooo000oo0000(
            ooooo0o0oo0ooooo0o0ooo00o, oo0000o0o0o00000o000oo0o0,
            o0oo0o00oo0oo000oo0o0000o)
    ooooo0o0oo0ooooo0o0ooo00o = oo0o0o0o000o0oo00o0oo0ooo(
        ooooo0o0oo0ooooo0o0ooo00o)
    ooooo0o0oo0ooooo0o0ooo00o = oooooooooo00oo0o0oo0oooo0(
        ooooo0o0oo0ooooo0o0ooo00o)
    ooooo0o0oo0ooooo0o0ooo00o = o0ooooo0oo0o0ooo000oo0000(
        ooooo0o0oo0ooooo0o0ooo00o, oo0000o0o0o00000o000oo0o0, 10)
    return ooooo0o0oo0ooooo0o0ooo00o


def oo00o000o00o0oo0o0o0o0o00(ooo0o00000000o000oo0oooo0,
    o00o00000oo0oo0oooo0o00o0):
    o0ooo000o0000oooooooo0oo0 = ooo0o00000000o000oo0oooo0
    o0ooo000o0000oooooooo0oo0 = o0ooooo0oo0o0ooo000oo0000(
        o0ooo000o0000oooooooo0oo0, o00o00000oo0oo0oooo0o00o0, 10)
    for o0000oo0ooo0000o00o00o000 in o000ooo00000oo00oooooo0oo(1, 10):
        o0ooo000o0000oooooooo0oo0 = o0ooo0000oo0o0oooo0oo00o0(
            o0ooo000o0000oooooooo0oo0)
        o0ooo000o0000oooooooo0oo0 = o000o00ooo0oo0oo0oo000oo0(
            o0ooo000o0000oooooooo0oo0)
        o0ooo000o0000oooooooo0oo0 = o0ooooo0oo0o0ooo000oo0000(
            o0ooo000o0000oooooooo0oo0, o00o00000oo0oo0oooo0o00o0, 10 -
            o0000oo0ooo0000o00o00o000)
        o0ooo000o0000oooooooo0oo0 = o00oo000o0000o0ooooooo0oo(
            o0ooo000o0000oooooooo0oo0)
    o0ooo000o0000oooooooo0oo0 = o0ooo0000oo0o0oooo0oo00o0(
        o0ooo000o0000oooooooo0oo0)
    o0ooo000o0000oooooooo0oo0 = o000o00ooo0oo0oo0oo000oo0(
        o0ooo000o0000oooooooo0oo0)
    o0ooo000o0000oooooooo0oo0 = o0ooooo0oo0o0ooo000oo0000(
        o0ooo000o0000oooooooo0oo0, o00o00000oo0oo0oooo0o00o0, 0)
    return o0ooo000o0000oooooooo0oo0


def ooo000000oo0o0oooo00ooo0o(o0ooo00o00ooo000o0oo0o0oo,
    o00oo0oo00oo00000ooo0o000, o00oo0oo00o00oo000ooo000o,
    ooo000000o0oo0oo00ooo0oo0=True):
    ooooo0oo0o0ooo0o0oooooo0o = []
    oooo0000o0oo0o00o0000o00o = []
    o00oo0oo0ooooooooooo0o0oo = oo0o00oooo0o0o00oooo00o00(
        o0ooo00o00ooo000o0oo0o0oo)
    for o00000o00o000o0o00o00oooo in o000ooo00000oo00oooooo0oo(
        o00oo0oo0ooooooooooo0o0oo // 16):
        oooo0000o0oo0o00o0000o00o.append(o0ooo00o00ooo000o0oo0o0oo[
            o00000o00o000o0o00o00oooo * 16:(o00000o00o000o0o00o00oooo + 1) *
            16])
    if o00oo0oo0ooooooooooo0o0oo % 16 != 0:
        oooooo0oo0o0oo00ooo00o0oo = 16 - o00oo0oo0ooooooooooo0o0oo % 16
        oo00oo000oooo00o00oo0oooo = o0ooo00o00ooo000o0oo0o0oo[
            o00oo0oo0ooooooooooo0o0oo // 16 * 16:] + oooo0o00o0oo00o0o000000oo(
            [oooooo0oo0o0oo00ooo00o0oo] * oooooo0oo0o0oo00ooo00o0oo)
        oooo0000o0oo0o00o0000o00o.append(oo00oo000oooo00o00oo0oooo)
    oo0ooo0ooo0oo0oo000000o0o = ooo0o0oo0000o00o000oooo0o(
        o00oo0oo00oo00000ooo0o000)
    if ooo000000o0oo0oo00ooo0oo0:
        for oo000o0oo0ooo00000oo0o00o in oooo0000o0oo0o00o0000o00o:
            oo00oo000oooo00o00oo0oooo = oooooo0o00oo00o00o0oooooo(
                oo000o0oo0ooo00000oo0o00o, o00oo0oo00o00oo000ooo000o)
            o00oo0oo00o00oo000ooo000o = o0000o0o000000oo000oo000o(
                oo00oo000oooo00o00oo0oooo, oo0ooo0ooo0oo0oo000000o0o)
            ooooo0oo0o0ooo0o0oooooo0o += o00oo0oo00o00oo000ooo000o
        return oooo0o00o0oo00o0o000000oo(ooooo0oo0o0ooo0o0oooooo0o)
    else:
        for oo000o0oo0ooo00000oo0o00o in oooo0000o0oo0o00o0000o00o:
            oo00oo000oooo00o00oo0oooo = oo00o000o00o0oo0o0o0o0o00(
                oo000o0oo0ooo00000oo0o00o, oo0ooo0ooo0oo0oo000000o0o)
            oo00oo000oooo00o00oo0oooo = oooooo0o00oo00o00o0oooooo(
                oo00oo000oooo00o00oo0oooo, o00oo0oo00o00oo000ooo000o)
            o00oo0oo00o00oo000ooo000o = oo000o0oo0ooo00000oo0o00o
            ooooo0oo0o0ooo0o0oooooo0o += oo00oo000oooo00o00oo0oooo
        return oooo0o00o0oo00o0o000000oo(ooooo0oo0o0ooo0o0oooooo0o)


def oooo0oo0o0ooooo00o00oo000():
    o000o000o000o0o000ooo0000 = o0oo000000o0o0o00oo0oooo0(
        oo00ooo0o00ooooooooo00000('&s_7t2)ayY9pr0Omuq7pi0DTys_ht2@j6pkF3-=='))
    ooo0o0oooo00ooo000oo0oo0o = [...]
    ooo00oo0oo00o0000000oo0oo = ooo0oo0o0oo000o0o00oooo00()
    oo0o0o0o0ooo0o0ooooo0o00o = ooooo0ooo0oo0oo000ooo000o()
    oo0o0000o00o0oo00oo00o0oo = (o000o000o000o0o000ooo0000.
        o00oooo000oo0oo00oooo000o())
    oo0o0o0ooo00oo0oo0o00000o = ooo000000oo0o0oooo00ooo0o(
        oo0o0000o00o0oo00oo00o0oo, ooo00oo0oo00o0000000oo0oo,
        oo0o0o0o0ooo0o0ooooo0o00o)
    o0o0oo0oo0o0o0oo00oo0oo0o = o00oo0ooo0o000oo00ooooooo(
        oo0o0o0ooo00oo0oo0o00000o).o000ooo0000000oooo00oooo0()
    o000o00oo000o0o00000ooooo = []
    for o00000o00o000o0o00o00oooo in o000ooo00000oo00oooooo0oo(
        oo0o00oooo0o0o00oooo00o00(o0o0oo0oo0o0o0oo00oo0oo0o) - 1):
        o0o000o00ooo0oo00o0o00o00 = o0o0oo0oo0o0o0oo00oo0oo0o[
            o00000o00o000o0o00o00oooo]
        if o0o000o00ooo0oo00o0o00o00.o0ooo0o0oo0000o00o00o0000():
            o000o00oo000o0o00000ooooo.append(o0oooo00ooo00000o00ooo00o(
                o0o000o00ooo0oo00o0o00o00) * o0oooo00ooo00000o00ooo00o(
                o0o0oo0oo0o0o0oo00oo0oo0o[o00000o00o000o0o00o00oooo + 1]) & 255
                )
        elif o0o000o00ooo0oo00o0o00o00.oo0o0ooooooo0oooo000oo0oo():
            o000o00oo000o0o00000ooooo.append(o0oooo00ooo00000o00ooo00o(
                o0o000o00ooo0oo00o0o00o00) - o0oooo00ooo00000o00ooo00o(
                o0o0oo0oo0o0o0oo00oo0oo0o[o00000o00o000o0o00o00oooo + 1]) & 255
                )
        elif o0o000o00ooo0oo00o0o00o00.oo0oooo00o0oo0o00o00000o0():
            o000o00oo000o0o00000ooooo.append(o0oooo00ooo00000o00ooo00o(
                o0o000o00ooo0oo00o0o00o00) + o0oooo00ooo00000o00ooo00o(
                o0o0oo0oo0o0o0oo00oo0oo0o[o00000o00o000o0o00o00oooo + 1]) & 255
                )
        else:
            o000o00oo000o0o00000ooooo.append(o0oooo00ooo00000o00ooo00o(
                o0o000o00ooo0oo00o0o00o00) ^ o0oooo00ooo00000o00ooo00o(
                o0o0oo0oo0o0o0oo00oo0oo0o[o00000o00o000o0o00o00oooo + 1]))
    for o00000o00o000o0o00o00oooo in o000ooo00000oo00oooooo0oo(
        oo0o00oooo0o0o00oooo00o00(o000o00oo000o0o00000ooooo)):
        if o000o00oo000o0o00000ooooo[o00000o00o000o0o00o00oooo
            ] != ooo0o0oooo00ooo000oo0oo0o[o00000o00o000o0o00o00oooo]:
            o0o000ooo00000000oo0000o0(oo00ooo0o00ooooooooo00000('&s_gyj$nyp==')
                )
            break
    else:
        o0o000ooo00000000oo0000o0(oo00ooo0o00ooooooooo00000('&s_Wr0uku-=='))


if __name__ == oo00ooo0o00ooooooooo00000('qTDvw0gbqTS='):
    oooo0oo0o0ooooo00o00oo000()
```
