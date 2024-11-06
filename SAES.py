# S-Box 和其逆矩阵
S_BOX = [
    [0x9, 0x4, 0xA, 0xB],
    [0xD, 0x1, 0x8, 0x5],
    [0x6, 0x2, 0x0, 0x3],
    [0xC, 0xE, 0xF, 0x7]
]

S_BOX_INV = [
    [0xA, 0x5, 0x9, 0xB],
    [0x1, 0x7, 0x8, 0xF],
    [0x6, 0x0, 0x2, 0x3],
    [0xC, 0x4, 0xD, 0xE]
]


# 将整数转换为状态矩阵
def int_to_matrix(text: int) -> list:
    return [
        (text >> 12) & 0x0F,  # S(0, 0)
        (text >> 4) & 0x0F,   # S(0, 1)
        (text >> 8) & 0x0F,   # S(1, 0)
        text & 0x0F           # S(1, 1)
    ]


# 将状态矩阵转换回整数
def matrix_to_int(matrix: list) -> int:
    return (matrix[0] << 12) | (matrix[1] << 4) | (matrix[2] << 8) | matrix[3]


# 将列表转换为整数
def list_to_int(l: list) -> int:
    result = 0
    for i in l:
        result = (result << 4) | (i & 0xF)
    return result


# 将ASCII字符串转换为块（16位）
def ascii_string_to_blocks(s: str) -> list:
    blocks = []
    for i in range(0, len(s), 2):
        block = (ord(s[i]) << 8)
        if i + 1 < len(s):
            block |= ord(s[i + 1])
        else:
            block |= 0
        blocks.append(block)
    return blocks


# 将块转换为ASCII字符串
def blocks_to_ascii_string(blocks: list) -> str:
    result = ''
    for block in blocks:
        high_char = (block >> 8) & 0xFF
        low_char = block & 0xFF
        if high_char != 0:
            result += chr(high_char)
        if low_char != 0:
            result += chr(low_char)
    return result


# 将二进制字符串转换为块（每块16位）
def string_to_blocks(s: str) -> list:
    blocks = []
    for i in range(0, len(s), 16):
        block = int(s[i:i + 16], 2)
        blocks.append(block)
    return blocks


# 将块转换为二进制字符串
def blocks_to_string(blocks: list) -> str:
    result = ''
    for block in blocks:
        result += bin(block)[2:].zfill(16)
    return result


# 在GF(2^4)域上实现乘法
def gf_mult(a: int, b: int, poly=0b10011) -> int:
    result = 0
    while b > 0:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0b10000:
            a ^= poly
        b >>= 1
    return result & 0xF


# 密钥加函数：对状态矩阵进行密钥加
def key_addition(state: list, key: list) -> list:
    key_matrix = [
        (key[0] >> 4) & 0x0F, (key[1] >> 4) & 0x0F,
        key[0] & 0x0F, key[1] & 0x0F
    ]
    return [state[i] ^ key_matrix[i] for i in range(4)]


# 半字节代替函数（S-Box替换）
def substitute_nibble(state: list, inverse=False) -> list:
    result = []
    for nibble in state:
        high_nibble = (nibble >> 2) & 0x03
        low_nibble = nibble & 0x03
        new_nibble = S_BOX_INV[high_nibble][low_nibble] if inverse else S_BOX[high_nibble][low_nibble]
        result.append(new_nibble)
    return result


# 行移位函数
def shift_rows(state: list) -> list:
    return [state[0], state[1], state[3], state[2]]


# 矩阵乘法辅助函数，用于列混淆
def matrix_mult(nibble1: int, nibble2: int, m: list) -> int:
    return gf_mult(m[0], nibble1) ^ gf_mult(m[1], nibble2)


# 列混淆函数
def mix_columns(state: list, inverse=False) -> list:
    if inverse:
        new_state = [
            matrix_mult(state[0], state[2], [9, 2]), matrix_mult(state[1], state[3], [9, 2]),
            matrix_mult(state[0], state[2], [2, 9]), matrix_mult(state[1], state[3], [2, 9])
        ]
    else:
        new_state = [
            matrix_mult(state[0], state[2], [1, 4]), matrix_mult(state[1], state[3], [1, 4]),
            matrix_mult(state[0], state[2], [4, 1]), matrix_mult(state[1], state[3], [4, 1])
        ]
    return new_state


# 密钥扩展：从主密钥生成扩展密钥
def key_expansion(key: int) -> list:
    w0 = (key >> 8) & 0xFF
    w1 = key & 0xFF
    w2 = w0 ^ 0b10000000 ^ list_to_int(substitute_nibble([w1 & 0xF, (w1 >> 4) & 0xF]))
    w3 = w2 ^ w1
    w4 = w2 ^ 0b00110000 ^ list_to_int(substitute_nibble([w3 & 0xF, (w3 >> 4) & 0xF]))
    w5 = w4 ^ w3
    return [w0, w1, w2, w3, w4, w5]


# 基础加密函数
def encrypt(plain: int, key: int) -> int:
    # 密钥扩展
    key = key_expansion(key)

    # 明文转为状态矩阵
    state = int_to_matrix(plain)

    # 进行加密过程
    state = key_addition(state, key[:2])  # 初始密钥加
    state = substitute_nibble(state)  # 半字节代替
    state = shift_rows(state)  # 行移位
    state = mix_columns(state)  # 列混淆
    state = key_addition(state, key[2:4])  # 第二轮密钥加

    state = substitute_nibble(state)  # 半字节代替
    state = shift_rows(state)  # 行移位
    state = key_addition(state, key[4:])  # 最后一轮密钥加

    # 返回加密后的结果
    return matrix_to_int(state)

# 基础解密函数
def decrypt(cipher: int, key: int) -> int:
    # 密钥扩展
    key = key_expansion(key)

    # 密文转为状态矩阵
    state = int_to_matrix(cipher)

    # 解密过程
    state = key_addition(state, key[4:])  # 初始密钥加
    state = shift_rows(state)  # 行移位
    state = substitute_nibble(state, inverse=True)  # 半字节代替
    state = key_addition(state, key[2:4])  # 第二轮密钥加
    state = mix_columns(state, inverse=True)  # 列混淆

    state = shift_rows(state)  # 行移位
    state = substitute_nibble(state, inverse=True)  # 半字节代替
    state = key_addition(state, key[:2])  # 最后一轮密钥加

    # 返回解密后的结果
    return matrix_to_int(state)


# 字符串加密
def encrypt_string(plain_text: str, key: int) -> str:
    blocks = ascii_string_to_blocks(plain_text) #将明文字符串转化为块列表（每个块16位）
    cipher_blocks = []
    for block in blocks:
        cipher_block = encrypt(block, key)
        cipher_blocks.append(cipher_block)
    return blocks_to_ascii_string(cipher_blocks)


# 字符串解密
def decrypt_string(cipher_text: str, key: int) -> str:
    cipher = ascii_string_to_blocks(cipher_text)
    plain_blocks = []
    for block in cipher:
        plain_block = decrypt(block, key)
        plain_blocks.append(plain_block)
    return blocks_to_ascii_string(plain_blocks)


# 双重加密
def double_encrypt(plain: int, key: int) -> int:
    k1 = (key >> 16) & 0xFFFF
    k2 = key & 0xFFFF
    cipher = encrypt(plain, k1)
    return encrypt(cipher, k2)


# 双重解密
def double_decrypt(cipher: int, key: int) -> int:
    k1 = (key >> 16) & 0xFFFF
    k2 = key & 0xFFFF
    plain = decrypt(cipher, k2)
    return decrypt(plain, k1)


# 三重加密
def triple_encrypt(plain: int, key: int) -> int:
    k1 = (key >> 32) & 0xFFFF
    k2 = (key >> 16) & 0xFFFF
    k3 = key & 0xFFFF
    cipher = encrypt(plain, k1)
    cipher = encrypt(cipher, k2)
    return encrypt(cipher, k3)


# 三重解密
def triple_decrypt(cipher: int, key: int) -> int:
    k1 = (key >> 32) & 0xFFFF
    k2 = (key >> 16) & 0xFFFF
    k3 = key & 0xFFFF
    plain = decrypt(cipher, k3)
    plain = decrypt(plain, k2)
    return decrypt(plain, k1)


# Cipher Block Chaining (CBC) 加密
def cbc_encrypt(plain: str, key: int, iv: int) -> str:
    plain = string_to_blocks(plain)
    cipher = []
    prev_cipher = iv
    for plain_block in plain:
        cipher_block = encrypt(plain_block ^ prev_cipher, key)
        cipher.append(cipher_block)
        prev_cipher = cipher_block
    return blocks_to_string(cipher)


# Cipher Block Chaining (CBC) 解密
def cbc_decrypt(cipher: str, key: int, iv: int) -> str: #->：返回str类型
    cipher = string_to_blocks(cipher)
    plain = []
    prev_cipher = iv
    for cipher_block in cipher:
        plain_block = decrypt(cipher_block, key) ^ prev_cipher
        plain.append(plain_block)
        prev_cipher = cipher_block
    return blocks_to_string(plain)


# 中间相遇攻击
def attack(plaintexts: str, ciphertexts: str) -> list:
    plaintexts = plaintexts.split()
    ciphertexts = ciphertexts.split()

    possible_keys = {}

    # 遍历第一个明密文对，生成初步候选密钥
    plain = int(plaintexts[0], 2)
    cipher = int(ciphertexts[0], 2)

    for k1 in range(0x10000):
        mid_value = encrypt(plain, k1)
        possible_keys[mid_value] = k1

    found_keys = []

    for k2 in range(0x10000):
        mid_value = decrypt(cipher, k2)
        if mid_value in possible_keys:
            found_keys.append((possible_keys[mid_value], k2))

    # 用剩余明密文对验证并过滤候选密钥
    for i in range(1, len(plaintexts)):
        plain = int(plaintexts[i], 2)
        cipher = int(ciphertexts[i], 2)
        found_keys = [
            (k1, k2) for k1, k2 in found_keys
            if encrypt(plain, k1) == decrypt(cipher, k2)
        ]

    return found_keys


