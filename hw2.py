from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

# تعریف S-box
S_BOX = [
    0x3a, 0xc6, 0xd5, 0xe2, 0x58, 0xd0, 0x13, 0x9d,
    0x7a, 0xc9, 0x63, 0x6e, 0x8e, 0xc2, 0x23, 0x25,
    0x41, 0x3b, 0x7b, 0x1e, 0x7d, 0x45, 0x2e, 0x1f,
    0x77, 0xba, 0x9a, 0x7c, 0x34, 0x62, 0xc3, 0x40,
    0x1d, 0x6d, 0x4d, 0x3e, 0x6a, 0xf8, 0xa8, 0x4a,
    0x61, 0x2d, 0xe0, 0xa3, 0x11, 0xbf, 0x7f, 0x27,
    0x98, 0x92, 0x20, 0xa0, 0xc1, 0xb6, 0x1a, 0xeb,
    0x22, 0x9e, 0xce, 0x4b, 0x8c, 0x15, 0xd6, 0xaf
]

# تعریف P-box
P_BOX = [
    0, 16, 32, 48, 1, 17, 33, 49,
    2, 18, 34, 50, 3, 19, 35, 51,
    4, 20, 36, 52, 5, 21, 37, 53,
    6, 22, 38, 54, 7, 23, 39, 55,
    8, 24, 40, 56, 9, 25, 41, 57,
    10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61,
    14, 30, 46, 62, 15, 31, 47, 63
]

# تابع جایگذاری (S-box)
def s_box_substitution(value):
    output = 0
    for i in range(8):
        input_bits = (value >> (6 * i)) & 0x3F
        sbox_output = S_BOX[input_bits]
        output |= (sbox_output << (4 * i))
    return output

# تابع جابجایی (P-box)
def p_box_permutation(value):
    output = 0
    for i in range(64):
        bit = (value >> i) & 0x1
        output |= (bit << P_BOX[i])
    return output

# تابع دور (Round Function)
def F(R, K):
    return p_box_permutation(s_box_substitution(R ^ K))

# تابع تولید کلیدهای فرعی
def generate_round_keys(main_key, num_rounds):
    salt = b'\x00' * 16  # تعریف salt ثابت
    return [int.from_bytes(HKDF(main_key.to_bytes(32, 'big'), 16, salt=salt, context=bytes([i]), hashmod=SHA256), 'big') for i in range(1, num_rounds + 1)]

# تابع اصلی الگوریتم فیستل
def feistel_cipher(block, key, rounds=20):
  #بلوک 128 بیتی ورودی به دو نیم‌بلوک 64 بیتی L0, R0
  #تقسیم می‌شود.
    L = (block >> 64) & 0xFFFFFFFFFFFFFFFF
    R = block & 0xFFFFFFFFFFFFFFFF
  #کلیدهای فرعی با استفاده از تابع HKDF و کلید اصلی تولید می‌شوند.
    round_keys = generate_round_keys(key, rounds)
  #حلقه برای تعداد دورهای مشخص (در اینجا 20 دور) شروع می‌شود.
    for i in range(rounds):
        L, R = R, L ^ F(R, round_keys[i])
    
    return (R << 64) | L

# مثال
block = int("0123456789ABCDEF0123456789ABCDEF", 16)
key = int("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", 16)

cipher_text = feistel_cipher(block, key)
print(f"Cipher Text: {hex(cipher_text)}")
