import os
import time
from aes_helpers import Sbox, InvSbox, Rcon, Mixer, InvMixer, gf_mult

BLOCK_SIZE = 16   
Nb = 4          
Nk = 4            
Nr = 10          



def sub_bytes(state, box):
    return bytearray(box[b] for b in state)


def shift_rows(state, inverse=False):
    """Row r is shifted left by r (encryption) or right by r (decryption)."""
    new = bytearray(16)
    for r in range(4):
        for c in range(4):
            src_c = (c - r) % 4 if inverse else (c + r) % 4
            new[r + 4 * c] = state[r + 4 * src_c]
    return new


def mix_columns(state, mixer):
    new = bytearray(16)
    for c in range(4):
        col = state[4 * c: 4 * c + 4]
        for r in range(4):
            val = 0
            for k in range(4):
                val ^= gf_mult(mixer[r][k], col[k])
            new[r + 4 * c] = val
    return new


def add_round_key(state, round_key):
    return bytearray(a ^ b for a, b in zip(state, round_key))



def _sub_word(word):
    return [Sbox[b] for b in word]


def _rot_word(word):
    return word[1:] + word[:1]


def key_expansion(key_bytes):
    w = [list(key_bytes[4 * i: 4 * i + 4]) for i in range(Nk)]

    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1][:]
        if i % Nk == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= Rcon[i // Nk]
        w.append([w[i - Nk][j] ^ temp[j] for j in range(4)])

    round_keys = []
    for r in range(Nr + 1):
        rk = bytearray()
        for c in range(4):
            rk += bytes(w[4 * r + c])
        round_keys.append(bytes(rk))
    return round_keys


def normalize_key(key_str, key_len_bytes=16):
    key_bytes = key_str.encode('utf-8')
    if len(key_bytes) >= key_len_bytes:
        return key_bytes[:key_len_bytes]
    return key_bytes + b'\x00' * (key_len_bytes - len(key_bytes))


def encrypt_block(plaintext_block, round_keys):
    state = bytearray(plaintext_block)
    state = add_round_key(state, round_keys[0])

    for r in range(1, Nr):
        state = sub_bytes(state, Sbox)
        state = shift_rows(state)
        state = mix_columns(state, Mixer)
        state = add_round_key(state, round_keys[r])

    state = sub_bytes(state, Sbox)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[Nr])
    return bytes(state)


def decrypt_block(ciphertext_block, round_keys):
    state = bytearray(ciphertext_block)
    state = add_round_key(state, round_keys[Nr])

    for r in range(Nr - 1, 0, -1):
        state = shift_rows(state, inverse=True)
        state = sub_bytes(state, InvSbox)
        state = add_round_key(state, round_keys[r])
        state = mix_columns(state, InvMixer)

    state = shift_rows(state, inverse=True)
    state = sub_bytes(state, InvSbox)
    state = add_round_key(state, round_keys[0])
    return bytes(state)



def pkcs7_pad(data):
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-pad_len]


def ecb_encrypt(plaintext, round_keys):
    padded = pkcs7_pad(plaintext)
    ct = bytearray()
    for i in range(0, len(padded), BLOCK_SIZE):
        ct += encrypt_block(padded[i:i + BLOCK_SIZE], round_keys)
    return bytes(ct)


def ecb_decrypt(ciphertext, round_keys):
    pt = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        pt += decrypt_block(ciphertext[i:i + BLOCK_SIZE], round_keys)
    return pkcs7_unpad(bytes(pt))


def cbc_encrypt(plaintext, round_keys, iv=None):
    if iv is None:
        iv = os.urandom(BLOCK_SIZE)
    padded = pkcs7_pad(plaintext)
    ct = bytearray()
    prev = iv
    for i in range(0, len(padded), BLOCK_SIZE):
        block = bytes(a ^ b for a, b in zip(padded[i:i + BLOCK_SIZE], prev))
        enc = encrypt_block(block, round_keys)
        ct += enc
        prev = enc
    return iv + bytes(ct)   # IV prepended (first 16 bytes)


def cbc_decrypt(iv_and_ciphertext, round_keys):
    iv = iv_and_ciphertext[:BLOCK_SIZE]
    ciphertext = iv_and_ciphertext[BLOCK_SIZE:]
    pt = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        dec = decrypt_block(block, round_keys)
        pt += bytes(a ^ b for a, b in zip(dec, prev))
        prev = block
    return pkcs7_unpad(bytes(pt))


def _ascii_repr(b):
    return ''.join(chr(x) if 32 <= x < 127 else '.' for x in b)


def run_demo(key_str, plaintext_str, mode="ECB"):
    print(f"===== Mode: {mode} =====")
    print(f"Key (ASCII) : {key_str}")

    t0 = time.perf_counter()
    key_bytes = normalize_key(key_str)
    round_keys = key_expansion(key_bytes)
    t1 = time.perf_counter()

    print(f"Key (HEX)   : {key_bytes.hex()}")
    print(f"Plaintext   : {plaintext_str}")

    plaintext = plaintext_str.encode('utf-8')

    t2 = time.perf_counter()
    if mode == "ECB":
        ciphertext = ecb_encrypt(plaintext, round_keys)
    else:
        ciphertext = cbc_encrypt(plaintext, round_keys)
    t3 = time.perf_counter()

    print(f"Ciphertext (HEX) : {ciphertext.hex()}")

    t4 = time.perf_counter()
    if mode == "ECB":
        recovered = ecb_decrypt(ciphertext, round_keys)
    else:
        recovered = cbc_decrypt(ciphertext, round_keys)
    t5 = time.perf_counter()

    print(f"Recovered (ASCII): {recovered.decode('utf-8', errors='replace')}")
    print(f"Recovered (HEX)  : {recovered.hex()}")
    print(f"Match original?  : {recovered == plaintext}")

    print(f"Key-schedule time : {(t1 - t0) * 1000:.3f} ms")
    print(f"Encryption time   : {(t3 - t2) * 1000:.3f} ms")
    print(f"Decryption time   : {(t5 - t4) * 1000:.3f} ms")
    print()


key = "ThisIsASecretKey"        
message = "The quick brown fox jumps over the lazy dog. AES-128 demo!"

if __name__ == "__main__":
    run_demo(key, message, mode="ECB")
    run_demo(key, message, mode="CBC")
