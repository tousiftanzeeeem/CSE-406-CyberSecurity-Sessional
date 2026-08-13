
import socket

from socket_util.socket_utils import send_msg, recv_msg
from dh import generate_suitable_prime, find_generator, generate_private_key,derive_aes_key
from aes import key_expansion, cbc_encrypt, ecb_encrypt

HOST = '127.0.0.1'
PORT = 65432

DH_BITS = 128     
AES_KEY_BITS = 128 
MODE = "CBC"     
MESSAGE = "Hello Bob! This message was encrypted with our DH-derived AES key."


def main():
    print("[ALICE] generating DH public parameters (P, g) ...")
    P, q = generate_suitable_prime(DH_BITS)
    g = find_generator(P, q)

    Ka = generate_private_key(DH_BITS)
    A = pow(g, Ka, P)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        print(f"[ALICE] connected to Bob at {HOST}:{PORT}")
        send_msg(sock, str(P).encode())
        send_msg(sock, str(g).encode())
        send_msg(sock, str(A).encode())
        print(f"[ALICE] sent P (bit length={P.bit_length()}), g, A")

        B = int(recv_msg(sock).decode())
        print("[ALICE] received B")

        s_shared = pow(B, Ka, P)
        aes_key = derive_aes_key(s_shared, AES_KEY_BITS)
        round_keys = key_expansion(aes_key)
        print("[ALICE] shared secret s computed")
        print(f"[ALICE] derived AES key (hex) = {aes_key.hex()}")

        ready = recv_msg(sock).decode()
        assert ready == "READY", f"Unexpected handshake reply: {ready}"
        print("[ALICE] Bob is READY, sending ciphertext ...")

        plaintext = MESSAGE.encode()
        if MODE == "CBC":
            ciphertext = cbc_encrypt(plaintext, round_keys)
        elif MODE == "ECB":
            ciphertext = ecb_encrypt(plaintext, round_keys)
        else:
            raise ValueError(f"Unknown mode: {MODE}")

        send_msg(sock, MODE.encode())
        send_msg(sock, ciphertext)

        print(f"[ALICE] plaintext (ASCII) = {MESSAGE}")
        print(f"[ALICE] plaintext (HEX)   = {plaintext.hex()}")
        print(f"[ALICE] ciphertext (HEX)  = {ciphertext.hex()}")
        print(f"[ALICE] sent {len(ciphertext)}-byte ciphertext, mode={MODE}")


if __name__ == "__main__":
    main()