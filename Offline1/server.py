import socket

from socket_util.socket_utils import send_msg, recv_msg
from dh import generate_private_key,derive_aes_key
from aes import key_expansion, cbc_decrypt, ecb_decrypt

HOST = '127.0.0.1'
PORT = 65432

AES_KEY_BITS = 128  


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)
        print(f"[BOB] listening on {HOST}:{PORT} ...")

        conn, addr = srv.accept()
        with conn:
            print(f"[BOB] connection from {addr}")
            P = int(recv_msg(conn).decode())
            g = int(recv_msg(conn).decode())
            A = int(recv_msg(conn).decode())
            print(f"[BOB] received P (bit length={P.bit_length()}), g, A")

            k_bits = P.bit_length()
            Kb = generate_private_key(k_bits)
            B = pow(g, Kb, P)
            send_msg(conn, str(B).encode())
            print("[BOB] sent B to Alice")

            s_shared = pow(A, Kb, P)
            aes_key = derive_aes_key(s_shared, AES_KEY_BITS)
            round_keys = key_expansion(aes_key)
            print(f"[BOB] shared secret s computed")
            print(f"[BOB] derived AES key (hex) = {aes_key.hex()}")

            send_msg(conn, b"READY")
            print("[BOB] signaled READY, waiting for ciphertext ...")


            mode = recv_msg(conn).decode()
            ciphertext = recv_msg(conn)
            print(f"[BOB] received {len(ciphertext)}-byte ciphertext, mode={mode}")
            print(f"[BOB] ciphertext (hex) = {ciphertext.hex()}")

            if mode == "CBC":
                plaintext = cbc_decrypt(ciphertext, round_keys)
            elif mode == "ECB":
                plaintext = ecb_decrypt(ciphertext, round_keys)
            else:
                raise ValueError(f"Unknown mode: {mode}")

            print(f"[BOB] recovered plaintext (ASCII) = {plaintext.decode()}")
            print(f"[BOB] recovered plaintext (HEX)   = {plaintext.hex()}")


if __name__ == "__main__":
    main()