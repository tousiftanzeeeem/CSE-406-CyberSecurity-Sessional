import struct

_HEADER_SIZE = 4  


def send_msg(sock, data: bytes):
    header = struct.pack('>I', len(data))
    sock.sendall(header + data)


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed before expected data arrived")
        buf += chunk
    return bytes(buf)


def recv_msg(sock) -> bytes:
    header = _recv_exact(sock, _HEADER_SIZE)
    (length,) = struct.unpack('>I', header)
    return _recv_exact(sock, length)