import socket

with socket.create_connection(("127.0.0.1", 57520)) as sock:
    sock.sendall(b'{"kind":"stop"}\n')
    print(sock.makefile("rb").readline().decode(), end="")
