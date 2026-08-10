import socket


def check_tcp_port(host, port):
    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(1)

        result = sock.connect_ex((host, port))

        sock.close()

        return "OPEN" if result == 0 else "CLOSED"

    except socket.error:
        return "CLOSED"


def check_udp_port(host, port):
    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        sock.settimeout(2)

        sock.connect((host, port))
        sock.send(b"\x00")

        try:
            response = sock.recv(1024)

            sock.close()

            if response:
                return "OPEN"

            return "NO_RESPONSE"

        except socket.timeout:
            sock.close()
            return "NO_RESPONSE"

        except ConnectionRefusedError:
            sock.close()
            return "CLOSED"

    except ConnectionRefusedError:
        return "CLOSED"

    except socket.error:
        return "NO_RESPONSE"