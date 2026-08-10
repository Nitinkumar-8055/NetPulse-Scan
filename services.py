import socket


COMMON_SERVICES = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MS-RPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt"
}


def get_banner(host, port):
    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(2)

        sock.connect((host, port))

        banner = sock.recv(1024)

        sock.close()

        if banner:
            return banner.decode(
                "utf-8",
                errors="ignore"
            ).strip()

        return None

    except (socket.timeout, socket.error):
        return None


def get_http_info(host, port):
    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(2)

        sock.connect((host, port))

        request = (
            f"GET / HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        sock.sendall(request.encode())

        response = sock.recv(4096)

        sock.close()

        if response:
            return response.decode(
                "utf-8",
                errors="ignore"
            ).strip()

        return None

    except (socket.timeout, socket.error):
        return None


def identify_service(port, banner=None, http_response=None):

    if http_response:
        if "http/" in http_response.lower():
            return "HTTP"

    if banner:

        banner_lower = banner.lower()

        if "ssh" in banner_lower:
            return "SSH"

        if "ftp" in banner_lower:
            return "FTP"

        if "smtp" in banner_lower:
            return "SMTP"

        if "mysql" in banner_lower:
            return "MySQL"

        if "redis" in banner_lower:
            return "Redis"

        if "http" in banner_lower:
            return "HTTP"

    return COMMON_SERVICES.get(
        port,
        "Unknown"
    )


def clean_banner(text):

    if not text:
        return None

    first_line = text.splitlines()[0]

    first_line = " ".join(
        first_line.split()
    )

    if len(first_line) > 150:
        first_line = first_line[:150] + "..."

    return first_line