import argparse
import sys
import time
from datetime import datetime

from colorama import Fore, Style, init

from scanner import check_tcp_port, check_udp_port

from services import (
    COMMON_SERVICES,
    get_banner,
    get_http_info,
    identify_service,
    clean_banner
)

from logger import (
    setup_logging,
    log_event
)

from alerts import send_alert

from report import generate_report


# =========================================================
# COLORAMA
# =========================================================

init(autoreset=True)


# =========================================================
# COLORS
# =========================================================

GREEN = Fore.GREEN
CYAN = Fore.CYAN
YELLOW = Fore.YELLOW
RED = Fore.RED
MAGENTA = Fore.MAGENTA
WHITE = Fore.WHITE
GRAY = Fore.LIGHTBLACK_EX

BOLD = Style.BRIGHT
RESET = Style.RESET_ALL


# =========================================================
# VERSION
# =========================================================

VERSION = "1.0.0"


# =========================================================
# PORT PROFILES
# =========================================================

PORT_PROFILES = {

    "common": [
        21, 22, 23, 25, 53,
        80, 110, 135, 139, 143,
        443, 445, 3306, 5432,
        6379, 8080, 8443
    ],

    "web": [
        80,
        443,
        8000,
        8008,
        8080,
        8081,
        8443,
        8888
    ],

    "database": [
        1433,
        1521,
        3306,
        5432,
        6379,
        9042,
        27017
    ]
}


# =========================================================
# BANNER
# =========================================================

def print_banner():

    print()

    print(
        f"{CYAN}{BOLD}NetPulse Scan{RESET}"
        f" on {MAGENTA}main{RESET}"
        f" {YELLOW}[?]{RESET}"
        f" is {MAGENTA}netpulse:{VERSION}{RESET}"
        f" via {MAGENTA}"
        f"Python {sys.version_info.major}."
        f"{sys.version_info.minor}"
        f"{RESET}"
    )

    print()

    print(
        f"{GREEN}"
        "███╗   ██╗███████╗████████╗██████╗ ██╗   ██╗██╗     ███████╗███████╗\n"
        "████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║   ██║██║     ██╔════╝██╔════╝\n"
        "██╔██╗ ██║█████╗     ██║   ██████╔╝██║   ██║██║     ███████╗█████╗  \n"
        "██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝  \n"
        "██║ ╚████║███████╗   ██║   ██║     ╚██████╔╝███████╗███████║███████╗\n"
        "╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝"
        f"{RESET}"
    )

    print()

    print(
        f"{CYAN}"
        "Network Port Monitoring & Change Detection."
        f"{RESET}"
    )

    print()

    print(
        f"{GRAY}"
        "────────────────────────────────────────────────────"
        f"{RESET}"
    )

    print(
        f"{GREEN}[~]{RESET} TCP / UDP monitoring"
    )

    print(
        f"{GREEN}[~]{RESET} Service detection"
    )

    print(
        f"{GREEN}[~]{RESET} Banner detection"
    )

    print(
        f"{GREEN}[~]{RESET} Baseline change detection"
    )

    print(
        f"{GREEN}[~]{RESET} Security alerts"
    )

    print(
        f"{GREEN}[~]{RESET} JSON / HTML reports"
    )

    print()


# =========================================================
# PORT PARSER
# =========================================================

def parse_ports(port_string):
    """
    Convert a comma-separated string into a list of ports.

    Example:
        "22,80,443" -> [22, 80, 443]
    """

    try:

        ports = [
            int(port.strip())
            for port in port_string.split(",")
        ]

    except ValueError:

        raise ValueError(
            "Ports must contain only numbers."
        )

    # Validate port range
    for port in ports:

        if port < 1 or port > 65535:

            raise ValueError(
                f"Invalid port: {port}. "
                "Valid range is 1-65535."
            )

    return ports


# =========================================================
# EXPECTED PORT PARSER
# =========================================================

def parse_expected_ports(port_string):
    """
    Convert expected-open ports into a set.

    Example:
        "22,80,443" -> {22, 80, 443}
    """

    if not port_string:

        return set()

    return set(
        parse_ports(port_string)
    )


# =========================================================
# EVENT CREATION
# =========================================================

def add_event(
    events,
    event_type,
    protocol,
    port,
    service,
    status=None,
    old_status=None,
    new_status=None,
    banner=None
):
    """
    Add a structured event to the report.
    """

    event = {
        "time": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "type": event_type,
        "protocol": protocol,
        "port": port,
        "service": service
    }

    if status is not None:

        event["status"] = status

    if old_status is not None:

        event["old_status"] = old_status

    if new_status is not None:

        event["new_status"] = new_status

    if banner:

        event["banner"] = clean_banner(
            banner
        )

    events.append(event)


# =========================================================
# PORT CHECK
# =========================================================

def check_port(protocol, host, port):
    """
    Check a port using the selected protocol.
    """

    if protocol == "TCP":

        return check_tcp_port(
            host,
            port
        )

    return check_udp_port(
        host,
        port
    )


# =========================================================
# SERVICE DETECTION
# =========================================================

def detect_service(
    host,
    port,
    protocol,
    status
):
    """
    Detect the service running on an open TCP port.

    UDP service probing is not performed because
    generic UDP service detection is unreliable.
    """

    service = COMMON_SERVICES.get(
        port,
        "Unknown"
    )

    banner = None
    http_response = None

    # Service detection only for TCP
    if protocol != "TCP":

        return service, banner, http_response

    # Only probe open ports
    if status != "OPEN":

        return service, banner, http_response

    # HTTP probing
    if port in (
        80,
        8000,
        8008,
        8080
    ):

        http_response = get_http_info(
            host,
            port
        )

    # Generic banner detection
    if not http_response:

        banner = get_banner(
            host,
            port
        )

    # Identify service
    service = identify_service(
        port,
        banner,
        http_response
    )

    return (
        service,
        banner,
        http_response
    )


# =========================================================
# INITIAL STATE OUTPUT
# =========================================================

def print_initial_state(
    protocol,
    port,
    status,
    service,
    banner,
    http_response
):
    """
    Print the initial state of a monitored port.
    """

    if status == "OPEN":

        status_color = GREEN

    elif status == "CLOSED":

        status_color = GRAY

    elif status == "NO_RESPONSE":

        status_color = YELLOW

    else:

        status_color = WHITE

    print(
        f"{GREEN}[+]{RESET} "
        f"{CYAN}{protocol:<4}{RESET} "
        f"{WHITE}{port:<5}{RESET} "
        f"{status_color}{status:<12}{RESET} "
        f"Service: {CYAN}{service}{RESET}"
    )

    if banner:

        print(
            f"    {GRAY}Banner :{RESET} "
            f"{WHITE}"
            f"{clean_banner(banner)}"
            f"{RESET}"
        )

    if http_response:

        print(
            f"    {GRAY}HTTP   :{RESET} "
            f"{WHITE}"
            f"{clean_banner(http_response)}"
            f"{RESET}"
        )


# =========================================================
# MONITOR
# =========================================================

def monitor(args):

    # Setup logging
    setup_logging()

    # Previous states
    previous_status = {}

    # Events for report
    events = []

    # Expected TCP open ports
    expected_open = parse_expected_ports(
        args.expected_open
    )

    # ==========================================
    # DISPLAY CONFIGURATION
    # ==========================================

    print()

    print(
        f"{GRAY}"
        "=============================================="
        f"{RESET}"
    )

    print(
        f"{GREEN}{BOLD}"
        "              NETPULSE SCAN v1.0"
        f"{RESET}"
    )

    print(
        f"{GRAY}"
        "=============================================="
        f"{RESET}"
    )

    print(
        f"{GRAY}Target        :{RESET} "
        f"{CYAN}{args.host}{RESET}"
    )

    print(
        f"{GRAY}Ports         :{RESET} "
        f"{WHITE}{args.ports}{RESET}"
    )

    print(
        f"{GRAY}Profile       :{RESET} "
        f"{CYAN}{args.profile}{RESET}"
    )

    print(
        f"{GRAY}Protocol      :{RESET} "
        f"{CYAN}{args.protocol.upper()}{RESET}"
    )

    print(
        f"{GRAY}Expected Open :{RESET} "
        f"{WHITE}{sorted(expected_open)}{RESET}"
    )

    print(
        f"{GRAY}Interval      :{RESET} "
        f"{WHITE}{args.interval} seconds{RESET}"
    )

    print(
        f"{GRAY}Log file      :{RESET} "
        f"{WHITE}logs/monitor.log{RESET}"
    )

    print(
        f"{GRAY}"
        "=============================================="
        f"{RESET}"
    )

    print()

    print(
        f"{GREEN}[~]{RESET} "
        f"Monitoring started..."
    )

    print()

    # Log start
    log_event(
        f"Monitoring started | "
        f"Target={args.host} | "
        f"Ports={args.ports} | "
        f"Profile={args.profile} | "
        f"Protocol={args.protocol.upper()} | "
        f"ExpectedOpen={sorted(expected_open)}"
    )

    # ==========================================
    # DETERMINE PROTOCOLS
    # ==========================================

    protocols = []

    if args.protocol in (
        "tcp",
        "both"
    ):

        protocols.append("TCP")

    if args.protocol in (
        "udp",
        "both"
    ):

        protocols.append("UDP")

    # ==========================================
    # MONITORING LOOP
    # ==========================================

    try:

        while True:

            for protocol in protocols:

                for port in args.ports:

                    # ==================================
                    # CHECK PORT
                    # ==================================

                    status = check_port(
                        protocol,
                        args.host,
                        port
                    )

                    # ==================================
                    # SERVICE DETECTION
                    # ==================================

                    (
                        service,
                        banner,
                        http_response
                    ) = detect_service(
                        args.host,
                        port,
                        protocol,
                        status
                    )

                    # Unique key for protocol + port
                    key = (
                        protocol,
                        port
                    )

                    # ==================================
                    # FIRST OBSERVATION
                    # ==================================

                    if key not in previous_status:

                        previous_status[key] = status

                        print_initial_state(
                            protocol,
                            port,
                            status,
                            service,
                            banner,
                            http_response
                        )

                        # Log initial state
                        log_event(
                            f"Initial state | "
                            f"Host={args.host} | "
                            f"Protocol={protocol} | "
                            f"Port={port} | "
                            f"Service={service} | "
                            f"Status={status}"
                        )

                        # Add report event
                        add_event(
                            events,
                            "INITIAL_STATE",
                            protocol,
                            port,
                            service,
                            status=status,
                            banner=banner
                        )

                        # ==================================
                        # BASELINE CHECK
                        # ==================================

                        if protocol == "TCP":

                            expected_status = (
                                "OPEN"
                                if port in expected_open
                                else "CLOSED"
                            )

                            # Unexpected state
                            if status != expected_status:

                                print(
                                    f"{RED}[!]{RESET} "
                                    f"{BOLD}{RED}"
                                    f"ALERT"
                                    f"{RESET}: "
                                    f"Unexpected TCP state "
                                    f"on port "
                                    f"{CYAN}{port}{RESET}"
                                )

                                # Desktop notification
                                send_alert(
                                    "Unexpected Port State",
                                    (
                                        f"TCP port {port} "
                                        f"({service}) is "
                                        f"{status}"
                                    )
                                )

                                # Log alert
                                log_event(
                                    f"ALERT | "
                                    f"Unexpected state | "
                                    f"Host={args.host} | "
                                    f"Protocol=TCP | "
                                    f"Port={port} | "
                                    f"Service={service} | "
                                    f"Actual={status}"
                                )

                                # Report event
                                add_event(
                                    events,
                                    "ALERT",
                                    protocol,
                                    port,
                                    service,
                                    status=status,
                                    banner=banner
                                )

                    # ==================================
                    # STATE CHANGE
                    # ==================================

                    elif (
                        previous_status[key]
                        != status
                    ):

                        old_status = (
                            previous_status[key]
                        )

                        new_status = status

                        print()

                        print(
                            f"{YELLOW}[!]{RESET} "
                            f"{BOLD}{YELLOW}"
                            f"CHANGE DETECTED"
                            f"{RESET}"
                        )

                        print(
                            f"    {GRAY}Protocol :{RESET} "
                            f"{CYAN}{protocol}{RESET}"
                        )

                        print(
                            f"    {GRAY}Port     :{RESET} "
                            f"{WHITE}{port}{RESET}"
                        )

                        print(
                            f"    {GRAY}Service  :{RESET} "
                            f"{CYAN}{service}{RESET}"
                        )

                        print(
                            f"    {GRAY}Status   :{RESET} "
                            f"{old_status} "
                            f"{YELLOW}->{RESET} "
                            f"{new_status}"
                        )

                        if banner:

                            print(
                                f"    {GRAY}Banner   :{RESET} "
                                f"{WHITE}"
                                f"{clean_banner(banner)}"
                                f"{RESET}"
                            )

                        # Log change
                        log_event(
                            f"Port change | "
                            f"Host={args.host} | "
                            f"Protocol={protocol} | "
                            f"Port={port} | "
                            f"Service={service} | "
                            f"Status={old_status}"
                            f"->{new_status}"
                        )

                        # Add change event
                        add_event(
                            events,
                            "PORT_CHANGE",
                            protocol,
                            port,
                            service,
                            old_status=old_status,
                            new_status=new_status,
                            banner=banner
                        )

                        # ==================================
                        # BASELINE CHECK
                        # ==================================

                        if protocol == "TCP":

                            expected_status = (
                                "OPEN"
                                if port in expected_open
                                else "CLOSED"
                            )

                            # Unexpected state
                            if (
                                new_status
                                != expected_status
                            ):

                                print(
                                    f"{RED}"
                                    "    🚨 ALERT: "
                                    "Unexpected port state!"
                                    f"{RESET}"
                                )

                                # Desktop notification
                                send_alert(
                                    "Port State Changed",
                                    (
                                        f"TCP port {port} "
                                        f"({service}): "
                                        f"{old_status} -> "
                                        f"{new_status}"
                                    )
                                )

                                # Log alert
                                log_event(
                                    f"ALERT | "
                                    f"Unexpected state | "
                                    f"Host={args.host} | "
                                    f"Protocol=TCP | "
                                    f"Port={port} | "
                                    f"Service={service} | "
                                    f"Actual={new_status}"
                                )

                                # Add alert event
                                add_event(
                                    events,
                                    "ALERT",
                                    protocol,
                                    port,
                                    service,
                                    status=new_status,
                                    banner=banner
                                )

                        # Update previous state
                        previous_status[key] = status

            # ==================================
            # WAIT
            # ==================================

            time.sleep(
                args.interval
            )

    # ==========================================
    # STOP MONITORING
    # ==========================================

    except KeyboardInterrupt:

        print()

        print(
            f"{YELLOW}[~]{RESET} "
            f"Monitoring stopped."
        )

        # Log stop
        log_event(
            f"Monitoring stopped | "
            f"Target={args.host}"
        )

        # Generate report
        generate_report(
            args.host,
            args.ports,
            events
        )

        print()

        print(
            f"{GREEN}[+]{RESET} "
            f"Report generated."
        )

        print(
            f"{GRAY}[*]{RESET} "
            f"Exiting..."
        )

        print()


# =========================================================
# MAIN
# =========================================================

def main():

    # ==========================================
    # BANNER
    # ==========================================

    print_banner()

    # ==========================================
    # CLI CONFIGURATION
    # ==========================================

    parser = argparse.ArgumentParser(
        description=(
            "NetPulse Scan - "
            "TCP/UDP Port Monitoring Tool"
        )
    )

    parser.add_argument(
        "--host",
        required=True,
        help=(
            "Target IP address or hostname"
        )
    )

    # ==========================================
    # PORTS
    # ==========================================

    parser.add_argument(
        "--ports",
        required=False,
        help=(
            "Ports to monitor, "
            "example: 22,80,443,8080"
        )
    )

    # ==========================================
    # PROFILE
    # ==========================================

    parser.add_argument(
        "--profile",
        choices=[
            "common",
            "web",
            "database"
        ],
        default="common",
        help=(
            "Port profile to monitor "
            "(default: common)"
        )
    )

    # ==========================================
    # PROTOCOL
    # ==========================================

    parser.add_argument(
        "--protocol",
        choices=[
            "tcp",
            "udp",
            "both"
        ],
        default="tcp",
        help=(
            "Protocol to monitor "
            "(default: tcp)"
        )
    )

    # ==========================================
    # INTERVAL
    # ==========================================

    parser.add_argument(
        "--interval",
        type=int,
        default=5,
        help=(
            "Monitoring interval "
            "in seconds (default: 5)"
        )
    )

    # ==========================================
    # EXPECTED OPEN
    # ==========================================

    parser.add_argument(
        "--expected-open",
        default="",
        help=(
            "TCP ports expected to be open, "
            "example: 22,80,443"
        )
    )

    # ==========================================
    # PARSE ARGUMENTS
    # ==========================================

    args = parser.parse_args()

    # ==========================================
    # VALIDATE INTERVAL
    # ==========================================

    if args.interval <= 0:

        parser.error(
            "--interval must be greater than 0"
        )

    # ==========================================
    # VALIDATE / SELECT PORTS
    # ==========================================

    try:

        if args.ports:

            # Custom ports override profile
            args.ports = parse_ports(
                args.ports
            )

        else:

            # Use selected profile
            args.ports = PORT_PROFILES[
                args.profile
            ].copy()

    except ValueError as error:

        parser.error(
            str(error)
        )

    # ==========================================
    # VALIDATE EXPECTED PORTS
    # ==========================================

    try:

        parse_expected_ports(
            args.expected_open
        )

    except ValueError as error:

        parser.error(
            str(error)
        )

    # ==========================================
    # START MONITOR
    # ==========================================

    monitor(args)


# =========================================================
# ENTRY POINT
# =========================================================

if __name__ == "__main__":

    main()