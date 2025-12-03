import socket
import threading
import json
import argparse
from datetime import datetime
from queue import Queue

print_lock = threading.Lock()

common_services = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP Proxy",
}

BANNER_PORTS = {21, 22, 25, 80, 110, 143, 443, 8080}

def get_service_name(port: int) -> str:
    # Check own mapping first
    if port in common_services:
        return common_services[port]

    # Then check system mapping
    try:
        return socket.getservbyport(port)
    except OSError:
        return "Unknown Service"

def grab_banner(host: str, port: int, timeout: float = 1.0) -> str:
    """
    Attempt to grab the banner from an open port.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            
            if port in {80, 8080, 8000, 8008}:
                try:
                    s.sendall(b"GET / HTTP/1.0\r\n\r\n")
                except OSError:
                    pass
            try:
                data = s.recv(1024)
                if not data:
                    return None
                return data.decode(errors="ignore").strip()
            except socket.timeout:
                return None
            banner = s.recv(1024).decode(errors="ignore").strip()
            return banner if banner else None
    except OSError:
        return None
    
def worker(host: str, q: Queue, open_ports: list, timeout: float = 0.5, verbose: bool = True):
    """
    Worker thread: takes ports from the queue and checks if they're open.
    """
    while not q.empty():
        port = q.get()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                result = s.connect_ex((host, port))
                if result == 0:
                    service = get_service_name(port)
                    
                    banner = None
                    if port in BANNER_PORTS:
                        banner = grab_banner(host, port)
                        
                    with print_lock:
                        if verbose:
                            line = f"Port {port}/TCP is open ({service})"
                            if banner:
                                line += f" - Banner: {banner[:60]}"
                            print(line)

                    # store (port, service) as a tuple
                    open_ports.append((port, service))
            except socket.error:
                pass

        q.task_done()


def threaded_scan(
    host: str,
    ports: list[int],
    num_threads: int = 100,
    output_file: str | None = None,
    verbose: bool = True,
):
    """
    Scan a list of TCP ports on a target host using multithreading.
    """

    q = Queue()
    open_ports: list[tuple[int, str]] = []

    # Fill the queue with port numbers
    for port in ports:
        q.put(port)

    # Create and start threads
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker, args=(host, q, open_ports, 0.5, verbose))
        t.daemon = True
        t.start()
        threads.append(t)

    # Wait for the queue to be empty
    q.join()

    # Sort and print results
    if open_ports:
        open_ports.sort(key=lambda x: x[0])  # sort by port number
        print(f"\nOpen ports on {host}:")
        for port, service in open_ports:
            print(f"Port {port}/TCP is open ({service})")
    else:
        print(f"\nNo open ports found on {host} in the selected range.")

    # Save results to JSON
    results = {
        "host": host,
        "scanned_at": datetime.utcnow().isoformat() + "Z",
        "ports": [{"port": p, "service": s} for p, s in open_ports],
    }

    if output_file is None:
        output_file = "scan_results.json"

    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nSaved results to {output_file}")

    return open_ports


def parse_ports(ports_str: str) -> list[int]:
    """
    Converts input like '80', '22,80,443', '1-1024' into a sorted list of ports.
    """
    ports = set()

    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            for p in range(int(start), int(end) + 1):
                ports.add(p)
        else:
            ports.add(int(part))

    return sorted(ports)


def parse_args():
    parser = argparse.ArgumentParser(description="Multithreaded TCP Port Scanner")

    parser.add_argument("-H", "--host", required=True, help="Target host (IP or domain)")
    parser.add_argument(
        "-p",
        "--ports",
        default="1-1024",
        help="Ports to scan, e.g. '80', '22,80,443', '1-1024'",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=100,
        help="Number of threads to use (default: 100)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output file to save results (default: scan_results.json)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    ports = parse_ports(args.ports)

    print(f"[+] Target: {args.host}")
    print(f"[+] Ports: {ports[:10]}{'...' if len(ports) > 10 else ''}")
    print(f"[+] Threads: {args.threads}\n")

    threaded_scan(
        host=args.host,
        ports=ports,
        num_threads=args.threads,
        output_file=args.output,
        verbose=args.verbose,
    )
