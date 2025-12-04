import socket
import threading
import json
import argparse
from datetime import datetime
from queue import Queue, Empty
from typing import Optional
import html as html_lib
import random
import time



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

MODE_PROFILES = {
    "fast": {
        "timeout": 0.3,
        "threads": 100,
        "jitter": (0.0, 0.02),
        "shuffle": True,
    },
    "normal": {
        "timeout": 0.5,
        "threads": 100,
        "jitter": (0.0, 0.00),
        "shuffle": False,
    },
    "aggressive": {
        "timeout": 0.2,
        "threads": 300,
        "jitter": (0.0, 0.05),
        "shuffle": True,
    },
    "stealth": {
        "timeout": 1.0,
        "threads": 30,
        "jitter": (0.05, 0.5),
        "shuffle": True,
    },
}

def get_mode_settings(mode: str, threads_override: Optional[int] = None):
    profile = MODE_PROFILES.get(mode, MODE_PROFILES["normal"])
    timeout = profile["timeout"]
    threads = threads_override if threads_override and threads_override > 0 else profile["threads"]
    jitter_min, jitter_max = profile["jitter"]
    shuffle = profile["shuffle"]
    return {
        "timeout": timeout,
        "threads": threads,
        "jitter": (jitter_min, jitter_max),
        "shuffle": shuffle,
    }

def get_service_name(port: int) -> str:
    # Check own mapping first
    if port in common_services:
        return common_services[port]

    # Then check system mapping
    try:
        return socket.getservbyport(port)
    except OSError:
        return "Unknown Service"


def grab_banner(host: str, port: int, timeout: float = 1.0) -> Optional[str]:
    """
    Attempt to grab the banner from an open port.
    Returns the banner string or None.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))

            # For HTTP-like ports, send a simple request to provoke a response
            if port in {80, 8080, 8000, 8008}:
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                except OSError:
                    pass

            try:
                data = s.recv(1024)
                if not data:
                    return None
                return data.decode(errors="ignore").strip()
            except socket.timeout:
                return None
    except OSError:
        return None


def update_progress(stats: dict, verbose: bool):
    """
    Simple text progress bar when verbose is False.
    Called after each processed port.
    """
    if verbose:
        # When verbose, we print each open port line-by-line, so
        # a progress bar would just look messy.
        return

    processed = stats["processed"]
    total = stats["total"]
    if total == 0:
        return

    progress = processed / total
    bar_len = 30
    filled = int(bar_len * progress)
    bar = "#" * filled + "-" * (bar_len - filled)
    print(
        f"\r[ {bar} ] {processed}/{total} ports ({progress*100:5.1f}%)",
        end="",
        flush=True,
    )


def worker(
    host: str,
    q: Queue,
    open_ports: list,
    stats: dict,
    timeout: float,
    verbose: bool,
    jitter: tuple[float, float],
):
    """
    Worker thread: takes ports from the queue and checks if they're open.
    """
    while True:
        try:
            port = q.get_nowait()
        except Empty:
            break

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                result = s.connect_ex((host, port))
                banner = None
                if result == 0:
                    service = get_service_name(port)

                    if port in BANNER_PORTS:
                        banner = grab_banner(host, port)

                    with print_lock:
                        if verbose:
                            line = f"Port {port}/TCP is open ({service})"
                            if banner:
                                line += f" - Banner: {banner[:60]}"
                            print(line)

                    open_ports.append((port, service, banner))
            except socket.error:
                pass

        with print_lock:
            stats["processed"] += 1
            update_progress(stats, verbose)
        
        # Apply jitter delay if specified
        jmin, jmax = jitter
        if jmax > 0:
            delay = random.uniform(jmin, jmax)
            time.sleep(delay)

        q.task_done()


def generate_html_report(results: dict, html_file: str) -> None:
    
    mode = html_lib.escape(results.get("mode", "unknown"))
    
    """
    Generate an HTML report from the scan results.
    """
    html_content = f"""
    <html>
    <head>
        <title>Port Scan Report for {html_lib.escape(results['host'])}</title>
        <style>
            body {{ font-family: Arial, sans-serif; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <h1>Port Scan Report for {html_lib.escape(results['host'])}</h1>
        <p>Scan started at: {html_lib.escape(results['started_at'])}</p>
        <p>Scan finished at: {html_lib.escape(results['finished_at'])}</p>
        <p>Duration (seconds): {results['duration_seconds']}</p>
        <p>Total ports scanned: {results['total_ports_scanned']}</p>
        <p>Scan mode: {mode}</p>
        <h2>Open Ports</h2>
        <table>
            <tr>
                <th>Port</th>
                <th>Service</th>
                <th>Banner</th>
            </tr>
    """

    for port_info in results["ports"]:
        port = port_info["port"]
        service = html_lib.escape(port_info["service"])
        banner = html_lib.escape(port_info["banner"] or "N/A")
        html_content += f"""
            <tr>
                <td>{port}</td>
                <td>{service}</td>
                <td><pre>{banner}</pre></td>
            </tr>
        """

    html_content += """
        </table>
    </body>
    </html>
    """

    with open(html_file, "w") as f:
        f.write(html_content)

    print(f"\nSaved HTML report to {html_file}")

def threaded_scan(
    host: str,
    ports: list[int],
    num_threads: int,
    timeout: float,
    jitter: tuple[float, float],
    mode: str,
    output_file: str | None = None,
    html_output: str | None = None,
    verbose: bool = True,
):
    """
    Scan a list of TCP ports on a target host using multithreading.
    """

    total_ports = len(ports)
    stats = {"processed": 0, "total": total_ports}

    q = Queue()
    open_ports: list[tuple[int, str, Optional[str]]] = []
    
    ports_to_scan = ports[:]
    if MODE_PROFILES.get(mode, MODE_PROFILES["normal"])["shuffle"]:
        random.shuffle(ports_to_scan)

    # Fill the queue with port numbers
    for port in ports_to_scan:
        q.put(port)

    start_time = datetime.utcnow()

    # Create and start threads
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(
            target=worker,
            args=(host, q, open_ports, stats, timeout, verbose, jitter),
        )
        t.daemon = True
        t.start()
        threads.append(t)

    # Wait for the queue to be empty
    q.join()
    end_time = datetime.utcnow()
    duration = (end_time - start_time).total_seconds()

    # Ensure progress line ends nicely in non-verbose mode
    if not verbose:
        print()

    # Sort and print results
    if open_ports:
        open_ports.sort(key=lambda x: x[0])  # sort by port number
        print(f"\nOpen ports on {host}:")
        for port, service, banner in open_ports:
            if banner:
                print(f"Port {port}/TCP is open ({service}) - Banner: {banner[:80]}")
            else:
                print(f"Port {port}/TCP is open ({service})")
    else:
        print(f"\nNo open ports found on {host} in the selected range.")

    print(f"\nScan completed in {duration:.2f} seconds.")
    print(f"Total ports scanned: {total_ports}")

    # Save results to JSON
    results = {
        "host": host,
        "mode": mode,
        "started_at": start_time.isoformat() + "Z",
        "finished_at": end_time.isoformat() + "Z",
        "duration_seconds": duration,
        "total_ports_scanned": total_ports,
        "ports": [
            {"port": p, "service": s, "banner": b}
            for (p, s, b) in open_ports
        ],
    }

    if output_file is None:
        output_file = "scan_results.json"

    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nSaved results to {output_file}")
    if html_output:
        generate_html_report(results, html_output)
        print(f"\nSaved HTML report to {html_output}")
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
        default=None,
        help="Number of threads to use (default: 100)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output file to save results (default: scan_results.json)",
    )
    parser.add_argument(
        "--html",
        help="Output HTML report file (e.g. report.html)",
    )
    
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output (prints each open port immediately)",
    )
    parser.add_argument(
    "--mode",
        choices=["fast", "normal", "aggressive", "stealth"],
        default="normal",
        help="Scan mode profile (affects timeout, threads, jitter, shuffle)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    ports = parse_ports(args.ports)

    mode_settings = get_mode_settings(args.mode, args.threads)
    
    print(f"[+] Target: {args.host}")
    print(f"[+] Ports: {ports[:10]}{'...' if len(ports) > 10 else ''}")
    print(f"[+] Mode: {args.mode}")
    print(f"[+] Timeout: {mode_settings['timeout']} seconds")
    print(f"[+] Threads: {args.threads}")
    print(f"[+] Verbose: {args.verbose}")
    print(f"[+] HTML report: {args.html if args.html else 'disabled'}\n")

    threaded_scan(
        host=args.host,
        ports=ports,
        num_threads=mode_settings["threads"],
        timeout=mode_settings["timeout"],
        jitter=mode_settings["jitter"],
        mode=args.mode,
        output_file=args.output,
        html_output=args.html,
        verbose=args.verbose,
    )

