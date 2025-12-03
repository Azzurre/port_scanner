import socket;
import threading
from datetime import datetime;
from queue import Queue;

print_lock = threading.Lock();

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
        8080: "HTTP Proxy"
    }
        
def get_service_name(port: int) -> str:
        #check own mapping first
        if port in common_services:
            return common_services[port]
        #then check system mapping
        try:
            return socket.getservbyport(port)
        except OSError:
            return "Unknown Service"
        
def worker(host: str, q: Queue , open_ports: list, timeout: float = 0.5):
    """
    Try to connect to a single TCP port.
    

    Args:
        host (str): _description_
        port (int): _description_
        timeout (float, optional): _description_. Defaults to 0.5.

    Returns:
        bool: Return True if port is open, False otherwise.
    """
    while not q.empty():
        port = q.get();
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout);
        try:
            result = s.connect_ex((host, port));
            if result == 0:
                service = get_service_name(port)
                with print_lock:
                    open_ports.append(port, service);
                    print(f"Port {port}/TCP is open ({service})");
            
        except socket.error:
            pass
        
        q.task_done();
        
def threaded_scan(host: str, start_port: int, end_port: int, num_threads: int = 100):
    """
    Scan a range of TCP ports on a target host using multithreading.
    
    Args:
        host (str): Target host (IP or domain).
        start_port (int): Starting port number.
        end_port (int): Ending port number.
        num_threads (int, optional): Number of threads to use. Defaults to 100.
    """
    q = Queue();
    open_ports = [];
    # Fill the queue with port numbers
    for port in range(start_port, end_port + 1):
        q.put(port);
    # Create and start threads
    threads = [];

    for _ in range(num_threads):
        t = threading.Thread(target=worker, args=(host, q, open_ports));
        t.daemon = True
        t.start()
        threads.append(t)
# Wait for the queue to be empty
    q.join();
    
    # Wait for all threads to finish
    if open_ports:
        open_ports.sort()
        print(f"\nOpen ports on {host}: {open_ports}")
    else:
        print(f"\nNo open ports found on {host} in the range {start_port}-{end_port}.")
        
    return open_ports;

if __name__ == "__main__":
    # simple cli input
    target = input("Enter target host (IP or domain): ").strip()
    start = int(input("Enter start port (e.g., 1): "))
    end = int(input("Enter end port (e.g., 1024): "))
    threads = int(input("Enter number of threads (e.g., 100): "))
    
    threaded_scan(target, start, end, threads)
    