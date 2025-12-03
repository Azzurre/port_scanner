import socket;
from datetime import datetime;

def scan_ports(host: str, port: int, timeout: float = 0.5) -> bool:
    """
    Try to connect to a single TCP port.
    

    Args:
        host (str): _description_
        port (int): _description_
        timeout (float, optional): _description_. Defaults to 0.5.

    Returns:
        bool: Return True if port is open, False otherwise.
    """
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout);
        try:
            result = s.connect_ex((host, port));
            return result == 0;
            
        except socket.error:
            return False;
        
def scan_range(host: str, start_port: int, end_port: int, timeout: float = 0.5) -> list[int]:
    """
    Scan a range of TCP ports on a given host.

    Args:
        host (str): The target host to scan.
        start_port (int): The starting port number.
        end_port (int): The ending port number.
        timeout (float, optional): Timeout for each port scan. Defaults to 0.5.

    Returns:
        list[int]: A list of open ports.
    """
    
    open_ports = [];
    print(f"Scanning ports {start_port} to {end_port} on host {host}...");
    start_time = datetime.now();
    
    for port in range(start_port, end_port + 1):
        if scan_ports(host, port, timeout):
            open_ports.append(port);
            print(f"Port {port} is open.");
    
    end_time = datetime.now();
    duration = end_time - start_time;
    print(f"Scanning completed in {duration}.");
    
    if open_ports:
        print(f"Open ports: {open_ports}");
    else:
        print("No open ports found.");
    return open_ports;

if __name__ == "__main__":
    # simple cli input
    target = input("Enter target host (IP or domain): ").strip()
    start = int(input("Enter start port (e.g., 1): "))
    end = int(input("Enter end port (e.g., 1024): "))
    
    scan_range(target, start, end)
    