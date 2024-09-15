import socket
import logging
from concurrent import futures
from typing import List, Tuple, Callable
from functools import partial

MAX_WORKERS = 50
DEFAULT_TIMEOUT = 1

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def scan_port(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> Tuple[int, bool]:
    """Scan a single port on the specified host."""
    logger.debug(f"Scanning port {port} on host {host}")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            is_open = result == 0
            logger.debug(f"Port {port} is {'open' if is_open else 'closed'}")
            return port, is_open
    except socket.error as e:
        logger.error(f"Error scanning port {port}: {e}")
        return port, False

def port_scanner(
    host: str,
    ports: List[int],
    callback: Callable[[str], None],
    total_ports: int
) -> None:
    """Scan multiple ports on the specified host."""
    logger.info(f"Starting scan on host {host} for {total_ports} ports")
    open_ports = []
    scan_func = partial(scan_port, host)

    callback("STATUS:Initializing scan...")
    callback(f"PROGRESS:0")

    with futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_port = {executor.submit(scan_func, port): port for port in ports}

        for i, future in enumerate(futures.as_completed(future_to_port), 1):
            try:
                port, is_open = future.result()
                
                if i % 10 == 0 or i == total_ports:
                    progress = i / total_ports * 100
                    logger.debug(f"Progress: {i}/{total_ports} ports scanned ({progress:.2f}%)")
                    callback(f"PROGRESS:{progress:.2f}")
                    callback(f"STATUS:Scanned {i}/{total_ports} ports")

                if is_open:
                    open_ports.append(port)
                    logger.info(f"Open port found: {port}")
                    callback(f"OPEN_PORT:{port}")
            except Exception as e:
                logger.error(f"Error processing result for port {future_to_port[future]}: {e}")

    logger.info("Scan completed")
    callback("STATUS:Scan completed")
    callback("PROGRESS:100")
    _report_results(callback, open_ports)

def _report_results(callback: Callable[[str], None], open_ports: List[int]) -> None:
    """Report the final results of the scan."""
    callback("Scan completed")
    if open_ports:
        logger.info(f"Found {len(open_ports)} open ports")
        callback(f"Found {len(open_ports)} open ports:")
        for port in sorted(open_ports):
            callback(f"  - {port}")
    else:
        logger.info("No open ports found")
        callback("No open ports found.")