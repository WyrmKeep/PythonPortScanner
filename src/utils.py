import json
from pathlib import Path
from typing import Dict, List, Optional

# Constants
COMMON_PORTS_FILENAME = 'common_ports.json'
DEFAULT_COMMON_PORTS = {
    "80": "HTTP",
    "443": "HTTPS",
    "22": "SSH",
    "21": "FTP",
    "25": "SMTP"
}

def identify_service(port: int, common_ports: Dict[str, str]) -> str:
    """Identify common services based on port number."""
    return common_ports.get(str(port), "Unknown")

def get_common_ports(common_ports: Dict[str, str]) -> List[int]:
    """Get a list of common ports for quick scan."""
    return [int(port) for port in common_ports.keys()]

def load_common_ports() -> Dict[str, str]:
    """Load common ports from JSON file."""
    file_path = find_common_ports_file()
    if file_path:
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"Error decoding JSON from {file_path}")
    else:
        print(f"Warning: {COMMON_PORTS_FILENAME} not found. Using default ports.")
    
    return DEFAULT_COMMON_PORTS

def find_common_ports_file() -> Optional[Path]:
    """Find the common_ports.json file in possible locations."""
    possible_locations = [
        Path(__file__).parent.parent / 'data' / COMMON_PORTS_FILENAME,
        Path(__file__).parent / 'data' / COMMON_PORTS_FILENAME,
        Path.cwd() / 'data' / COMMON_PORTS_FILENAME,
        Path.cwd().parent / 'data' / COMMON_PORTS_FILENAME
    ]

    for file_path in possible_locations:
        if file_path.exists():
            return file_path

    return None

# Load common ports once at module level
COMMON_PORTS = load_common_ports()