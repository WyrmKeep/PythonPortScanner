import json
from tkinter import filedialog
from typing import List, Optional

def save_results(results: str) -> str:
    """
    Save scan results to a JSON file.

    Args:
        results: String containing the scan results.

    Returns:
        A message indicating the result of the save operation.
    """
    file_path = filedialog.asksaveasfilename(
        defaultextension=".json",
        filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
    )
    if not file_path:
        return "Save cancelled"

    try:
        with open(file_path, "w") as f:
            json.dump({"scan_results": results}, f, indent=2)
        return f"Results saved to {file_path}"
    except IOError as e:
        return f"Error saving results: {str(e)}"

def load_custom_ports() -> Optional[List[int]]:
    """
    Load custom port list from a file.

    Returns:
        A sorted list of unique port numbers, or None if loading failed.
    """
    file_path = filedialog.askopenfilename(
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
    )
    if not file_path:
        return None

    try:
        with open(file_path, "r") as f:
            ports = f.read().strip().split()
        return sorted(set(map(int, ports)))
    except ValueError:
        print("Error: File contains non-integer values.")
    except IOError as e:
        print(f"Error reading file: {str(e)}")
    
    return None