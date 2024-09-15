"""GUI module for the Port Scanner application."""

import tkinter as tk
from tkinter import ttk, scrolledtext
from concurrent import futures
from typing import List, Optional
import queue
import logging

from scanner import port_scanner
from file_operations import save_results, load_custom_ports
from utils import get_common_ports, COMMON_PORTS

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PortScannerGUI:
    """Main GUI class for the Port Scanner application."""

    def __init__(self, master: tk.Tk) -> None:
        """Initialize the PortScannerGUI.

        Args:
            master: The root Tkinter window.
        """
        self.master = master
        self.master.title("Port Scanner")
        self.master.geometry("500x700")
        self.custom_ports: Optional[List[int]] = None
        self.message_queue = queue.Queue()
        self.create_widgets()
        self.master.after(100, self.process_queue)
        logger.info("GUI initialized")

    def create_widgets(self) -> None:
        """Create and arrange the GUI widgets."""
        self.host_entry = self._create_input("Host:", 0)
        self.start_port_entry = self._create_input("Start Port:", 1)
        self.end_port_entry = self._create_input("End Port:", 2)

        self.quick_scan_var = tk.BooleanVar()
        self.quick_scan_checkbox = ttk.Checkbutton(
            self.master,
            text="Quick Scan (Common Ports)",
            variable=self.quick_scan_var,
            command=self._toggle_port_entries
        )
        self.quick_scan_checkbox.grid(row=3, column=0, columnspan=2, pady=5)

        self.scan_button = ttk.Button(self.master, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=4, column=0, columnspan=2, pady=10)

        self.load_ports_button = ttk.Button(
            self.master, text="Load Custom Ports", command=self.load_custom_ports
        )
        self.load_ports_button.grid(row=5, column=0, columnspan=2, pady=10)

        self.results_area = scrolledtext.ScrolledText(
            self.master, wrap=tk.WORD, width=40, height=20
        )
        self.results_area.grid(row=6, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")

        self.status_var = tk.StringVar(value="Ready to scan")
        self.status_label = ttk.Label(self.master, textvariable=self.status_var)
        self.status_label.grid(row=7, column=0, columnspan=2, pady=5)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.master, variable=self.progress_var, maximum=100
        )
        self.progress_bar.grid(row=8, column=0, columnspan=2, sticky="ew", padx=5, pady=5)

        self.save_button = ttk.Button(
            self.master, text="Save Results", command=self.save_results
        )
        self.save_button.grid(row=9, column=0, columnspan=2, pady=10)
        self.save_button.config(state="disabled")

        self.master.columnconfigure(1, weight=1)
        self.master.rowconfigure(6, weight=1)

    def _create_input(self, label: str, row: int) -> ttk.Entry:
        """Create a labeled input field."""
        ttk.Label(self.master, text=label).grid(row=row, column=0, sticky="w", padx=5, pady=5)
        entry = ttk.Entry(self.master)
        entry.grid(row=row, column=1, sticky="ew", padx=5, pady=5)
        return entry

    def _toggle_port_entries(self) -> None:
        """Enable or disable port entry fields based on quick scan checkbox."""
        state = "disabled" if self.quick_scan_var.get() else "normal"
        self.start_port_entry.config(state=state)
        self.end_port_entry.config(state=state)

    def start_scan(self) -> None:
        """Initiate the port scanning process."""
        logger.info("Starting scan process")
        self.results_area.delete("1.0", tk.END)
        self.scan_button.config(state="disabled")
        self.save_button.config(state="disabled")
        self.progress_var.set(0)
        self.status_var.set("Starting scan...")

        host = self.host_entry.get()
        if not host:
            self._show_error("Please enter a host to scan.")
            return

        logger.debug(f"Host to scan: {host}")

        if self.quick_scan_var.get():
            ports = get_common_ports(COMMON_PORTS)
            logger.debug("Using quick scan (common ports)")
        elif self.custom_ports:
            ports = self.custom_ports
            logger.debug("Using custom ports")
        else:
            try:
                start_port = int(self.start_port_entry.get())
                end_port = int(self.end_port_entry.get())
                if start_port > end_port:
                    raise ValueError("Start port must be less than or equal to end port.")
                ports = list(range(start_port, end_port + 1))
                logger.debug(f"Scanning port range: {start_port} to {end_port}")
            except ValueError as e:
                self._show_error(f"Invalid port numbers: {str(e)}")
                return

        total_ports = len(ports)
        logger.info(f"Total ports to scan: {total_ports}")
        self._run_scan(port_scanner, host, ports, total_ports)

    def _run_scan(self, scanner_func, *args) -> None:
        """Run the port scanner in a separate thread."""
        logger.debug("Starting scan in a separate thread")
        self.results_area.insert(tk.END, "Starting scan...\n")
        futures.ThreadPoolExecutor(max_workers=1).submit(
            scanner_func, *args[:-1], self.queue_update, args[-1]
        )
    def queue_update(self, message: str) -> None:
        """Queue a GUI update message."""
        logger.debug(f"Queueing message: {message}")
        self.message_queue.put(message)

    def process_queue(self) -> None:
        """Process queued GUI update messages."""
        try:
            while True:
                message = self.message_queue.get_nowait()
                self._update_gui(message)
        except queue.Empty:
            pass
        finally:
            self.master.after(100, self.process_queue)

    def load_custom_ports(self) -> None:
        """Load custom ports from a file."""
        self.custom_ports = load_custom_ports()
        if self.custom_ports:
            self.queue_update(f"Loaded {len(self.custom_ports)} custom ports")
            self.start_port_entry.config(state="disabled")
            self.end_port_entry.config(state="disabled")
            self.quick_scan_checkbox.config(state="disabled")
        else:
            self._show_error("No ports loaded or invalid file format.")

    def save_results(self) -> None:
        """Save the scan results to a file."""
        results = self.results_area.get("1.0", tk.END).strip()
        message = save_results(results)
        self.queue_update(message)

    def _update_gui(self, message: str) -> None:
        """Update the GUI with scan progress and results."""
        logger.debug(f"Processing GUI update: {message}")
        if message.startswith("PROGRESS:"):
            progress = float(message.split(":")[1])
            self.progress_var.set(progress)
            logger.debug(f"Progress updated: {progress}%")
        elif message.startswith("STATUS:"):
            status = message.split(":")[1]
            self.status_var.set(status)
            logger.debug(f"Status updated: {status}")
        elif message.startswith("OPEN_PORT:"):
            port = message.split(":")[1]
            service = COMMON_PORTS.get(port, "Unknown")
            self.results_area.insert(tk.END, f"Open port found: {port} ({service})\n")
            self.results_area.see(tk.END)
            logger.info(f"Open port found: {port} ({service})")
        else:
            self.results_area.insert(tk.END, message + "\n")
            self.results_area.see(tk.END)
            logger.debug(f"Other message: {message}")
        
        if message == "Scan completed":
            logger.info("Scan completed")
            self.scan_button.config(state="normal")
            self.save_button.config(state="normal")
            self.progress_var.set(100)
            self.status_var.set("Scan completed")

        self.master.update_idletasks()

    def _show_error(self, message: str) -> None:
        """Display an error message in the results area."""
        logger.error(f"Error: {message}")
        self.results_area.insert(tk.END, f"Error: {message}\n")
        self.status_var.set("Error occurred")
        self.scan_button.config(state="normal")
        self.save_button.config(state="disabled")