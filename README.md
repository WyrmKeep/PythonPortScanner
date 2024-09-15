# 🔍 Python Port Scanner with GUI

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Unspecified-red)](LICENSE)

A powerful, user-friendly port scanning tool built with Python and tkinter. Scan networks, identify open ports, and enhance your cybersecurity toolkit with this versatile application.

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Getting Started](#-getting-started)
- [Usage](#-usage)
- [Configuration](#-configuration)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)
- [Support](#-support)

## ✨ Features

- 🖥️ Intuitive graphical user interface (GUI) built with tkinter
- 🚀 Fast, multithreaded port scanning for efficient network analysis
- 🎯 Flexible scanning options:
  - Custom port range scanning
  - Quick scan for common ports
  - Load and scan custom port lists
- 📊 Real-time progress updates with a visual progress bar
- 💾 Save scan results in JSON format for further analysis
- 🔍 Automatic identification of common services based on port numbers
- 🛡️ Enhance your network security and penetration testing toolkit

## 🚀 Installation

This project requires Python 3.6 or higher. No additional libraries are needed as it uses standard Python libraries.

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/python-port-scanner.git
   cd python-port-scanner
   ```

2. (Optional) Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

## 🏁 Getting Started

To launch the Port Scanner application:

```bash
python main.py
```

You'll be greeted with the GUI interface, ready to start scanning!

## 🔧 Usage

1. 🖥️ Launch the application by running `main.py`.
2. 🌐 Enter the target host IP address or domain name in the "Host" field.
3. 🎛️ Choose your scanning method:
   - Enter a start and end port for a custom range scan.
   - Check the "Quick Scan" box to scan common ports.
   - Use the "Load Custom Ports" button to scan a predefined list of ports.
4. 🚀 Click "Start Scan" to begin the port scanning process.
5. 📊 View real-time results in the scrollable text area.
6. 💾 Use the "Save Results" button to export scan results to a JSON file.

## ⚙️ Configuration

Customize the quick scan feature by modifying the `common_ports.json` file:

1. Create a `data` directory in the project root (if it doesn't exist).
2. Create or edit `data/common_ports.json`:
   ```json
   {
     "80": "HTTP",
     "443": "HTTPS",
     "22": "SSH",
     "21": "FTP",
     "25": "SMTP"
   }
   ```
3. Add or remove port numbers and their corresponding service names as needed.

## 🛠️ Troubleshooting

- **Scan not starting**: Ensure you've entered a valid host and port range.
- **Slow scan performance**: Try reducing the port range or using the quick scan option.
- **Missing common_ports.json**: The app will use default ports. Create the file as described in the Configuration section.
