<p align="center">
  <img src="https://raw.githubusercontent.com/Rajesh61344/malscan/main/banner.png" alt="MalScan Banner" width="100%">
</p>
# MalScan

MalScan is a Python-based enterprise malware scanning tool designed for Kali Linux. It helps security professionals and ethical hackers identify suspicious processes, malware indicators, persistence mechanisms, network anomalies, and potential rootkit activity during authorized security assessments.

## Features

- Process Anomaly Detection
- Filesystem Malware Scanning
- Persistence & Cron Analysis
- Network Connection Analysis
- Rootkit Detection
- Detailed Security Report Generation
- Interactive Command-Line Interface (CLI)

## Requirements

- Python 3.9+
- Kali Linux / Ubuntu / Parrot OS
- PHP
- lsof
- iproute2
- ClamAV (Optional but Recommended)

## Installation

```bash
sudo apt update
sudo apt install -y php lsof iproute2 clamav
chmod +x malscan.py
sudo python3 malscan.py
```

## Usage

Run the tool with root privileges:

```bash
sudo python3 malscan.py
```

## Project Structure

```
MalScan/
├── malscan.py
├── README.md
├── LICENSE
```

## Disclaimer

This tool is intended for educational purposes and authorized security assessments only. Do not use it on systems or networks without explicit permission from the owner.

## License

This project is licensed under the MIT License.
