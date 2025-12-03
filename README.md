# 🛡️ Multithreaded TCP Port Scanner  
A fast, lightweight, and extensible **Python-based port scanner** with multithreading, service detection, JSON reporting, and flexible port input.

---

## 🚀 Features

- **⚡ Multithreaded scanning** (100+ threads for high speed)  
- **🔎 Service detection** using custom mapping + system lookups  
- **📄 JSON export** for automation, scripting, or reporting  
- **🎯 Flexible port input**  
  - Single ports: `80`  
  - Lists: `22,80,443`  
  - Ranges: `1-1024`  
  - Mixed: `1-1024,3306,5432`  
- **🧵 Thread-safe output**  
- **🔧 Command-line interface (argparse)**  
- **🖥️ Designed for security learning, home labs, and tooling portfolios**  

---

## 📦 Installation

### Clone the repository

```bash
git clone https://github.com/<your-username>/<your-repo-name>.git
cd <your-repo-name>
```
---
## Requirements

Python 3.8+
No external libraries required — only the Python Standard Library.

---

### 🏃 Usage

```
python port_scanner.py -H <target-ip> -p <ports> -t <threads>
```


⚠️ Legal Disclaimer

This tool is intended for educational use and authorized security testing only.
Do NOT use it to scan networks or hosts without explicit permission.
The author assumes no liability for misuse.
