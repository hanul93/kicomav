<img src="https://raw.githubusercontent.com/hanul93/kicomav-db/master/logo/k2_full_2.png">

# KicomAV v0.40

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-windows-lightgrey.svg)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)
![Platform](https://img.shields.io/badge/platform-mac-lightgrey.svg)<br>
![Language](https://img.shields.io/badge/Python-V3.10+-brightgreen)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/kicomav?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=PyPI%20downloads)](https://pepy.tech/projects/kicomav)

KicomAV is an open source antivirus engine designed for detecting malware and disinfecting it. This antivirus engine is created and maintained by [Kei Choi](http://www.hanul93.com).

## Requirements

- Python 3.10+
- [rich](https://github.com/Textualize/rich) - Terminal formatting
- [requests](https://github.com/psf/requests) - HTTP library
- [python-dotenv](https://github.com/theskumar/python-dotenv) - Environment variables
- [yara-python](https://github.com/VirusTotal/yara-python) - YARA rules engine
- [py7zr](https://github.com/miurahr/py7zr) - 7z archive support
- [rarfile](https://github.com/markokr/rarfile) - RAR archive support
- [pycabfile](https://github.com/hanul93/pycabfile) - CAB archive support

**Optional dependencies:**
- [pylzma](https://github.com/fancycode/pylzma) - LZMA compression (for NSIS)

## Quick start

### Installation via pip (Recommended)

```bash
pip install kicomav
```

### Installation from source

```bash
git clone https://github.com/hanul93/kicomav.git
cd kicomav
pip install -e .
```

## Configuration

KicomAV uses environment variables for configuration. Create a `.env` file in your home directory:

**Windows:**
```
mkdir %USERPROFILE%\.kicomav
copy .env.example %USERPROFILE%\.kicomav\.env
```

**Linux/macOS:**
```bash
mkdir -p ~/.kicomav
cp .env.example ~/.kicomav/.env
```

Then edit `~/.kicomav/.env` to configure:

| Variable | Description | Example                                                 |
|----------|-------------|---------------------------------------------------------|
| `UNRAR_TOOL` | Path to UnRAR executable | `/usr/bin/unrar` or `C:\Program Files\WinRAR\UnRAR.exe` |
| `RAR_TOOL` | Path to RAR executable | `/usr/bin/rar` or `C:\Program Files\WinRAR\Rar.exe`                 |
| `SYSTEM_RULES_BASE` | System rules path | `/var/lib/kicomav/rules` or `C:\kicomav\rules`                                |
| `USER_RULES_BASE` | User rules path | `/home/user/kicomav_rules` or `C:\kicomav\user_rules`                                               |

> **Note:** You can also place a `.env` file in the current working directory for project-specific settings (takes priority over global settings).

## Usage

```
$ k2 path[s] [options]
```

**Example 1:** Show help options

```
$ k2 --help
------------------------------------------------------------
KICOM Anti-Virus II (for WIN32) Ver 0.40 (Dec 31 2025)
Copyright (C) 1995-2025 Kei Choi. All rights reserved.
------------------------------------------------------------

Usage: k2.py path[s] [options]
Options:
        -f,  --files           scan files *
        -r,  --arc             scan archives
        -G,  --log=file        create log file
        -I,  --list            display all files
        -e,  --app             append to log file
        -F,  --infp=path       set infected quarantine folder
        -R,  --nor             do not recurse into folders
        -V,  --vlist           display virus list
        -p,  --prompt          prompt for action
        -d,  --dis             disinfect files
        -l,  --del             delete infected files
             --no-color        don't print with color
             --move            move infected files in quarantine folder
             --copy            copy infected files in quarantine folder
             --qname           quarantine by name of malware
             --qhash           quarantine by sha256 hash of malware
             --password=PWD    set password for encrypted archives
             --parallel        enable parallel file scanning
             --workers=N       number of worker threads (default: CPU count)
             --update          update
        -?,  --help            this help
                               * = default option
```

**Example 2:** Update malware signatures

```
$ k2 --update
------------------------------------------------------------
KICOM Anti-Virus II (for WIN32) Ver 0.40 (Dec 31 2025)
Copyright (C) 1995-2025 Kei Choi. All rights reserved.
------------------------------------------------------------

whitelist.txt  update
yara/reversinglabs-yara-rules-develop.zip  update

[Signature updates complete]
```

**Example 3:** Scan current directory

```
$ k2 . -I
------------------------------------------------------------
KICOM Anti-Virus II (for WIN32) Ver 0.40 (Dec 31 2025)
Copyright (C) 1995-2025 Kei Choi. All rights reserved.
------------------------------------------------------------
Last updated Tue Dec 30 06:49:08 2025 UTC
Signature number: 1,266

C:\kicomav\eicar.txt  infected : EICAR-Test-File (not a virus)

Results:
Folders           :0
Files             :1
Packed            :0
Infected files    :1
Suspect files     :0
Warnings          :0
Identified viruses:1
I/O errors        :0
```

**Example 4:** Scan directory recursively (including archives)

```
$ k2 /path/to/scan -r -I
```

## Library Usage

KicomAV can also be used as a Python library in your own projects.

### Installation

```bash
pip install kicomav
```

### Basic Scanning

```python
import kicomav

# Scan a single file
with kicomav.Scanner() as scanner:
    result = scanner.scan_file("/path/to/suspicious_file.exe")
    if result.infected:
        print(f"Malware detected: {result.malware_name}")
    else:
        print("File is clean")
```

### Directory Scanning

```python
import kicomav

# Scan an entire directory
with kicomav.Scanner() as scanner:
    results = scanner.scan_directory("/path/to/folder", recursive=True)

    infected_files = [r for r in results if r.infected]
    print(f"Scanned {len(results)} files, found {len(infected_files)} infected")

    for result in infected_files:
        print(f"  {result.path}: {result.malware_name}")
```

### Updating Signatures

```python
import kicomav

# Update malware signatures
result = kicomav.update()

if result.package_update_available:
    print(f"New version available: {result.latest_version}")
    print("Run: pip install --upgrade kicomav")

if result.updated_files:
    print(f"Updated {len(result.updated_files)} signature files")
```

### Configuration Access

```python
import kicomav

# Access current configuration
config = kicomav.get_config()
print(f"System rules path: {config.system_rules_base}")
print(f"User rules path: {config.user_rules_base}")
print(f"Rules paths dict: {config.rules_paths}")
```

### Configuration Warnings

When you `import kicomav` without proper configuration, warning messages will be displayed:

```
[KicomAV Warning] .env file not found: /home/user/.kicomav/.env
[KicomAV Warning]   Create it with: mkdir -p /home/user/.kicomav && touch /home/user/.kicomav/.env
[KicomAV Warning] No rules paths configured (SYSTEM_RULES_BASE, USER_RULES_BASE)
[KicomAV Warning]   Signature updates and YARA scanning will not work.
[KicomAV Warning]   Set SYSTEM_RULES_BASE in your .env file.
[KicomAV Warning] To suppress these warnings, set KICOMAV_SUPPRESS_WARNINGS=1
```

**Suppress warnings via environment variable:**

```bash
export KICOMAV_SUPPRESS_WARNINGS=1
```

**Suppress warnings in code:**

```python
from kicomav.kavcore.config import suppress_warnings
suppress_warnings(True)

import kicomav  # No warnings will be shown
```

### Advanced: Direct Engine Access

```python
import kicomav

# For advanced use cases, access the engine directly
engine = kicomav.Engine(verbose=True)
engine.set_plugins("/path/to/plugins")

instance = engine.create_instance()
instance.init()

# Get engine information
info = instance.getinfo()
for plugin_info in info:
    print(f"Plugin: {plugin_info.get('title')}")

# Scan a single file
def on_detect(result, filename, malware_name, malware_id):
    print(f"Detected: {malware_name} in {filename}")

instance.scan("/path/to/file.exe", on_detect)

instance.uninit()
```

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Kei Choi**

- [http://www.hanul93.com](http://www.hanul93.com)
- [http://twitter.com/hanul93](http://twitter.com/hanul93)
- [http://facebook.com/hanul93](http://facebook.com/hanul93)
- [http://github.com/hanul93](http://github.com/hanul93)

