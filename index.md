---
layout: default
---

# About KicomAV

***


KicomAV is an open source (MIT License) antivirus engine designed for detecting malware and disinfecting it. In fact, Since 1995, it has been written in C/C++ and it was integrated into the ViRobot engine of [HAURI](http://www.hauri.co.kr), 1998. I decided to re-create a new KicomAV. So, this is developed in Python. Anyone can participate in the development easily.

<style>.embed-container { position: relative; padding-bottom: 56.25%; height: 0; overflow: hidden; max-width: 100%; } .embed-container iframe, .embed-container object, .embed-container embed { position: absolute; top: 0; left: 0; width: 100%; height: 100%; }</style><div class='embed-container'><iframe src='https://www.youtube.com/embed/32M6QKboCGM' frameborder='0' allowfullscreen></iframe></div>

## 1. How to use

***

### Requirements

* Python 3.10+
* [yara-python](https://github.com/VirusTotal/yara-python) (optional)


### Quick start

* Install via PyPI:
    ```
    pip install kicomav
    ```

* Or clone the repo:
    ```
    git clone git://github.com/hanul93/kicomav.git
    cd kicomav
    pip install -e .
    ```

* Run KicomAV:
    ```
    k2 <scan_path>
    ```

* Update signatures:
    ```
    k2 --update
    ```

## 2. Features

***

* **Multi-format scanning**: Files, archives (ZIP, RAR, 7z, CAB, ALZ, EGG, APK, OneNote), and nested containers
* **YARA integration**: Custom YARA rules support for advanced threat detection
* **Intelligent caching**: Dual-cache system with scan mode awareness for consistent, fast rescans
* **Exclusion rules**: Flexible file/directory exclusion with glob patterns
* **Parallel scanning**: Multi-threaded scanning for improved performance
* **Daemon mode**: REST API and clamd-compatible socket protocol
* **Cross-platform**: Windows, Linux, macOS support
* **Library API**: Use as a Python library in your projects
* **PyInstaller support**: Scan PyInstaller executables (Windows PE and Linux ELF)

## 3. Components

***

KicomAV provides three command-line tools:

| Tool | Description |
|------|-------------|
| **k2** | Main scanner - scan files and directories for malware |
| **k2d** | Daemon server - REST API and socket protocol service |
| **k2c** | Client - communicate with k2d daemon |

* **Standalone scanning**: Use `k2` directly for local file scanning
* **Client-server mode**: Run `k2d` as a service, use `k2c` to send scan requests

## 4. Daemon Mode (k2d & k2c)

***

KicomAV can run as a daemon server, providing both REST API (port 8311) and clamd-compatible socket protocol (port 3311).

### Server (k2d)

```bash
# Start daemon server
k2d

# Start with API key authentication
k2d --generate-key
```

### Client (k2c)

```bash
# Check server status
k2c --ping

# Scan a file
k2c /path/to/file

# Scan from stdin
k2c --stream < suspicious.exe
```

### REST API Example

```bash
# Health check
curl http://127.0.0.1:8311/ping

# Scan a file
curl -X POST -F "file=@suspicious.exe" http://127.0.0.1:8311/scan/file
```

## 5. Releases

***

## v0.41 (Jan 23, 2026)

* **Engine :**
  * Added dual-cache system for improved scan consistency
    * `scan_cache` for regular file scanning
    * `archive_cache` for archive-specific caching with `opt_arc` separation
  * Added k2security module for security validation
  * Fixed resource cleanup in k2engine

* **Plugins Modules :**
  * apk: Added APK archive support
  * onenote: Added Microsoft OneNote file format support
  * elf: Added ELF-based PyInstaller support
  * nsis: Fixed resource cleanup and improved error messages for unknown formats
  * script: Fixed infinite loop when scanning malformed BAT files
  * pe: Fixed resource cleanup for PE files
  * tar/zip: Fixed resource cleanup

* **Security :**
  * Added input validation for archive extraction
  * Added path traversal protection
  * Added resource limit controls

* **Daemon Mode (k2d & k2c) :**
  * k2d: Added daemon server with REST API (port 8311) and clamd-compatible socket protocol (port 3311)
  * k2d: Added API key authentication support
  * k2d: Added concurrent scan request handling with worker pool
  * k2c: Added command-line client for k2d daemon
  * k2c: Added file/directory scanning via HTTP and socket protocols
  * k2c: Added stream scanning from stdin

* **Documentation :**
  * Added Components section introducing k2, k2c, k2d tools
  * Added Scan Cache section with Cache Architecture and Performance Impact
  * Added Archive Exploration API documentation with `list_archive`, `extract_archive`, `read_archive` examples
  * Updated README.md structure for better readability

## v0.40 (Dec 30, 2025)

* **Engine :**
  * Added high-level Scanner API for easy file and directory scanning
  * Added parallel scanning support with configurable worker threads (--parallel, --workers)
  * Implemented worker pool for optimized performance
  * Batched file discovery for faster scanning start
  * Optimized worker initialization overhead
  * Fixed py7zr API compatibility after version upgrade

* **Configuration :**
  * Changed .env file location to ~/.kicomav/.env
  * Added warning messages when .env is not configured
  * Added KICOMAV_SUPPRESS_WARNINGS option

* **Update System :**
  * Added update.cfg timestamp parsing for "Last updated" display
  * Added __last_update__ fallback when update.cfg is not available
  * Fixed update.cfg deletion issue after signature updates

* **Package :**
  * Changed license from GPL v2 to MIT
  * Added PyPI support (pip install kicomav)
  * Added `k2` command-line entry point
  * Renamed Engine folder to kicomav for proper package structure
  * Requires Python 3.10+

## v0.33c (Sep 26, 2022)

* **Engine :**
  * k2engine: Fixed python source code import error
  * k2io: Removed six module

## v0.33b (Sep 24, 2022)

* **Engine :**
  * Project ported from Python 2 to Python 3

## v0.33 (Mar 17, 2020)

* **Engine :**
  * k2engine: Fixed a bug(#16) that failed to scan folders containing bracket characters ('[]')

* **Plugins Modules :**
  * 7z: Added recompression
  * alz: Added recompression
  * bat: New support
  * bz: Added recompression
  * egg: Added recompression
  * elf: Added parse Program Headers of Elf 64bit files (#12)
  * gz: Added recompression
  * lnk: New support
  * macro: Fixed decompress of module of vba
  * tar: Added recompression
  * xz: Added recompression

* **Command Line Interface :**
  * k2: Fixed KicomAV update flow (#10)

## v0.32 (Aug 1, 2019)

* **Engine :**
  * k2engine: Removed dependence on psutil
  * k2engine: Fixed recompression logic after disinfection of malwares in compress file

* **Plugins Modules :**
  * attach: Added disinfection of attached malwares
  * dummy: Fixed file open in dummy engine
  * nsis: Modified NSIS engine's info
  * ole: Fixed OleWriteStream (SBD -> SBD (Inc))
  * ole: Fixed delete of OLE's directory
  * rtf: Added make archive of rtf
  * ve: Added disinfect function for VE
  * zlib: Added make archive of zlib

* **Command Line Interface :**
  * k2: Added new options (--qhash)

## v0.31 (Jun 18, 2018)

* **Plugins Modules :**
  * cab: Improved speed for cab file extract
  * dde: Added a CVE-2017-0199 pattern
  * egg: Fixed the problem that file name inside egg file is broken
  * emalware: Added a Worm.Win32.Allaple.gen pattern
  * html: Added scan function for Trojan.HTML.IFrame.a
  * ishield: New support
  * macro: Fixed parse of dir_referencesrecord
  * ole: Added extraction of Ole's attach data
  * olenative: Fixed a _OleNative Stream name
  * pe: Fixed missing import API names
  * pe: Fixed check to resource size
  * rar: New support
  * ve: Added New scan areas
  * ve: Fixed crc32 of base offset
  * yaraex: Fixed detect yara rule name
  * yaraex: Fixed malware detection against yaraex.yar
  * zip: Added 7z archive

* **Command Line Interface :**
  * k2: Added New status (IDENTIFIED)
  * k2: Added New options (--copy, --qname)
  * k2: Fixed file name assembly

### v0.30 (Mar 07, 2018)

* **Engine :**
  * k2engine: Changed WindowsError exception handling to OSError exception handling
  * k2engine: Modified Checking for malicious code to stop immediately via Ctrl+C
  * k2file: Changed WindowsError exception handling to OSError exception handling
  * k2file: Moved the path of the temporary folder

* **Plugins Modules :**
  * adware: Modified the data processing byte number in the ASN.1 parser
  * cryptolib: Supported crc32
  * dde: Changed malware pattern
  * hwp: Added Exploit.JS.Agent.gen check function
  * kavutil: Added malicious code pattern handling function of virus type
  * kavutil: Fixed the error handling part of malicious code pattern number
  * macro: Supported 32/64bit
  * nsis: Improved decompression speed
  * ole: Added CVE-2012-0158 pattern
  * ole: Fixed infinite loop error during parsing
  * pe: Supported 32/64bit
  * pe: Added error handling for invalid resource size
  * rtf: Added objdata extraction function
  * rtf: Changed malicious code patterns
  * upx: Fixed infinite loop error
  * ve: New support (scan for malware of virus types)

* **Command Line Interface :**
  * k2: Added color mode in Linux/Mac
  * k2: Fixed an error when updating k2.exe from a folder where k2.exe does not exist (# 1455)
  * k2: Fixed do not download k2.exe on platforms other than windows

### v0.29 (Jan 08, 2018)

* **Engine :**
  * k2engine: Handling the callback function call if the plugin module fails to load
  * k2engine: Processing to render the result of recompression in detail after malicious code in the compressed file is processed
  * k2engine: Fixed the problem that the extension can not be removed properly if the kmd file path name has a period (.)
  * k2engine: Fixed an infinite loop problem in case of malfunction code failure
  * k2engine: Process temporary folders by process
  * k2file: Add a class to process temporary folders by process

* **Plugins Modules :**
  * adware: new support
  * attach: process to add size information of an attached image to newly extract an attached image
  * bz: New support
  * carch: New support
  * dde: New support
  * egg: new support
  * elf: verbose processing on ELF 64bit
  * emalware: Handle MD5 calculations if section size is 0
  * emalware: Handle malicious code in addition to .text area
  * gz: New support
  * kavutil: MD5 pattern is compressed so that it is decompressed and then loaded
  * ole: Added malicious code remedy to infected ole file
  * ole: Correct the processing for bad access and the PPS length to be 0x40 max.
  * ole: Eliminate unnecessary logic
  * ole: Exploit.OLE.CVE-2003-0347 Add inspection logic
  * ole: Opening ole file in write mode to handle failure to delete stream
  * olenative: Added malicious code remediation to Ole10Native files
  * pdf: Add malware PDF signature test signature
  * pdf: Added Trojan.PDF.Generic inspection logic
  * pdf: Improved inspection speed by avoiding unnecessary stream extraction
  * pe: Do not calculate MD5 if section size is 0
  * pe: Error handling to divide by 0 in converting RAV to Offset
  * pe: If there is a digital signature, the position and size of the attached image are newly processed
  * pe: Processing parsing failure if there is not enough data in the .rsrc area
  * pyz: Added pyc type malicious code
  * pyz: Improved error by checking TOC type
  * pyz: New support
  * tar: New support
  * unpack: Exceptions when zlib is not a compressed object
  * unpack: Process zlib and embed_ole simultaneously to recognize format
  * unpack: add infected malicious code remedy to embed ole file
  * upx: Add exception handling for uncompressed sizes
  * upx: Fixed an issue where execution compression was not released
  * xz: New support
  * yaraex: Engine initialization failure processing when there is no yara module

* **Command Line Interface :**
  * k2: engine initialization failure processing when there is no yara module
  * k2: Processing to prevent the same malicious code inspection result from being output
  * k2: Easily recognizable by adding a comma (,) to the number of malicious code patterns loaded
  * k2: Outputs error message after processing residual printout when nonexistent Paht check
  * k2: Output the plug-in module that failed to load as an error message
  * k2: Processing to render the result of recompression in detail after malicious code in the compressed file is processed
  * k2: Processing to prevent redundant output when expressing the result of re-compression in detail
  * k2: Change the update file to a gz file and process the update itself
  * k2: Change update path
    * Related Issue: https://github.com/hanul93/kicomav/issues/4
  * k2: Fixed error when scrolling while printing Windows 10 legacy console
    * Related Issue: https://github.com/hanul93/kicomav/issues/7

* **Tools :**
  * sigtool_md5: Reduce capacity by compressing MD5 pattern
  * sigtool_md5: Prevent duplicate malware name generation
  * sigtool_yar: New support

### v0.28 (Sep 4, 2017)

* Improved decompression speed of compressed files
* Added resource parsing function for PE file
* Added malware scanning function using YARA rule
* Fixed product hang when extracting ZIP files with errors
* Fixed errors when scanning ZIP and HWP files with passwords

### v0.27b (May 22, 2017)

* Fixed for pylzma import error

### v0.27a (May 17, 2017)

* Enabled update option (--update)

### v0.27 (May 4, 2017)

* Redesigned an architecture of KicomAV

### v0.26 (June 16, 2016)

* Added support for decompressed BinData/BIN0001.OLE in HWP File
* Added support for decompressed OleNative in OLE File
* Added support for scanning the malware for APK(Android) files

### v0.25 (July 18, 2013)

* Added support for decompressed UPX file
* Added support for separated the attached files from PE file
* Added support for scannning the malware for Common Object File Format (COFF)

### v0.24 (July 7, 2013)

* Added support for decompressed ALZ file
* Added support for decompressed EGG file
* Added support for scanning the malware for MSWord and MSExcel files

### v0.23 (June 27, 2013)

* Added support for scanning the malware for PE file
* Added support for multi scan paths
* Added display for the signature number and the last update information
* BUGFIX : infinite loop in OLE PPS Dump

### v0.22 (June 16, 2013)

* Added support for decompressed OLE file
* Added support for scanning the exploit code for Hangul Word Processor (HWP) file

### v0.21 (June 11, 2013)

* Added support for command option for archive files
* Added support for decompressed ZIP file

### v0.20b (June 1, 2013)

* Added support for command line : k2.py

### v0.20 (May 27, 2013)

* Redesigned Plug-in architectures

### v0.10 (May 8, 2013)

* Initial release


## 6. Supporters

***

![](/images/support.png)
