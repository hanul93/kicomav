# -*- coding:utf-8 -*-
# KICOM Anti-Virus II Engine
# Author: Kei Choi (hanul93@gmail.com)

"""
KicomAV - Open Source Antivirus Engine

A modular, extensible antivirus engine for malware detection and analysis.

Basic Usage:
    import kicomav

    # Simple file scan
    with kicomav.Scanner() as scanner:
        result = scanner.scan_file("/path/to/file.exe")
        if result.infected:
            print(f"Detected: {result.malware_name}")

    # Directory scan
    with kicomav.Scanner() as scanner:
        results = scanner.scan_directory("/path/to/folder")
        for result in results:
            if result.infected:
                print(f"{result.path}: {result.malware_name}")

    # Update signatures
    result = kicomav.update()
    if result.package_update_available:
        print(f"New version available: {result.latest_version}")

Advanced Usage:
    import kicomav

    # Direct engine access
    engine = kicomav.Engine()
    engine.set_plugins("/path/to/plugins")
    instance = engine.create_instance()
    instance.init()
    # ... perform scans ...
    instance.uninit()

    # Configuration access
    config = kicomav.get_config()
    print(config.rules_paths)
"""

__version__ = "0.40"
__author__ = "Kei Choi"
__last_update__ = "Wed Dec 31 03:50:27 2025 UTC"

# Import from kavcore for public API
from kicomav.kavcore import (
    # Configuration
    Config,
    get_config,
    # Update
    UpdateResult,
    check_package_update,
    update,
    update_signatures,
    # Engine
    Engine,
    EngineInstance,
    # Scanner (high-level API)
    ScanResult,
    Scanner,
    # Core modules
    k2const,
)

__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__last_update__",
    # Configuration
    "Config",
    "get_config",
    # Update
    "UpdateResult",
    "update",
    "update_signatures",
    "check_package_update",
    # Engine
    "Engine",
    "EngineInstance",
    # Scanner (recommended high-level API)
    "Scanner",
    "ScanResult",
    # Core modules
    "k2const",
]
