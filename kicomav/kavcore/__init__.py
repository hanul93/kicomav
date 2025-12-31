# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
KicomAV Core Module

This module provides the core functionality for KicomAV antivirus engine.
"""

# Configuration management
from .config import Config, get_config, init, reload_config

# Update functionality
from .updater import (
    UpdateResult,
    check_package_update,
    get_installed_version,
    get_last_update_time,
    get_latest_version,
    get_update_timestamp,
    update,
    update_signatures,
)

# Engine classes
from .k2engine import Engine, EngineInstance

# Scanner (high-level API)
from .scanner import ScanResult, Scanner

# Core modules
from . import k2const, k2file, k2security, k2timelib

__all__ = [
    # Configuration
    "Config",
    "get_config",
    "init",
    "reload_config",
    # Update
    "UpdateResult",
    "update",
    "update_signatures",
    "check_package_update",
    "get_installed_version",
    "get_latest_version",
    "get_update_timestamp",
    "get_last_update_time",
    # Engine
    "Engine",
    "EngineInstance",
    # Scanner
    "Scanner",
    "ScanResult",
    # Core modules
    "k2const",
    "k2file",
    "k2security",
    "k2timelib",
]
