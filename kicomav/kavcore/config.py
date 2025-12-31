# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
KicomAV Configuration Module

This module handles configuration management including .env file loading.
Configuration is automatically loaded when the module is imported.
"""

import logging
import os
import sys
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

# Module logger
logger = logging.getLogger(__name__)

# Warning suppression flag (set to True to suppress warnings)
_suppress_warnings = os.environ.get("KICOMAV_SUPPRESS_WARNINGS", "").lower() in ("1", "true", "yes")

# Default paths
DEFAULT_ENV_PATH = Path.home() / ".kicomav" / ".env"
DEFAULT_UPDATE_URL = "https://raw.githubusercontent.com/hanul93/kicomav-db/master/update/"


@dataclass
class Config:
    """KicomAV configuration container.

    Attributes:
        system_rules_base: Path to system rules directory (from SYSTEM_RULES_BASE)
        user_rules_base: Path to user rules directory (from USER_RULES_BASE)
        update_url: URL for signature updates
        env_loaded: Whether .env file was successfully loaded
    """

    system_rules_base: Optional[str] = None
    user_rules_base: Optional[str] = None
    update_url: str = DEFAULT_UPDATE_URL
    env_loaded: bool = False

    @property
    def rules_paths(self) -> Dict[str, Optional[str]]:
        """Get rules paths as a dictionary.

        Returns:
            Dictionary with 'system' and 'user' keys
        """
        return {"system": self.system_rules_base, "user": self.user_rules_base}

    @classmethod
    def from_env(cls, env_path: Optional[Path] = None) -> "Config":
        """Create Config from environment variables.

        Args:
            env_path: Optional path to .env file. If None, uses DEFAULT_ENV_PATH.

        Returns:
            Config instance populated from environment variables
        """
        env_loaded = False

        # Try to load .env file
        if env_path is None:
            env_path = DEFAULT_ENV_PATH

        try:
            from dotenv import load_dotenv

            if env_path.exists():
                load_dotenv(env_path)
                env_loaded = True
                logger.debug("Loaded .env from %s", env_path)
        except ImportError:
            logger.debug("python-dotenv not installed, skipping .env loading")
        except Exception as e:
            logger.warning("Failed to load .env from %s: %s", env_path, e)

        # Read configuration from environment
        system_rules = os.environ.get("SYSTEM_RULES_BASE", "").strip() or None
        user_rules = os.environ.get("USER_RULES_BASE", "").strip() or None
        update_url = os.environ.get("KICOMAV_UPDATE_URL", "").strip() or DEFAULT_UPDATE_URL

        return cls(
            system_rules_base=system_rules,
            user_rules_base=user_rules,
            update_url=update_url,
            env_loaded=env_loaded,
        )


# Global configuration instance
_config: Optional[Config] = None
_warnings_shown = False  # Track if warnings have been shown


def _print_warning(message: str) -> None:
    """Print a warning message to stderr with formatting."""
    if _suppress_warnings:
        return
    # Use ANSI colors if terminal supports it
    if sys.stderr.isatty():
        # Yellow color for warnings
        sys.stderr.write(f"\033[93m[KicomAV Warning]\033[0m {message}\n")
    else:
        sys.stderr.write(f"[KicomAV Warning] {message}\n")


def _show_config_warnings(config: Config, env_path: Path) -> None:
    """Show warnings about missing configuration."""
    global _warnings_shown
    if _suppress_warnings or _warnings_shown:
        return

    _warnings_shown = True
    has_warning = False

    # Check if .env file exists
    if not config.env_loaded:
        if not env_path.exists():
            _print_warning(f".env file not found: {env_path}")
            _print_warning(f"  Create it with: mkdir -p {env_path.parent} && touch {env_path}")
        has_warning = True

    # Check if rules paths are configured
    if not config.system_rules_base and not config.user_rules_base:
        _print_warning("No rules paths configured (SYSTEM_RULES_BASE, USER_RULES_BASE)")
        _print_warning("  Signature updates and YARA scanning will not work.")
        _print_warning("  Set SYSTEM_RULES_BASE in your .env file.")
        has_warning = True

    if has_warning:
        _print_warning("To suppress these warnings, set KICOMAV_SUPPRESS_WARNINGS=1")


def init(env_path: Optional[Path] = None, show_warnings: bool = True) -> Config:
    """Initialize KicomAV configuration.

    This function loads the .env file and creates the global configuration.
    It is automatically called when the module is imported.

    Args:
        env_path: Optional path to .env file. If None, uses DEFAULT_ENV_PATH.
        show_warnings: If True, show warnings about missing configuration.

    Returns:
        Config instance
    """
    global _config
    if env_path is None:
        env_path = DEFAULT_ENV_PATH
    _config = Config.from_env(env_path)

    if show_warnings:
        _show_config_warnings(_config, env_path)

    return _config


def get_config() -> Config:
    """Get the current configuration.

    Returns:
        Current Config instance. If not initialized, initializes with defaults.
    """
    global _config
    if _config is None:
        _config = init()
    return _config


def reload_config(env_path: Optional[Path] = None, show_warnings: bool = True) -> Config:
    """Reload configuration from .env file.

    Args:
        env_path: Optional path to .env file. If None, uses DEFAULT_ENV_PATH.
        show_warnings: If True, show warnings about missing configuration.

    Returns:
        New Config instance
    """
    global _warnings_shown
    _warnings_shown = False  # Reset so warnings can be shown again
    return init(env_path, show_warnings)


def suppress_warnings(suppress: bool = True) -> None:
    """Suppress or enable configuration warnings.

    Args:
        suppress: If True, suppress warnings. If False, enable warnings.
    """
    global _suppress_warnings
    _suppress_warnings = suppress


# Auto-initialize on module import
init()
