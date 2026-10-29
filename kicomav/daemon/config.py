# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
KicomAV Daemon Configuration Module

This module handles daemon-specific configuration including:
- HTTP API settings
- Socket server settings
- Authentication settings
- Resource limits
"""

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from kicomav.kavcore.k2config import get_config as get_base_config


# Default values
DEFAULT_HTTP_HOST = "127.0.0.1"
DEFAULT_HTTP_PORT = 8311
DEFAULT_SOCKET_PORT = 3311
DEFAULT_SOCKET_HOST = "127.0.0.1"
DEFAULT_SOCKET_PATH = "/var/run/kicomav/k2d.sock"
DEFAULT_MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50MB
DEFAULT_MAX_WORKERS = 4
DEFAULT_SCAN_TIMEOUT = 300  # 5 minutes


def _get_env_bool(key: str, default: bool = False) -> bool:
    """Get boolean value from environment variable."""
    value = os.environ.get(key, "").strip().lower()
    if not value:
        return default
    return value in ("1", "true", "yes", "on")


def _get_env_int(key: str, default: int) -> int:
    """Get integer value from environment variable."""
    value = os.environ.get(key, "").strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _get_env_str(key: str, default: str = "") -> str:
    """Get string value from environment variable."""
    return os.environ.get(key, "").strip() or default


@dataclass
class DaemonConfig:
    """Daemon configuration container.

    Attributes:
        http_enabled: Enable HTTP REST API server
        http_host: HTTP server bind address
        http_port: HTTP server port
        socket_enabled: Enable socket protocol server
        socket_port: TCP socket port
        socket_path: Unix socket path
        max_upload_size: Maximum file upload size in bytes
        max_workers: Maximum concurrent scan workers
        scan_timeout: Scan timeout in seconds
        api_key: API key for authentication
        require_auth: Require authentication for API access
    """

    # HTTP settings
    http_enabled: bool = True
    http_host: str = DEFAULT_HTTP_HOST
    http_port: int = DEFAULT_HTTP_PORT

    # Socket settings
    socket_enabled: bool = True
    socket_host: str = DEFAULT_SOCKET_HOST
    socket_port: int = DEFAULT_SOCKET_PORT
    socket_path: str = DEFAULT_SOCKET_PATH

    # Resource limits
    max_upload_size: int = DEFAULT_MAX_UPLOAD_SIZE
    max_workers: int = DEFAULT_MAX_WORKERS
    scan_timeout: int = DEFAULT_SCAN_TIMEOUT

    # Authentication
    api_key: str = ""
    require_auth: bool = False

    # PID and log files
    pid_file: Optional[str] = None
    log_file: Optional[str] = None

    @classmethod
    def from_env(cls) -> "DaemonConfig":
        """Create DaemonConfig from environment variables.

        Returns:
            DaemonConfig instance populated from environment variables
        """
        # Determine max_workers default based on CPU count
        cpu_count = os.cpu_count() or 4
        default_workers = min(cpu_count, 8)

        return cls(
            # HTTP settings
            http_enabled=_get_env_bool("K2D_HTTP_ENABLED", True),
            http_host=_get_env_str("K2D_HTTP_HOST", DEFAULT_HTTP_HOST),
            http_port=_get_env_int("K2D_HTTP_PORT", DEFAULT_HTTP_PORT),
            # Socket settings
            socket_enabled=_get_env_bool("K2D_SOCKET_ENABLED", True),
            socket_host=_get_env_str("K2D_SOCKET_HOST", DEFAULT_SOCKET_HOST),
            socket_port=_get_env_int("K2D_SOCKET_PORT", DEFAULT_SOCKET_PORT),
            socket_path=_get_env_str("K2D_SOCKET_PATH", DEFAULT_SOCKET_PATH),
            # Resource limits
            max_upload_size=_get_env_int("K2D_MAX_UPLOAD_SIZE", DEFAULT_MAX_UPLOAD_SIZE),
            max_workers=_get_env_int("K2D_MAX_WORKERS", default_workers),
            scan_timeout=_get_env_int("K2D_SCAN_TIMEOUT", DEFAULT_SCAN_TIMEOUT),
            # Authentication
            api_key=_get_env_str("K2D_API_KEY", ""),
            require_auth=_get_env_bool("K2D_REQUIRE_AUTH", False),
            # Files
            pid_file=_get_env_str("K2D_PID_FILE", "") or None,
            log_file=_get_env_str("K2D_LOG_FILE", "") or None,
        )

    def validate(self) -> list[str]:
        """Validate configuration and return list of errors.

        Returns:
            List of error messages. Empty if valid.
        """
        errors = []

        # At least one server must be enabled
        if not self.http_enabled and not self.socket_enabled:
            errors.append("At least one of HTTP or Socket server must be enabled")

        # Port validation
        if self.http_enabled and not (1 <= self.http_port <= 65535):
            errors.append(f"Invalid HTTP port: {self.http_port}")
        if self.socket_enabled and not (1 <= self.socket_port <= 65535):
            errors.append(f"Invalid socket port: {self.socket_port}")

        # Resource limits
        if self.max_upload_size < 1024:  # Minimum 1KB
            errors.append(f"max_upload_size too small: {self.max_upload_size}")
        if self.max_workers < 1:
            errors.append(f"max_workers must be at least 1: {self.max_workers}")
        if self.scan_timeout < 1:
            errors.append(f"scan_timeout must be at least 1: {self.scan_timeout}")

        # Authentication
        if self.require_auth and not self.api_key:
            errors.append("API key required when require_auth is enabled")

        # Fail closed: never expose a non-loopback listener without authentication
        import ipaddress

        def _is_loopback(host: str) -> bool:
            if host in ("localhost", ""):
                return True
            try:
                return ipaddress.ip_address(host).is_loopback
            except ValueError:
                return False

        if self.http_enabled and not _is_loopback(self.http_host) and not self.require_auth:
            errors.append(
                f"HTTP server bound to non-loopback {self.http_host} requires require_auth=True"
            )
        if self.socket_enabled and not _is_loopback(self.socket_host) and not self.require_auth:
            errors.append(
                f"Socket server bound to non-loopback {self.socket_host} requires require_auth=True"
            )

        return errors

    def generate_api_key(self) -> str:
        """Generate a new random API key.

        Returns:
            Generated API key (32 characters)
        """
        self.api_key = secrets.token_urlsafe(24)
        return self.api_key

    @property
    def max_upload_size_mb(self) -> float:
        """Get max upload size in MB."""
        return self.max_upload_size / (1024 * 1024)


# Global daemon configuration instance
_daemon_config: Optional[DaemonConfig] = None


def get_daemon_config() -> DaemonConfig:
    """Get the current daemon configuration.

    Returns:
        Current DaemonConfig instance. If not initialized, initializes from env.
    """
    global _daemon_config
    if _daemon_config is None:
        _daemon_config = DaemonConfig.from_env()
    return _daemon_config


def reload_daemon_config() -> DaemonConfig:
    """Reload daemon configuration from environment.

    Returns:
        New DaemonConfig instance
    """
    global _daemon_config
    _daemon_config = DaemonConfig.from_env()
    return _daemon_config


def set_daemon_config(config: DaemonConfig) -> None:
    """Set the daemon configuration.

    Args:
        config: DaemonConfig instance to use
    """
    global _daemon_config
    _daemon_config = config
