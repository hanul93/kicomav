# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
KicomAV Daemon Socket Server Module

This module provides a clamd-compatible socket protocol server:
- TCP socket support
- Unix socket support (Linux/macOS)
- clamd-style commands (PING, SCAN, INSTREAM, etc.)
"""

import asyncio
import logging
import os
import signal
import struct
import sys
from typing import Optional, Tuple

from .auth import SocketAuthState, require_auth
from .config import get_daemon_config
from .scanner import ScanStatus, get_scanner

logger = logging.getLogger(__name__)


class SocketProtocol:
    """clamd-compatible protocol handler."""

    # Command constants
    CMD_PING = "PING"
    CMD_VERSION = "VERSION"
    CMD_SCAN = "SCAN"
    CMD_CONTSCAN = "CONTSCAN"
    CMD_MULTISCAN = "MULTISCAN"
    CMD_INSTREAM = "INSTREAM"
    CMD_RELOAD = "RELOAD"
    CMD_SHUTDOWN = "SHUTDOWN"
    CMD_STATS = "STATS"
    CMD_AUTH = "AUTH"

    # Response messages
    RESP_PONG = "PONG"
    RESP_OK = "OK"
    RESP_FOUND = "FOUND"
    RESP_ERROR = "ERROR"
    RESP_RELOADING = "RELOADING"
    RESP_UNKNOWN_COMMAND = "UNKNOWN COMMAND"
    RESP_AUTH_REQUIRED = "AUTHENTICATION REQUIRED"
    RESP_AUTH_OK = "AUTHENTICATION OK"
    RESP_AUTH_FAILED = "AUTHENTICATION FAILED"

    def __init__(self):
        self.scanner = get_scanner()
        self.config = get_daemon_config()

    def parse_command(self, data: bytes) -> Tuple[str, str]:
        """Parse a command from raw data.

        Supports:
        - Legacy format: COMMAND arg
        - n-prefix format: nCOMMAND arg\\n
        - z-prefix format: zCOMMAND arg\\0

        Args:
            data: Raw command data

        Returns:
            Tuple of (command, argument)
        """
        # Decode bytes to string
        try:
            text = data.decode("utf-8").strip()
        except UnicodeDecodeError:
            text = data.decode("latin-1").strip()

        if not text:
            return "", ""

        # Handle n-prefix and z-prefix
        if text[0] in ("n", "z"):
            text = text[1:]

        # Remove null terminator if present
        text = text.rstrip("\x00")

        # Split command and argument
        parts = text.split(maxsplit=1)
        command = parts[0].upper() if parts else ""
        argument = parts[1] if len(parts) > 1 else ""

        return command, argument

    def format_response(self, message: str, delimiter: str = "\n") -> bytes:
        """Format a response message.

        Args:
            message: Response message
            delimiter: Line delimiter (\\n or \\0)

        Returns:
            Encoded response bytes
        """
        return f"{message}{delimiter}".encode("utf-8")

    def format_scan_result(self, filepath: str, status: ScanStatus, malware: Optional[str]) -> str:
        """Format a scan result in clamd style.

        Args:
            filepath: Path to scanned file
            status: Scan status
            malware: Malware name if infected

        Returns:
            Formatted result string
        """
        if status == ScanStatus.INFECTED:
            return f"{filepath}: {malware} {self.RESP_FOUND}"
        elif status == ScanStatus.ERROR:
            return f"{filepath}: {malware or 'Scan error'} {self.RESP_ERROR}"
        else:
            return f"{filepath}: {self.RESP_OK}"


class SocketClientHandler:
    """Handler for a single socket client connection."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        protocol: SocketProtocol,
    ):
        self.reader = reader
        self.writer = writer
        self.protocol = protocol
        self.auth_state = SocketAuthState()
        self.delimiter = "\n"
        self._shutdown_requested = False

    async def handle(self) -> bool:
        """Handle client connection.

        Returns:
            True if shutdown was requested
        """
        addr = self.writer.get_extra_info("peername")
        logger.debug("New connection from %s", addr)

        try:
            while True:
                # Read data (with timeout)
                try:
                    data = await asyncio.wait_for(self.reader.read(4096), timeout=300)
                except asyncio.TimeoutError:
                    logger.debug("Connection timeout from %s", addr)
                    break

                if not data:
                    break

                # Determine delimiter from prefix
                if data and data[0:1] == b"z":
                    self.delimiter = "\x00"
                else:
                    self.delimiter = "\n"

                # Parse and handle command
                command, argument = self.protocol.parse_command(data)

                if not command:
                    continue

                response = await self.handle_command(command, argument)

                if response:
                    self.writer.write(self.protocol.format_response(response, self.delimiter))
                    await self.writer.drain()

                if self._shutdown_requested:
                    return True

        except ConnectionResetError:
            logger.debug("Connection reset by %s", addr)
        except Exception as e:
            logger.exception("Error handling connection from %s: %s", addr, e)
        finally:
            self.writer.close()
            await self.writer.wait_closed()
            logger.debug("Connection closed from %s", addr)

        return False

    async def handle_command(self, command: str, argument: str) -> str:
        """Handle a parsed command.

        Args:
            command: Command name
            argument: Command argument

        Returns:
            Response string
        """
        # AUTH command (always allowed)
        if command == SocketProtocol.CMD_AUTH:
            if self.auth_state.authenticate(f"AUTH {argument}"):
                return SocketProtocol.RESP_AUTH_OK
            return SocketProtocol.RESP_AUTH_FAILED

        # Check authentication for other commands
        if not self.auth_state.is_authenticated():
            return SocketProtocol.RESP_AUTH_REQUIRED

        # PING - always allowed
        if command == SocketProtocol.CMD_PING:
            return SocketProtocol.RESP_PONG

        # VERSION
        elif command == SocketProtocol.CMD_VERSION:
            info = self.protocol.scanner.get_version()
            return f"KicomAV {info.version} / Signatures: {info.signatures}"

        # STATS
        elif command == SocketProtocol.CMD_STATS:
            stats = self.protocol.scanner.get_stats()
            return (
                f"UPTIME: {stats.uptime_seconds}s | "
                f"SCANS: {stats.scans_total} | "
                f"FILES: {stats.files_scanned} | "
                f"MALWARE: {stats.malware_found} | "
                f"ERRORS: {stats.errors}"
            )

        # SCAN - scan a single file
        elif command == SocketProtocol.CMD_SCAN:
            if not argument:
                return f"SCAN: No path specified {SocketProtocol.RESP_ERROR}"
            return await self._handle_scan(argument)

        # CONTSCAN - scan directory (continue on error)
        elif command == SocketProtocol.CMD_CONTSCAN:
            if not argument:
                return f"CONTSCAN: No path specified {SocketProtocol.RESP_ERROR}"
            return await self._handle_contscan(argument)

        # MULTISCAN - same as CONTSCAN for now (multi-threaded in future)
        elif command == SocketProtocol.CMD_MULTISCAN:
            if not argument:
                return f"MULTISCAN: No path specified {SocketProtocol.RESP_ERROR}"
            return await self._handle_contscan(argument)

        # INSTREAM - scan streamed data
        elif command == SocketProtocol.CMD_INSTREAM:
            return await self._handle_instream()

        # RELOAD
        elif command == SocketProtocol.CMD_RELOAD:
            success = self.protocol.scanner.reload_signatures()
            return SocketProtocol.RESP_RELOADING if success else f"RELOAD {SocketProtocol.RESP_ERROR}"

        # SHUTDOWN
        elif command == SocketProtocol.CMD_SHUTDOWN:
            if not self.auth_state.requires_auth():
                return f"SHUTDOWN: Authentication required {SocketProtocol.RESP_ERROR}"
            self._shutdown_requested = True
            return "SHUTDOWN OK"

        else:
            return SocketProtocol.RESP_UNKNOWN_COMMAND

    async def _handle_scan(self, path: str) -> str:
        """Handle SCAN command."""
        if not os.path.exists(path):
            return f"{path}: No such file or directory {SocketProtocol.RESP_ERROR}"

        if os.path.isdir(path):
            return f"{path}: Is a directory {SocketProtocol.RESP_ERROR}"

        result = self.protocol.scanner.scan_file(path)
        return self.protocol.format_scan_result(path, result.status, result.malware_name)

    async def _handle_contscan(self, path: str) -> str:
        """Handle CONTSCAN command."""
        if not os.path.exists(path):
            return f"{path}: No such file or directory {SocketProtocol.RESP_ERROR}"

        results = []

        if os.path.isfile(path):
            result = self.protocol.scanner.scan_file(path)
            results.append(self.protocol.format_scan_result(path, result.status, result.malware_name))
        else:
            scan_results = self.protocol.scanner.scan_directory(path, recursive=True)
            for result in scan_results:
                full_path = (
                    os.path.join(path, result.filename) if not os.path.isabs(result.filename) else result.filename
                )
                results.append(self.protocol.format_scan_result(full_path, result.status, result.malware_name))

        return self.delimiter.join(results)

    async def _handle_instream(self) -> str:
        """Handle INSTREAM command.

        INSTREAM protocol:
        1. Client sends chunks: <4-byte length><data>
        2. Client sends terminator: <4 zero bytes>
        3. Server responds with scan result
        """
        data = b""
        config = get_daemon_config()

        try:
            while True:
                # Read chunk length (4 bytes, network byte order)
                length_data = await asyncio.wait_for(self.reader.readexactly(4), timeout=30)
                chunk_length = struct.unpack("!I", length_data)[0]

                # Zero length = end of stream
                if chunk_length == 0:
                    break

                # Check size limit
                if len(data) + chunk_length > config.max_upload_size:
                    return f"stream: Size limit exceeded {SocketProtocol.RESP_ERROR}"

                # Read chunk data
                chunk = await asyncio.wait_for(self.reader.readexactly(chunk_length), timeout=30)
                data += chunk

        except asyncio.TimeoutError:
            return f"stream: Timeout {SocketProtocol.RESP_ERROR}"
        except asyncio.IncompleteReadError:
            return f"stream: Incomplete data {SocketProtocol.RESP_ERROR}"

        if not data:
            return f"stream: No data received {SocketProtocol.RESP_ERROR}"

        # Scan the data
        result = self.protocol.scanner.scan_stream(data, "stream")
        return self.protocol.format_scan_result("stream", result.status, result.malware_name)


class SocketServer:
    """Socket server for clamd-compatible protocol."""

    def __init__(self):
        self.config = get_daemon_config()
        self.protocol = SocketProtocol()
        self._tcp_server: Optional[asyncio.Server] = None
        self._unix_server: Optional[asyncio.Server] = None
        self._running = False
        self._shutdown_event = asyncio.Event()

    async def _client_handler(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a client connection."""
        handler = SocketClientHandler(reader, writer, self.protocol)
        shutdown_requested = await handler.handle()
        if shutdown_requested:
            self._shutdown_event.set()

    async def start_tcp(self, host: str, port: int) -> None:
        """Start TCP socket server.

        Args:
            host: Bind address
            port: Bind port
        """
        self._tcp_server = await asyncio.start_server(
            self._client_handler,
            host,
            port,
        )
        addr = self._tcp_server.sockets[0].getsockname()
        logger.info("TCP socket server listening on %s:%d", addr[0], addr[1])

    async def start_unix(self, path: str) -> None:
        """Start Unix socket server.

        Args:
            path: Socket file path
        """
        if sys.platform == "win32":
            logger.warning("Unix sockets not supported on Windows")
            return

        # Create socket directory if needed
        socket_dir = os.path.dirname(path)
        if socket_dir and not os.path.exists(socket_dir):
            os.makedirs(socket_dir, exist_ok=True)

        # Remove existing socket file
        if os.path.exists(path):
            os.unlink(path)

        self._unix_server = await asyncio.start_unix_server(
            self._client_handler,
            path,
        )
        logger.info("Unix socket server listening on %s", path)

    async def serve_forever(self) -> None:
        """Serve until shutdown requested."""
        self._running = True

        servers = []
        if self._tcp_server:
            servers.append(self._tcp_server.serve_forever())
        if self._unix_server:
            servers.append(self._unix_server.serve_forever())

        if not servers:
            logger.error("No servers to run")
            return

        # Run servers and wait for shutdown
        try:
            await asyncio.gather(
                *servers,
                self._shutdown_event.wait(),
            )
        except asyncio.CancelledError:
            pass
        finally:
            await self.stop()

    async def stop(self) -> None:
        """Stop the server."""
        if not self._running:
            return

        self._running = False
        logger.info("Stopping socket server...")

        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()

        if self._unix_server:
            self._unix_server.close()
            await self._unix_server.wait_closed()
            # Clean up socket file
            if os.path.exists(self.config.socket_path):
                os.unlink(self.config.socket_path)

        logger.info("Socket server stopped")


async def run_socket_server() -> None:
    """Run the socket server."""
    config = get_daemon_config()

    # Refuse to start on an insecure configuration (e.g. network-exposed, no auth)
    config_errors = config.validate()
    if config_errors:
        for err in config_errors:
            logger.error("Invalid daemon configuration: %s", err)
        return

    scanner = get_scanner()

    # Initialize scanner
    if not scanner.initialize():
        logger.error("Failed to initialize scanner")
        return

    server = SocketServer()

    try:
        # Start TCP server
        if config.socket_enabled:
            await server.start_tcp(config.socket_host, config.socket_port)

            # Start Unix socket on non-Windows
            if sys.platform != "win32":
                await server.start_unix(config.socket_path)

        await server.serve_forever()

    except Exception as e:
        logger.exception("Socket server error: %s", e)
    finally:
        await server.stop()
        scanner.shutdown()
