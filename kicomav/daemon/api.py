# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
KicomAV Daemon REST API Module

This module provides FastAPI-based REST API endpoints for:
- File scanning (upload and path-based)
- Version and status information
- Signature management
- Statistics
"""

import asyncio
import base64
import logging
import os
import signal
import tempfile
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from .auth import get_api_key_dependency
from .config import get_daemon_config
from .scanner import ScanResult, ScanStatus, get_scanner

logger = logging.getLogger(__name__)

# Try to import FastAPI dependencies
try:
    from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile, status
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field

    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False


def check_fastapi_available():
    """Check if FastAPI is available."""
    if not FASTAPI_AVAILABLE:
        raise ImportError("FastAPI dependencies not installed. " "Install with: pip install kicomav[daemon]")


# Pydantic models for request/response
if FASTAPI_AVAILABLE:

    class PingResponse(BaseModel):
        """Response for ping endpoint."""

        status: str = "ok"
        message: str = "pong"

    class VersionResponse(BaseModel):
        """Response for version endpoint."""

        version: str
        build_date: str
        signatures: int
        last_update: str
        engine_count: int

    class ScanResultResponse(BaseModel):
        """Response for scan result."""

        filename: str
        status: str
        malware: Optional[str] = None
        scan_time_ms: int
        error: Optional[str] = None
        sha256: Optional[str] = None

    class ScanPathRequest(BaseModel):
        """Request for path-based scanning."""

        path: str = Field(..., description="Path to scan")
        recursive: bool = Field(True, description="Scan subdirectories recursively")
        include_hash: bool = Field(False, description="Include SHA256 hash in results")

    class ScanPathResponse(BaseModel):
        """Response for path-based scanning."""

        path: str
        files_scanned: int
        infected: int
        errors: int
        results: List[ScanResultResponse]
        scan_time_ms: int

    class ScanStreamRequest(BaseModel):
        """Request for stream-based scanning."""

        data: str = Field(..., description="Base64 encoded file data")
        filename: str = Field("stream", description="Optional filename")

    class StatsResponse(BaseModel):
        """Response for statistics endpoint."""

        uptime_seconds: int
        scans_total: int
        files_scanned: int
        malware_found: int
        errors: int
        avg_scan_time_ms: float

    class ReloadResponse(BaseModel):
        """Response for reload endpoint."""

        success: bool
        message: str

    class ErrorResponse(BaseModel):
        """Error response model."""

        detail: str


def create_api_app() -> "FastAPI":
    """Create and configure the FastAPI application.

    Returns:
        Configured FastAPI application
    """
    check_fastapi_available()

    config = get_daemon_config()
    scanner = get_scanner()

    # Shutdown event
    shutdown_event = asyncio.Event()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Application lifespan handler."""
        # Startup
        logger.info("Starting KicomAV REST API server...")
        if not scanner.initialize():
            logger.error("Failed to initialize scanner")
            raise RuntimeError("Scanner initialization failed")
        logger.info("REST API server started on http://%s:%d", config.http_host, config.http_port)
        yield
        # Shutdown
        logger.info("Shutting down REST API server...")
        scanner.shutdown()

    app = FastAPI(
        title="KicomAV Daemon API",
        description="REST API for KicomAV antivirus scanning",
        version="1.0.0",
        lifespan=lifespan,
    )

    # Get the auth dependency
    verify_api_key = get_api_key_dependency()

    # Health check endpoints (no auth required)
    @app.get("/ping", response_model=PingResponse, tags=["Health"])
    async def ping():
        """Check if the daemon is running."""
        if not scanner.is_running():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Scanner not running",
            )
        return PingResponse()

    @app.get("/version", response_model=VersionResponse, tags=["Info"])
    async def version():
        """Get version information."""
        info = scanner.get_version()
        return VersionResponse(**info.to_dict())

    @app.get("/stats", response_model=StatsResponse, tags=["Info"])
    async def stats():
        """Get daemon statistics."""
        stat = scanner.get_stats()
        return StatsResponse(**stat.to_dict())

    # Scan endpoints (auth required if configured)
    @app.post(
        "/scan/file",
        response_model=ScanResultResponse,
        tags=["Scan"],
        responses={
            401: {"model": ErrorResponse, "description": "Unauthorized"},
            413: {"model": ErrorResponse, "description": "File too large"},
        },
    )
    async def scan_file(
        file: UploadFile = File(...),
        include_hash: bool = Query(False, description="Include SHA256 hash"),
        api_key: str = Depends(verify_api_key),
    ):
        """Scan an uploaded file."""
        # Check file size
        if file.size and file.size > config.max_upload_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File too large. Maximum size: {config.max_upload_size_mb:.1f}MB",
            )

        # Read file content
        content = await file.read()

        # Check size after reading (in case size wasn't reported)
        if len(content) > config.max_upload_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File too large. Maximum size: {config.max_upload_size_mb:.1f}MB",
            )

        # Scan the stream
        result = scanner.scan_stream(content, file.filename or "uploaded_file")

        return ScanResultResponse(
            filename=result.filename,
            status=result.status.value,
            malware=result.malware_name,
            scan_time_ms=result.scan_time_ms,
            error=result.error_message,
            sha256=result.sha256 if include_hash else None,
        )

    @app.post(
        "/scan/path",
        response_model=ScanPathResponse,
        tags=["Scan"],
        responses={
            401: {"model": ErrorResponse, "description": "Unauthorized"},
            404: {"model": ErrorResponse, "description": "Path not found"},
        },
    )
    async def scan_path(
        request: ScanPathRequest,
        api_key: str = Depends(verify_api_key),
    ):
        """Scan a local path on the server."""
        import time

        path = request.path

        # Validate path exists
        if not os.path.exists(path):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Path not found: {path}",
            )

        start_time = time.time()

        if os.path.isfile(path):
            # Single file
            result = scanner.scan_file(path, include_hash=request.include_hash)
            results = [result]
        else:
            # Directory
            results = scanner.scan_directory(path, recursive=request.recursive)

        elapsed_ms = int((time.time() - start_time) * 1000)

        # Count results
        infected = sum(1 for r in results if r.status == ScanStatus.INFECTED)
        errors = sum(1 for r in results if r.status == ScanStatus.ERROR)

        return ScanPathResponse(
            path=path,
            files_scanned=len(results),
            infected=infected,
            errors=errors,
            results=[
                ScanResultResponse(
                    filename=r.filename,
                    status=r.status.value,
                    malware=r.malware_name,
                    scan_time_ms=r.scan_time_ms,
                    error=r.error_message,
                    sha256=r.sha256,
                )
                for r in results
            ],
            scan_time_ms=elapsed_ms,
        )

    @app.post(
        "/scan/stream",
        response_model=ScanResultResponse,
        tags=["Scan"],
        responses={
            401: {"model": ErrorResponse, "description": "Unauthorized"},
            413: {"model": ErrorResponse, "description": "Data too large"},
        },
    )
    async def scan_stream(
        request: ScanStreamRequest,
        api_key: str = Depends(verify_api_key),
    ):
        """Scan base64 encoded data."""
        try:
            data = base64.b64decode(request.data)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid base64 data: {e}",
            )

        # Check size
        if len(data) > config.max_upload_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Data too large. Maximum size: {config.max_upload_size_mb:.1f}MB",
            )

        result = scanner.scan_stream(data, request.filename)

        return ScanResultResponse(
            filename=result.filename,
            status=result.status.value,
            malware=result.malware_name,
            scan_time_ms=result.scan_time_ms,
            error=result.error_message,
            sha256=result.sha256,
        )

    # Management endpoints (auth required)
    @app.post(
        "/reload",
        response_model=ReloadResponse,
        tags=["Management"],
        responses={401: {"model": ErrorResponse, "description": "Unauthorized"}},
    )
    async def reload_signatures(api_key: str = Depends(verify_api_key)):
        """Reload signature databases."""
        success = scanner.reload_signatures()
        return ReloadResponse(
            success=success,
            message="Signatures reloaded" if success else "Reload failed",
        )

    @app.post(
        "/shutdown",
        response_model=ReloadResponse,
        tags=["Management"],
        responses={401: {"model": ErrorResponse, "description": "Unauthorized"}},
    )
    async def shutdown(api_key: str = Depends(verify_api_key)):
        """Shutdown the daemon (requires authentication)."""
        config = get_daemon_config()

        # Always require auth for shutdown
        if not config.require_auth:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Shutdown requires authentication to be enabled",
            )

        logger.info("Shutdown requested via API")
        shutdown_event.set()

        # Schedule shutdown
        asyncio.get_event_loop().call_later(1.0, lambda: os.kill(os.getpid(), signal.SIGTERM))

        return ReloadResponse(success=True, message="Shutdown initiated")

    return app


def run_api_server():
    """Run the REST API server."""
    check_fastapi_available()

    import uvicorn

    config = get_daemon_config()

    # Refuse to start on an insecure configuration (e.g. network-exposed, no auth)
    config_errors = config.validate()
    if config_errors:
        for err in config_errors:
            logger.error("Invalid daemon configuration: %s", err)
        raise SystemExit(1)

    app = create_api_app()

    uvicorn.run(
        app,
        host=config.http_host,
        port=config.http_port,
        log_level="info",
    )
