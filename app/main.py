from __future__ import annotations

import ipaddress
import shutil
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen
from xml.etree.ElementTree import ParseError

from defusedxml import ElementTree as DefusedElementTree
from defusedxml.common import DefusedXmlException
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles


APP_DIR = Path(__file__).resolve().parent
PROJECT_DIR = APP_DIR.parent
STATIC_DIR = APP_DIR / "static"
RESULTS_DIR = PROJECT_DIR / "results"
FAILED_SCANS_DIR = PROJECT_DIR / "Failed_Scans"

IPIFY_URL = "https://api.ipify.org"
SCAN_PORTS = (21, 22, 25, 53, 80, 443, 3000, 3389, 8080, 8443)
PORT_ARGUMENT = ",".join(str(port) for port in SCAN_PORTS)
NMAP_TIMEOUT_SECONDS = 120
IP_LOOKUP_TIMEOUT_SECONDS = 10
MAX_XML_BYTES = 5 * 1024 * 1024

_scan_lock = threading.Lock()

app = FastAPI(title="Local Network Scanner", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class ScanFailure(Exception):
    """An expected failure that can be safely shown to the user."""


def timestamp() -> str:
    """Return a filename-safe, collision-resistant local timestamp."""
    return datetime.now().strftime("%Y%m%dT%H%M%S_%f")


def ensure_runtime_directories() -> None:
    """Create the fixed application-owned output directories if needed."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    FAILED_SCANS_DIR.mkdir(parents=True, exist_ok=True)


def write_failure_log(message: str) -> None:
    """Record a concise expected failure without exposing a traceback."""
    try:
        ensure_runtime_directories()
        (FAILED_SCANS_DIR / f"scan_failure_{timestamp()}.txt").write_text(
            f"Local Network Scanner failure\n{message}\n", encoding="utf-8"
        )
    except OSError:
        # A storage failure must not replace the original, actionable error.
        pass


def validate_public_ipv4(value: str) -> str:
    """Accept only a canonical literal IPv4 address from the fixed lookup service."""
    if not value or value != value.strip():
        raise ScanFailure("The public IP service returned an invalid IPv4 address.")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ScanFailure("The public IP service returned an invalid IPv4 address.") from error
    if not isinstance(address, ipaddress.IPv4Address) or str(address) != value:
        raise ScanFailure("The public IP service returned an invalid IPv4 address.")
    return value


def resolve_public_ipv4() -> str:
    """Get and strictly validate the server host's public IPv4 address."""
    try:
        with urlopen(IPIFY_URL, timeout=IP_LOOKUP_TIMEOUT_SECONDS) as response:
            raw_value = response.read(64)
    except (URLError, OSError, TimeoutError) as error:
        raise ScanFailure("Could not retrieve the public IP address. Please try again.") from error

    try:
        value = raw_value.decode("ascii")
    except UnicodeDecodeError as error:
        raise ScanFailure("The public IP service returned an invalid address.") from error
    return validate_public_ipv4(value)


def safe_service_text(value: str | None) -> str:
    """Keep untrusted XML values printable, short, and safe for JSON/UI display."""
    if not value:
        return ""
    clean_value = "".join(character for character in value if character.isprintable()).strip()
    return clean_value[:300]


def parse_nmap_xml(xml_path: Path) -> list[dict[str, Any]]:
    """Defensively parse only requested Nmap port records from bounded XML output."""
    try:
        if not xml_path.is_file() or xml_path.stat().st_size > MAX_XML_BYTES:
            raise ScanFailure("Nmap returned an invalid scan result.")
        xml_data = xml_path.read_bytes()
        root = DefusedElementTree.fromstring(xml_data)
    except (OSError, ParseError, DefusedXmlException) as error:
        if isinstance(error, ScanFailure):
            raise
        raise ScanFailure("Nmap returned a scan result that could not be read.") from error

    port_data: dict[int, dict[str, str]] = {}
    for port_element in root.findall("./host/ports/port"):
        try:
            port_number = int(port_element.get("portid", ""))
        except ValueError:
            continue
        if port_number not in SCAN_PORTS or port_number in port_data:
            continue

        state_element = port_element.find("state")
        service_element = port_element.find("service")
        state = safe_service_text(state_element.get("state") if state_element is not None else "")
        service_parts = []
        if service_element is not None:
            for attribute in ("name", "product", "version", "extrainfo"):
                detail = safe_service_text(service_element.get(attribute))
                if detail:
                    service_parts.append(detail)
        port_data[port_number] = {
            "state": state or "unknown",
            "service": " ".join(service_parts) or "Not identified",
        }

    return [
        {
            "port": port,
            "state": port_data.get(port, {}).get("state", "unknown"),
            "service": port_data.get(port, {}).get("service", "Not identified"),
        }
        for port in SCAN_PORTS
    ]


def run_fixed_scan() -> tuple[str, list[dict[str, Any]]]:
    """Run the sole allowed Nmap command and retain only valid successful XML."""
    ensure_runtime_directories()
    target_ip = resolve_public_ipv4()
    nmap_path = shutil.which("nmap")
    if nmap_path is None:
        raise ScanFailure("Nmap is not installed or is not available in PATH. Install Nmap, then try again.")

    scan_id = timestamp()
    temporary_xml = RESULTS_DIR / f".scan_{scan_id}.xml.part"
    final_xml = RESULTS_DIR / f"scan_{scan_id}.xml"
    command = [
        nmap_path,
        "-sT",
        "-sV",
        "-Pn",
        "-p",
        PORT_ARGUMENT,
        "-oX",
        str(temporary_xml),
        target_ip,
    ]

    try:
        completed = subprocess.run(
            command,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            timeout=NMAP_TIMEOUT_SECONDS,
        )
        if completed.returncode != 0:
            raise ScanFailure("Nmap could not complete this scan. Please check Nmap and try again.")
        results = parse_nmap_xml(temporary_xml)
        temporary_xml.replace(final_xml)
        return target_ip, results
    except subprocess.TimeoutExpired as error:
        raise ScanFailure("The Nmap scan timed out after 120 seconds.") from error
    except OSError as error:
        raise ScanFailure("Nmap could not be started. Please check the Nmap installation.") from error
    finally:
        # Failed and incomplete XML is not retained as a successful scan result.
        try:
            temporary_xml.unlink(missing_ok=True)
        except OSError:
            pass


@app.get("/", include_in_schema=False)
def homepage() -> FileResponse:
    """Serve the fixed single-page interface."""
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/api/scan", include_in_schema=False)
def start_scan() -> JSONResponse:
    """Start the one fixed scan, rejecting concurrent requests without accepting input."""
    if not _scan_lock.acquire(blocking=False):
        return JSONResponse(
            status_code=409,
            content={"ok": False, "error": "A scan is already running. Please wait for it to finish."},
        )

    try:
        target_ip, results = run_fixed_scan()
        return JSONResponse(content={"ok": True, "target": target_ip, "results": results})
    except ScanFailure as error:
        message = str(error)
        write_failure_log(message)
        return JSONResponse(status_code=500, content={"ok": False, "error": message})
    except Exception:
        message = "The scan could not be completed due to an unexpected application error."
        write_failure_log(message)
        return JSONResponse(status_code=500, content={"ok": False, "error": message})
    finally:
        _scan_lock.release()


if __name__ == "__main__":
    # The application-provided development entry point is deliberately loopback-only.
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
