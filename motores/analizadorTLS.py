from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict

from parsers.nmap import parse_nmap
from parsers.openssl import parse_openssl
from parsers.sslscan import parse_sslscan
from parsers.testssl import parse_testssl


def _construir_cmd_sslscan(objetivo: str, puerto: int) -> list[str]:
    # Algunas versiones fallan con salida ANSI o sin SNI explicito para dominios.
    cmd = ["sslscan", "--no-colour"]
    if ":" not in objetivo:
        cmd.extend(["--servername", objetivo])
    cmd.append(f"{objetivo}:{puerto}")
    return cmd


def _ejecutar(comando: list[str], timeout: int) -> Dict[str, Any]:
    if shutil.which(comando[0]) is None:
        return {
            "disponible": False,
            "returncode": 127,
            "stdout": "",
            "stderr": f"No se encontro {comando[0]}",
            "comando": " ".join(comando),
        }

    try:
        completed = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "disponible": True,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "comando": " ".join(comando),
        }
    except subprocess.TimeoutExpired:
        return {
            "disponible": True,
            "returncode": 124,
            "stdout": "",
            "stderr": "Timeout",
            "comando": " ".join(comando),
        }


def _openssl_via_bash(objetivo: str, puerto: int, timeout: int) -> Dict[str, Any]:
    script_path = Path(__file__).resolve().parent.parent / "scripts" / "openssl_probe.sh"
    if not script_path.exists() or shutil.which("bash") is None:
        return {
            "disponible": False,
            "returncode": 127,
            "stdout": "",
            "stderr": "bash o script openssl_probe.sh no disponible",
            "comando": f"bash {script_path} {objetivo} {puerto}",
        }

    cmd = ["bash", str(script_path), objetivo, str(puerto)]
    return _ejecutar(cmd, timeout)


def _resultado_parseado(raw_tool: Dict[str, Any], parser) -> Dict[str, Any]:
    texto_parseo = "\n".join(
        fragmento for fragmento in (raw_tool.get("stdout", ""), raw_tool.get("stderr", "")) if fragmento
    )
    return {
        "metadata": {
            "disponible": raw_tool["disponible"],
            "returncode": raw_tool["returncode"],
            "comando": raw_tool["comando"],
            "stderr": raw_tool["stderr"].strip(),
        },
        "parsed": parser(texto_parseo),
    }


def analizar_tls(objetivo: str, puerto: int = 443, timeout: int = 25) -> Dict[str, Dict[str, Any]]:
    # Buscar testssl.sh en ubicaciones comunes
    testssl_paths = [
        "testssl.sh",
        r"C:\testssl\testssl.sh",
        r"C:\git\testssl\testssl.sh",
        r"C:\Program Files\testssl\testssl.sh",
    ]
    testssl_cmd = None
    for path in testssl_paths:
        if shutil.which(path) is not None:
            testssl_cmd = [path, "--warnings", "off", "--quiet", f"{objetivo}:{puerto}"]
            break
    if testssl_cmd is None:
        testssl_cmd = ["testssl.sh", "--warnings", "off", "--quiet", f"{objetivo}:{puerto}"]
    
    herramientas = {
        "nmap": {
            "cmd": ["nmap", "-p", str(puerto), "--script", "ssl-enum-ciphers,ssl-heartbleed,ssl-poodle", objetivo],
            "parser": parse_nmap,
        },
        "testssl": {
            "cmd": testssl_cmd,
            "parser": parse_testssl,
        },
        "sslscan": {
            "cmd": _construir_cmd_sslscan(objetivo, puerto),
            "parser": parse_sslscan,
        },
    }

    resultados: Dict[str, Dict[str, Any]] = {}
    for nombre, conf in herramientas.items():
        raw_tool = _ejecutar(conf["cmd"], timeout)
        resultados[nombre] = _resultado_parseado(raw_tool, conf["parser"])

    raw_openssl = _openssl_via_bash(objetivo, puerto, timeout)
    if not raw_openssl["disponible"]:
        raw_openssl = _ejecutar(
            [
                "openssl",
                "s_client",
                "-connect",
                f"{objetivo}:{puerto}",
                "-servername",
                objetivo,
                "-brief",
            ],
            timeout,
        )
    resultados["openssl"] = _resultado_parseado(raw_openssl, parse_openssl)

    return resultados