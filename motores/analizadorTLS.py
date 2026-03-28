from __future__ import annotations

import os
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


def _resolver_testssl() -> str:
    # Permite inyectar ruta explicita, por ejemplo:
    # TESTSSL_PATH=~/testssl.sh/testssl.sh
    ruta_env = os.getenv("TESTSSL_PATH", "").strip()
    if ruta_env:
        candidata = Path(ruta_env).expanduser()
        if candidata.is_dir():
            candidata = candidata / "testssl.sh"
        if candidata.exists():
            return str(candidata)

    rutas_comunes = [
        "testssl.sh",
        str(Path.home() / "testssl.sh" / "testssl.sh"),
        str(Path.home() / "tools" / "testssl.sh" / "testssl.sh"),
        r"C:\testssl\testssl.sh",
        r"C:\git\testssl\testssl.sh",
        r"C:\Program Files\testssl\testssl.sh",
    ]

    for ruta in rutas_comunes:
        expandida = Path(ruta).expanduser()
        if expandida.exists() or shutil.which(str(expandida)):
            return str(expandida)

    return "testssl.sh"


def _construir_cmd_testssl(objetivo: str, puerto: int) -> list[str]:
    ruta = _resolver_testssl()
    args = ["--warnings", "off", "--quiet"]

    # En modo rapido reduce mucho los 124 en entornos lentos.
    if os.getenv("TESTSSL_FAST", "1").strip() != "0":
        args.append("--fast")
    args.append(f"{objetivo}:{puerto}")

    # Si tenemos script .sh y bash disponible, forzamos ejecucion via bash.
    if ruta.endswith(".sh") and shutil.which("bash") is not None:
        return ["bash", ruta, *args]

    return [ruta, *args]


def analizar_tls(objetivo: str, puerto: int = 443, timeout: int = 25) -> Dict[str, Dict[str, Any]]:
    testssl_cmd = _construir_cmd_testssl(objetivo, puerto)

    # testssl y sslscan suelen requerir mas tiempo que openssl/nmap.
    timeout_nmap = max(timeout, 20)
    timeout_testssl = max(timeout * 6, 180)
    timeout_testssl = int(os.getenv("TESTSSL_TIMEOUT", str(timeout_testssl)))
    timeout_sslscan = max(timeout * 2, 40)
    timeout_openssl = max(timeout, 20)

    herramientas = {
        "nmap": {
            "cmd": ["nmap", "-p", str(puerto), "--script", "ssl-enum-ciphers,ssl-heartbleed,ssl-poodle", objetivo],
            "parser": parse_nmap,
            "timeout": timeout_nmap,
        },
        "testssl": {
            "cmd": testssl_cmd,
            "parser": parse_testssl,
            "timeout": timeout_testssl,
        },
        "sslscan": {
            "cmd": _construir_cmd_sslscan(objetivo, puerto),
            "parser": parse_sslscan,
            "timeout": timeout_sslscan,
        },
    }

    resultados: Dict[str, Dict[str, Any]] = {}
    for nombre, conf in herramientas.items():
        raw_tool = _ejecutar(conf["cmd"], conf["timeout"])
        resultados[nombre] = _resultado_parseado(raw_tool, conf["parser"])

    raw_openssl = _openssl_via_bash(objetivo, puerto, timeout_openssl)
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
            timeout_openssl,
        )
    resultados["openssl"] = _resultado_parseado(raw_openssl, parse_openssl)

    return resultados