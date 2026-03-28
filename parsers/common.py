from __future__ import annotations

import re
from typing import Iterable, List

PROTOCOLO_RE = re.compile(r"\b(SSLv2|SSLv3|TLSv1(?:\.0|\.1|\.2|\.3)?)\b", flags=re.IGNORECASE)
CIFRADO_RE = re.compile(
    r"\b(TLS_[A-Z0-9_]+|ECDHE-[A-Z0-9-]+|DHE-[A-Z0-9-]+|AES[0-9]+-[A-Z0-9-]+|CHACHA20-[A-Z0-9-]+)\b"
)
LINEA_NEGATIVA_RE = re.compile(
    r"\b(not\s+offered|not\s+supported|disabled|rejected|failed|no\b|none\b|n/a)\b",
    flags=re.IGNORECASE,
)


def normalizar_protocolo(valor: str) -> str:
    txt = valor.upper().replace(" ", "")
    if txt == "TLSV1":
        return "TLSv1"
    if txt.startswith("TLSV"):
        return "TLSv" + txt[4:]
    if txt.startswith("SSLV"):
        return "SSLv" + txt[4:]
    return valor


def extraer_protocolos(texto: str) -> List[str]:
    protocolos = set()
    for linea in texto.splitlines():
        if LINEA_NEGATIVA_RE.search(linea):
            continue
        for encontrado in PROTOCOLO_RE.findall(linea):
            protocolos.add(normalizar_protocolo(encontrado))
    return sorted(protocolos)


def extraer_cifrados(texto: str) -> List[str]:
    cifrados = set()
    for linea in texto.splitlines():
        if LINEA_NEGATIVA_RE.search(linea):
            continue
        for encontrado in CIFRADO_RE.findall(linea):
            cifrados.add(encontrado)
    return ordenar_unicos(cifrados)


def ordenar_unicos(items: Iterable[str]) -> List[str]:
    return sorted(set(items))
