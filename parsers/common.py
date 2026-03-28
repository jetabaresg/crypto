from __future__ import annotations

import re
from typing import Iterable, List

PROTOCOLO_RE = re.compile(r"\b(SSLv2|SSLv3|TLSv1(?:\.0|\.1|\.2|\.3)?)\b", flags=re.IGNORECASE)


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
    encontrados = PROTOCOLO_RE.findall(texto)
    return sorted({normalizar_protocolo(p) for p in encontrados})


def ordenar_unicos(items: Iterable[str]) -> List[str]:
    return sorted(set(items))
