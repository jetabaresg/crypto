from __future__ import annotations

import re
from typing import Dict, List

from parsers.common import extraer_cifrados, extraer_protocolos, normalizar_protocolo, ordenar_unicos


_PROTO_ESTADO_RE = re.compile(
    r"^\s*(SSLv2|SSLv3|TLS\s*1(?:\.0|\.1|\.2|\.3)?|TLSv1(?:\.0|\.1|\.2|\.3)?)\s+(.+)$",
    flags=re.IGNORECASE | re.MULTILINE,
)


def _normalizar_testssl_proto(valor: str) -> str:
    txt = valor.upper().replace(" ", "")
    if txt.startswith("TLS") and not txt.startswith("TLSV"):
        txt = txt.replace("TLS", "TLSV", 1)
    return normalizar_protocolo(txt)


def _protocolos_habilitados_testssl(raw: str) -> List[str]:
    protocolos: list[str] = []
    for proto, estado in _PROTO_ESTADO_RE.findall(raw):
        estado_txt = estado.strip().lower()
        if any(marca in estado_txt for marca in ("not offered", "not supported", "disabled", " no ")):
            continue
        if any(marca in estado_txt for marca in ("offered", "enabled", "supported", "ok")):
            protocolos.append(_normalizar_testssl_proto(proto))
    return ordenar_unicos(protocolos)


def parse_testssl(raw: str) -> Dict[str, List[str]]:
    protocolos = _protocolos_habilitados_testssl(raw)
    if not protocolos:
        protocolos = extraer_protocolos(raw)

    return {
        "protocolos": protocolos,
        "cifrados": extraer_cifrados(raw),
    }
