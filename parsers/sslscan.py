from __future__ import annotations

import re
from typing import Dict, List

from parsers.common import extraer_cifrados, extraer_protocolos, normalizar_protocolo, ordenar_unicos


def parse_sslscan(raw: str) -> Dict[str, List[str]]:
    aceptados = re.findall(
        r"^Accepted\s+(\S+)\s+\d+\s+bits\s+([^\r\n]+)",
        raw,
        flags=re.MULTILINE,
    )
    protocolos_en_aceptados = [normalizar_protocolo(proto) for proto, _ in aceptados]
    cifrados = [cifrado.strip() for _, cifrado in aceptados]

    if not cifrados:
        cifrados = extraer_cifrados(raw)

    return {
        "protocolos": ordenar_unicos(extraer_protocolos(raw) + protocolos_en_aceptados),
        "cifrados": ordenar_unicos(cifrados),
    }
