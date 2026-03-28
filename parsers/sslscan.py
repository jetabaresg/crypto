from __future__ import annotations

import re
from typing import Dict, List

from parsers.common import extraer_cifrados, extraer_protocolos, normalizar_protocolo, ordenar_unicos


def parse_sslscan(raw: str) -> Dict[str, List[str]]:
    aceptados = re.findall(
        r"^(?:Accepted|Preferred)\s+(\S+)\s+\d+\s+bits?\s+([^\r\n]+)",
        raw,
        flags=re.MULTILINE | re.IGNORECASE,
    )
    protocolos = [normalizar_protocolo(proto) for proto, _ in aceptados]
    cifrados = [cifrado.strip() for _, cifrado in aceptados]

    return {
        "protocolos": ordenar_unicos(protocolos),
        "cifrados": ordenar_unicos(cifrados),
    }
