from __future__ import annotations

import re
from typing import Dict, List

from parsers.common import normalizar_protocolo, ordenar_unicos


def parse_nmap(raw: str) -> Dict[str, List[str]]:
    protocolos = []
    cifrados = []
    
    proto_re = re.compile(r"^\s*\|?\s*(TLSv1(?:\.[0-3])?|SSLv[23]):\s*$", flags=re.MULTILINE | re.IGNORECASE)
    for p in proto_re.findall(raw):
        protocolos.append(normalizar_protocolo(p))
        
    cifrado_re = re.compile(
        r"^\s*\|?\s+(TLS_[A-Z0-9_]+|ECDHE-[A-Z0-9-]+|DHE-[A-Z0-9-]+|AES[0-9]+-[A-Z0-9-]+|CHACHA20-[A-Z0-9-]+)(?:\s|$)",
        flags=re.MULTILINE | re.IGNORECASE
    )
    for c in cifrado_re.findall(raw):
        cifrados.append(c.strip())

    return {
        "protocolos": ordenar_unicos(protocolos),
        "cifrados": ordenar_unicos(cifrados),
    }
