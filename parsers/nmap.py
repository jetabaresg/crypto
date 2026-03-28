from __future__ import annotations

from typing import Dict, List

from parsers.common import extraer_cifrados, extraer_protocolos


def parse_nmap(raw: str) -> Dict[str, List[str]]:
    return {
        "protocolos": extraer_protocolos(raw),
        "cifrados": extraer_cifrados(raw),
    }
