from __future__ import annotations

import re
from typing import Dict, List

from parsers.common import extraer_protocolos, ordenar_unicos


def parse_testssl(raw: str) -> Dict[str, List[str]]:
    cifrados = re.findall(
        r"\b(TLS_[A-Z0-9_]+|ECDHE-[A-Z0-9-]+|DHE-[A-Z0-9-]+|AES[0-9]+-[A-Z0-9-]+|CHACHA20-[A-Z0-9-]+)\b",
        raw,
    )
    return {
        "protocolos": extraer_protocolos(raw),
        "cifrados": ordenar_unicos(cifrados),
    }
