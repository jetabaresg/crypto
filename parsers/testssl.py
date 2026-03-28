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
    
    cifrados = []
    # Testssl cipher lines are usually indented and look like:
    # " xc02f   ECDHE-RSA-AES128-GCM-SHA256" or " TLS 1.2   TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    # or "      TLS_RSA_WITH_AES_128_GCM_SHA256"
    cifrado_re = re.compile(
        r"^\s*(?:x[0-9a-fA-F]+\s+|TLS[ \t]+\d\.\d[ \t]+)?(?:[a-zA-Z0-9_\-.]+[ \t]+)?(TLS_[A-Z0-9_]+|ECDHE-[A-Z0-9-]+|DHE-[A-Z0-9-]+|AES[0-9]+-[A-Z0-9-]+|CHACHA20-[A-Z0-9-]+)",
        flags=re.IGNORECASE
    )
    for linea in raw.splitlines():
        match = cifrado_re.search(linea)
        if match:
            lower_line = linea.lower()
            if not any(x in lower_line for x in ("cve", "vulnerable", "sweet32", "drown", "logjam", "freak", "poodle", "not offered", "not supported", "failed")):
                cifrados.append(match.group(1).upper().replace("Tls_", "TLS_"))

    return {
        "protocolos": protocolos,
        "cifrados": ordenar_unicos(cifrados),
    }
