from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict

from parsers.common import extraer_protocolos


_FORMATOS = ["%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"]


def parse_openssl(raw: str) -> Dict[str, Any]:
    not_after = _extraer_not_after(raw)
    fecha = _parse_fecha(not_after) if not_after else None
    expirado = bool(fecha and fecha < datetime.now(tz=timezone.utc))
    return {
        "protocolos": extraer_protocolos(raw),
        "cifrados": [],
        "certificado": {
            "not_after": not_after,
            "expirado": expirado,
        },
    }


def _extraer_not_after(raw: str) -> str | None:
    match = re.search(r"notAfter=(.+)", raw)
    if match:
        return match.group(1).strip()

    match = re.search(r"Not After\s*:\s*(.+)", raw)
    if match:
        return match.group(1).strip()

    return None


def _parse_fecha(value: str) -> datetime | None:
    for fmt in _FORMATOS:
        try:
            dt = datetime.strptime(value, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None
