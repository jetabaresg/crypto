from __future__ import annotations

from typing import Any, Dict, List


_PESOS = {
    "critical": 40,
    "high": 25,
    "medium": 15,
    "low": 8,
}


def _hallazgo(
    severidad: str,
    titulo: str,
    detalle: str,
    recomendacion: str,
) -> Dict[str, str]:
    return {
        "severidad": severidad,
        "titulo": titulo,
        "detalle": detalle,
        "recomendacion": recomendacion,
    }


def evaluar_resultados(resultados: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    hallazgos: List[Dict[str, str]] = []

    protocolos = set()
    cifrados = set()

    for fuente in ("nmap", "testssl", "sslscan", "openssl"):
        parsed = resultados.get(fuente, {}).get("parsed", {})
        protocolos.update(parsed.get("protocolos", []))
        cifrados.update(parsed.get("cifrados", []))

    inseguros_proto = sorted(
        p for p in protocolos if p in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
    )
    if inseguros_proto:
        hallazgos.append(
            _hallazgo(
                "high",
                "Versiones TLS/SSL inseguras habilitadas",
                "Se detectaron versiones obsoletas: " + ", ".join(inseguros_proto),
                "Deshabilitar SSLv2/SSLv3/TLS 1.0/TLS 1.1 y permitir solo TLS 1.2 y TLS 1.3.",
            )
        )

    debiles = sorted(
        c
        for c in cifrados
        if any(marca in c.upper() for marca in ("RC4", "3DES", "DES", "MD5", "NULL", "EXPORT"))
    )
    if debiles:
        hallazgos.append(
            _hallazgo(
                "high",
                "Cifrados debiles detectados",
                "Se detectaron suites debiles: " + ", ".join(debiles[:8]),
                "Eliminar suites debiles y priorizar AES-GCM o CHACHA20 con ECDHE.",
            )
        )

    certificado = resultados.get("openssl", {}).get("parsed", {}).get("certificado", {})
    if certificado.get("expirado"):
        hallazgos.append(
            _hallazgo(
                "critical",
                "Certificado expirado",
                "El certificado remoto aparece expirado segun notAfter.",
                "Renovar el certificado inmediatamente e instalar la cadena completa.",
            )
        )

    score = _calcular_score(hallazgos)
    riesgo = _clasificar_riesgo(score)
    recomendaciones = _consolidar_recomendaciones(hallazgos)

    return {
        "score": score,
        "riesgo": riesgo,
        "protocolos_detectados": sorted(protocolos),
        "hallazgos": hallazgos,
        "recomendaciones": recomendaciones,
    }


def _calcular_score(hallazgos: List[Dict[str, str]]) -> int:
    score = 100
    for h in hallazgos:
        score -= _PESOS.get(h["severidad"], 0)
    return max(0, score)


def _clasificar_riesgo(score: int) -> str:
    if score >= 90:
        return "Bajo"
    if score >= 70:
        return "Medio"
    if score >= 40:
        return "Alto"
    return "Critico"


def _consolidar_recomendaciones(hallazgos: List[Dict[str, str]]) -> List[str]:
    base = [
        "Habilitar solamente TLS 1.2 y TLS 1.3.",
        "Deshabilitar suites de cifrado obsoletas o debiles.",
        "Mantener OpenSSL, servidor web y librerias criptograficas actualizadas.",
        "Aplicar HSTS y revisar configuraciones periodicamente.",
    ]
    extras = [h["recomendacion"] for h in hallazgos]

    unicas: List[str] = []
    for rec in base + extras:
        if rec not in unicas:
            unicas.append(rec)
    return unicas