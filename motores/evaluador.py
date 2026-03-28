from __future__ import annotations

from typing import Any, Dict, List

from motores.recomendador_ia import generar_recomendaciones_ia


_PESOS = {
    "critical": 40,
    "high": 25,
    "medium": 15,
    "low": 8,
}
_FUENTES = ("nmap", "testssl", "sslscan", "openssl")
_PROTOCOLS_INSEGUROS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
_MARCAS_CIFRADO_DEBIL = ("RC4", "3DES", "DES", "MD5", "NULL", "EXPORT")


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

    resultados_validos = _resultados_validos(resultados)
    protocolos, cifrados = _agrupar_protocolos_y_cifrados(resultados_validos)

    inseguros_proto = sorted(p for p in protocolos if p in _PROTOCOLS_INSEGUROS)
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
        if any(marca in c.upper() for marca in _MARCAS_CIFRADO_DEBIL)
        and _cifrado_con_evidencia_fuerte(c, resultados_validos)
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

    score_base = _calcular_score_base(hallazgos)
    herramientas_validas, herramientas_invalidas, herramientas_total = _resumen_herramientas(resultados)
    score = _calcular_score_final(score_base, herramientas_invalidas, herramientas_total)
    riesgo = _clasificar_riesgo(score)
    recomendaciones_base = _consolidar_recomendaciones(hallazgos)
    recomendaciones, recomendaciones_fuente = _recomendaciones_con_ia(
        resultados=resultados,
        hallazgos=hallazgos,
        score=score,
        riesgo=riesgo,
        protocolos=sorted(protocolos),
        recomendaciones_fallback=recomendaciones_base,
    )
    prueba_completa = herramientas_validas == herramientas_total
    estado_prueba = (
        "Prueba realizada correctamente"
        if prueba_completa
        else "Prueba parcial: faltan herramientas o alguna no respondio"
    )
    penalizacion_cobertura = score_base - score

    return {
        "score": score,
        "score_base": score_base,
        "penalizacion_cobertura": penalizacion_cobertura,
        "riesgo": riesgo,
        "protocolos_detectados": sorted(protocolos),
        "hallazgos": hallazgos,
        "recomendaciones": recomendaciones,
        "recomendaciones_fuente": recomendaciones_fuente,
        "herramientas_ok": herramientas_validas,
        "herramientas_validas": herramientas_validas,
        "herramientas_invalidas": herramientas_invalidas,
        "herramientas_total": herramientas_total,
        "prueba_completa": prueba_completa,
        "estado_prueba": estado_prueba,
    }


def _agrupar_protocolos_y_cifrados(resultados: Dict[str, Dict[str, Any]]) -> tuple[set[str], set[str]]:
    protocolos: set[str] = set()
    cifrados: set[str] = set()

    for fuente in _FUENTES:
        metadata = resultados.get(fuente, {}).get("metadata", {})
        if not (metadata.get("disponible", False) and metadata.get("returncode") == 0):
            continue
        parsed = resultados.get(fuente, {}).get("parsed", {})
        protocolos.update(parsed.get("protocolos", []))
        cifrados.update(parsed.get("cifrados", []))

    return protocolos, cifrados


def _resultados_validos(resultados: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    validos: Dict[str, Dict[str, Any]] = {}
    for fuente in _FUENTES:
        data = resultados.get(fuente, {})
        metadata = data.get("metadata", {})
        if metadata.get("disponible", False) and metadata.get("returncode") == 0:
            validos[fuente] = data
    return validos


def _cifrado_con_evidencia_fuerte(cifrado: str, resultados_validos: Dict[str, Dict[str, Any]]) -> bool:
    # Priorizamos evidencia de herramientas enfocadas en cifrados.
    fuentes_fuertes = ("sslscan", "testssl")
    for fuente in fuentes_fuertes:
        parsed = resultados_validos.get(fuente, {}).get("parsed", {})
        if cifrado in parsed.get("cifrados", []):
            return True
    return False


def _calcular_score_base(hallazgos: List[Dict[str, str]]) -> int:
    score = 100
    for h in hallazgos:
        score -= _PESOS.get(h["severidad"], 0)
    return max(0, score)


def _calcular_score_final(score_base: int, herramientas_invalidas: int, herramientas_total: int) -> int:
    # Penalizacion por cobertura: maximo 40 puntos menos cuando no hay evidencia tecnica.
    if herramientas_total <= 0:
        return score_base
    fraccion_invalida = herramientas_invalidas / herramientas_total
    penalizacion = round(40 * fraccion_invalida)
    return max(0, score_base - penalizacion)


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


def _recomendaciones_con_ia(
    resultados: Dict[str, Dict[str, Any]],
    hallazgos: List[Dict[str, str]],
    score: int,
    riesgo: str,
    protocolos: List[str],
    recomendaciones_fallback: List[str],
) -> tuple[List[str], str]:
    estado_herramientas = {}
    for nombre, data in resultados.items():
        metadata = data.get("metadata", {})
        parsed = data.get("parsed", {})
        estado_herramientas[nombre] = {
            "disponible": metadata.get("disponible", False),
            "returncode": metadata.get("returncode"),
            "stderr": metadata.get("stderr", ""),
            "protocolos": parsed.get("protocolos", []),
            "cifrados_count": len(parsed.get("cifrados", [])),
        }

    analisis = {
        "score": score,
        "riesgo": riesgo,
        "protocolos_detectados": protocolos,
        "hallazgos": hallazgos,
        "herramientas": estado_herramientas,
    }

    recomendaciones_ia = generar_recomendaciones_ia(analisis)
    if recomendaciones_ia:
        return recomendaciones_ia, "ia"
    return recomendaciones_fallback, "fallback"


def _resumen_herramientas(resultados: Dict[str, Dict[str, Any]]) -> tuple[int, int, int]:
    herramientas_validas = 0
    herramientas_invalidas = 0
    for fuente in _FUENTES:
        metadata = resultados.get(fuente, {}).get("metadata", {})
        disponible = metadata.get("disponible", False)
        returncode = metadata.get("returncode")
        if disponible and returncode == 0:
            herramientas_validas += 1
        else:
            herramientas_invalidas += 1
    return herramientas_validas, herramientas_invalidas, len(_FUENTES)