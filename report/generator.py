from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any, Dict


def generar_reporte_html(
    salida: Path,
    objetivo: str,
    puerto: int,
    resultados: Dict[str, Dict[str, Any]],
    evaluacion: Dict[str, Any],
) -> None:
    resumen_severidad = _contar_severidades(evaluacion["hallazgos"])
    hallazgos_html = "".join(_fila_hallazgo(h) for h in evaluacion["hallazgos"])
    if not hallazgos_html:
        hallazgos_html = '<tr><td colspan="4">No se detectaron hallazgos con las reglas actuales.</td></tr>'

    herramientas_html = "".join(_fila_herramienta(nombre, data) for nombre, data in resultados.items())
    recomendaciones = "".join(f"<li>{escape(r)}</li>" for r in evaluacion["recomendaciones"])
    herramientas_ok = evaluacion.get("herramientas_validas", evaluacion.get("herramientas_ok", 0))
    herramientas_invalidas = evaluacion.get("herramientas_invalidas", 0)
    herramientas_total = evaluacion.get("herramientas_total", 4)
    estado_prueba = evaluacion.get("estado_prueba", "Sin estado")

    html = f"""<!doctype html>
<html lang=\"es\">
<head>
    <meta charset=\"utf-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
    <title>Reporte TLS - {escape(objetivo)}</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f6f8fb; color: #15202b; margin: 0; }}
        .container {{ max-width: 1000px; margin: 28px auto; padding: 0 16px; }}
        .card {{ background: #fff; border: 1px solid #d8e0eb; border-radius: 10px; padding: 16px; margin-bottom: 14px; }}
        h1, h2 {{ margin-top: 0; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ border-bottom: 1px solid #e4eaf2; padding: 9px 7px; text-align: left; vertical-align: top; font-size: 14px; }}
        .pill {{ display: inline-block; border-radius: 999px; padding: 4px 10px; background: #e8efff; }}
        .critical {{ color: #a32020; font-weight: bold; }}
        .high {{ color: #b45309; font-weight: bold; }}
        .medium {{ color: #8d5a00; font-weight: bold; }}
        .low {{ color: #0a7a49; font-weight: bold; }}
        .sev-grid {{ display: grid; grid-template-columns: repeat(4, minmax(110px, 1fr)); gap: 10px; }}
        .sev-item {{ border: 1px solid #e4eaf2; border-radius: 8px; padding: 10px; text-align: center; }}
        .sev-num {{ display: block; font-size: 24px; font-weight: 700; line-height: 1.1; }}
    </style>
</head>
<body>
    <div class=\"container\">
        <section class=\"card\">
            <h1>Reporte de Seguridad TLS</h1>
            <p><strong>Objetivo:</strong> {escape(objetivo)}:{puerto}</p>
            <p><strong>Score:</strong> {evaluacion['score']}/100 ({herramientas_ok}/{herramientas_total} validas, {herramientas_invalidas} invalidas)</p>
            <p><strong>Estado de prueba:</strong> {escape(estado_prueba)}</p>
            <p><strong>Riesgo:</strong> <span class=\"pill\">{escape(evaluacion['riesgo'])}</span></p>
            <p><strong>Protocolos detectados:</strong> {escape(', '.join(evaluacion['protocolos_detectados']) or '-')}</p>
        </section>

        <section class=\"card\">
            <h2>Resumen de Severidades</h2>
            <div class=\"sev-grid\">
                <div class=\"sev-item\"><span class=\"sev-num critical\">{resumen_severidad['critical']}</span>Critical</div>
                <div class=\"sev-item\"><span class=\"sev-num high\">{resumen_severidad['high']}</span>High</div>
                <div class=\"sev-item\"><span class=\"sev-num medium\">{resumen_severidad['medium']}</span>Medium</div>
                <div class=\"sev-item\"><span class=\"sev-num low\">{resumen_severidad['low']}</span>Low</div>
            </div>
        </section>

        <section class=\"card\">
            <h2>Hallazgos</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severidad</th>
                        <th>Titulo</th>
                        <th>Detalle</th>
                        <th>Recomendacion</th>
                    </tr>
                </thead>
                <tbody>
                    {hallazgos_html}
                </tbody>
            </table>
        </section>

        <section class=\"card\">
            <h2>Estado de Herramientas</h2>
            <table>
                <thead>
                    <tr>
                        <th>Herramienta</th>
                        <th>Estado</th>
                        <th>Protocolos</th>
                        <th>Cifrados</th>
                        <th>Detalle</th>
                    </tr>
                </thead>
                <tbody>
                    {herramientas_html}
                </tbody>
            </table>
        </section>

        <section class=\"card\">
            <h2>Recomendaciones</h2>
            <ul>{recomendaciones}</ul>
        </section>
    </div>
</body>
</html>
"""
    salida.write_text(html, encoding="utf-8")


def _fila_hallazgo(hallazgo: Dict[str, str]) -> str:
    sev = escape(hallazgo["severidad"])
    return (
        "<tr>"
        f"<td class=\"{sev}\">{sev}</td>"
        f"<td>{escape(hallazgo['titulo'])}</td>"
        f"<td>{escape(hallazgo['detalle'])}</td>"
        f"<td>{escape(hallazgo['recomendacion'])}</td>"
        "</tr>"
    )


def _contar_severidades(hallazgos: list[Dict[str, str]]) -> Dict[str, int]:
    conteo = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for hallazgo in hallazgos:
        severidad = hallazgo.get("severidad", "").strip().lower()
        if severidad in conteo:
            conteo[severidad] += 1
    return conteo


def _fila_herramienta(nombre: str, data: Dict[str, Any]) -> str:
    meta = data.get("metadata", {})
    parsed = data.get("parsed", {})
    disponible = meta.get("disponible", False)
    code = meta.get("returncode")
    detalle_error = meta.get("stderr", "") or "-"

    if disponible and code == 0:
        estado = "OK"
    elif not disponible:
        estado = "No disponible"
    else:
        estado = f"Error ({code})"

    protos = ", ".join(parsed.get("protocolos", [])) or "-"
    cifrados = str(len(parsed.get("cifrados", [])))
    return (
        "<tr>"
        f"<td>{escape(nombre)}</td>"
        f"<td>{escape(estado)}</td>"
        f"<td>{escape(protos)}</td>"
        f"<td>{escape(cifrados)}</td>"
        f"<td>{escape(detalle_error)}</td>"
        "</tr>"
    )
