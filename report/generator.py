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
    hallazgos_html = "".join(_fila_hallazgo(h) for h in evaluacion["hallazgos"])
    if not hallazgos_html:
        hallazgos_html = '<tr><td colspan="4">No se detectaron hallazgos con las reglas actuales.</td></tr>'

    herramientas_html = "".join(_fila_herramienta(nombre, data) for nombre, data in resultados.items())
    recomendaciones = "".join(f"<li>{escape(r)}</li>" for r in evaluacion["recomendaciones"])

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
		.critical, .high {{ color: #a32020; font-weight: bold; }}
		.medium {{ color: #8d5a00; font-weight: bold; }}
		.low {{ color: #0a7a49; font-weight: bold; }}
	</style>
</head>
<body>
	<div class=\"container\">
		<section class=\"card\">
			<h1>Reporte de Seguridad TLS</h1>
			<p><strong>Objetivo:</strong> {escape(objetivo)}:{puerto}</p>
			<p><strong>Score:</strong> {evaluacion['score']}/100</p>
			<p><strong>Riesgo:</strong> <span class=\"pill\">{escape(evaluacion['riesgo'])}</span></p>
			<p><strong>Protocolos detectados:</strong> {escape(', '.join(evaluacion['protocolos_detectados']) or '-')}</p>
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
