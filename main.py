from __future__ import annotations

import argparse
import ipaddress
import re
from pathlib import Path

from motores.analizadorTLS import analizar_tls
from motores.evaluador import evaluar_resultados
from report.generator import generar_reporte_html


_DOMINIO_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)


def _slug_objetivo(valor: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", valor)


def _resolver_salida(base_salida: Path, objetivo: str, varios_objetivos: bool) -> Path:
    if not varios_objetivos:
        return base_salida

    stem = base_salida.stem or "reporte_tls"
    suffix = base_salida.suffix or ".html"
    return base_salida.with_name(f"{stem}_{_slug_objetivo(objetivo)}{suffix}")


def _validar_objetivo(valor: str) -> str:
    objetivo = valor.strip()
    if not objetivo:
        raise argparse.ArgumentTypeError("El objetivo no puede estar vacio.")

    try:
        ipaddress.ip_address(objetivo)
        return objetivo
    except ValueError:
        if _DOMINIO_RE.match(objetivo):
            return objetivo

    raise argparse.ArgumentTypeError(
        "Objetivo invalido. Usa un dominio valido (ej: ejemplo.com) o una IP."
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Auditor TLS simple (Python + Bash) con reporte HTML manual"
    )
    parser.add_argument(
        "objetivos",
        nargs="+",
        type=_validar_objetivo,
        help="Uno o varios dominios/IP a analizar",
    )
    parser.add_argument("--puerto", type=int, default=443, help="Puerto TLS (default: 443)")
    parser.add_argument(
        "--salida",
        default="reporte_tls.html",
        help=(
            "Archivo HTML de salida base (default: reporte_tls.html). "
            "Si se pasan varios objetivos, se creara un archivo por objetivo."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=25,
        help="Timeout por herramienta en segundos (default: 25)",
    )
    return parser


def main() -> None:
    args = _parser().parse_args()
    base_salida = Path(args.salida)
    varios_objetivos = len(args.objetivos) > 1

    for objetivo in args.objetivos:
        print(f"[+] Objetivo: {objetivo}:{args.puerto}")
        resultados = analizar_tls(objetivo, args.puerto, args.timeout)
        evaluacion = evaluar_resultados(resultados)

        salida = _resolver_salida(base_salida, objetivo, varios_objetivos)
        generar_reporte_html(salida, objetivo, args.puerto, resultados, evaluacion)

        fuente_recomendaciones = evaluacion.get("recomendaciones_fuente", "fallback")
        if fuente_recomendaciones == "ia":
            print("[+] Recomendaciones: IA activa")
        else:
            print("[+] Recomendaciones: fallback local")
        herramientas_ok = evaluacion.get("herramientas_ok", 0)
        herramientas_total = evaluacion.get("herramientas_total", 4)
        print(
            f"[+] Riesgo: {evaluacion['riesgo']} | "
            f"Score: {evaluacion['score']}/100 ({herramientas_ok}/{herramientas_total} herramientas)"
        )
        print(f"[+] Estado de prueba: {evaluacion.get('estado_prueba', 'Sin estado')}")
        print(f"[+] Reporte generado: {salida.resolve()}")


if __name__ == "__main__":
    main()
