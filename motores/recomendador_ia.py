from __future__ import annotations

import json
import os
from typing import Any, Dict, List
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen


def generar_recomendaciones_ia(analisis: Dict[str, Any], timeout: int = 20) -> List[str] | None:
    # La función retorna una lista de recomendaciones generadas por IA o None si no se pudo obtener recomendaciones.
    api_url = os.getenv("AI_RECOMMENDER_API_URL", "https://openrouter.ai/api/v1/chat/completions").strip()
    api_key = os.getenv("AI_RECOMMENDER_API_KEY", "").strip() or os.getenv("OPENROUTER_API_KEY", "").strip()
    model = os.getenv("AI_RECOMMENDER_MODEL", "openai/gpt-4o-mini").strip()

    if not api_key:
        return None

    prompt = _construir_prompt(analisis)
    payload = _build_payload(model, prompt)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {api_key}",
        "HTTP-Referer": os.getenv("OPENROUTER_REFERER", "https://localhost"),
        "X-Title": os.getenv("OPENROUTER_APP_NAME", "CryptoHackaton"),
    }

    request = Request(api_url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")

    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError, OSError):
        return None

    return _parsear_recomendaciones(body)


def _build_payload(model: str, prompt: str) -> Dict[str, Any]:
    return {
        "model": model,
        "temperature": 0.2,
        "messages": [
            {
                "role": "system",
                "content": (
                    "Eres un especialista en seguridad TLS. "
                    "Devuelve un JSON valido con la forma exacta: "
                    '{"recommendations": ["...", "..."]}. '
                    "Cada recomendacion debe ser accionable, concreta y en espanol."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "response_format": {"type": "json_object"},
    }


def _construir_prompt(analisis: Dict[str, Any]) -> str:
    return (
        "Genera 5 a 8 recomendaciones priorizadas para mejorar seguridad TLS.\\n"
        "No inventes hallazgos. Basate solo en los datos entregados.\\n\\n"
        "ANALISIS JSON:\\n"
        f"{json.dumps(analisis, ensure_ascii=False, indent=2)}"
    )


def _parsear_recomendaciones(body: str) -> List[str] | None:
    # Caso 1: la API ya devuelve {'recommendations': [...]}.
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None

    recomendaciones = data.get("recommendations")
    if isinstance(recomendaciones, list):
        return _normalizar_lista(recomendaciones)

    # Caso 2: formato tipo chat completions de OpenAI-compatible.
    contenido = (
        data.get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
        .strip()
    )
    if not contenido:
        return None

    # Intento A: el contenido es JSON.
    try:
        contenido_json = json.loads(contenido)
        recomendaciones = contenido_json.get("recommendations")
        if isinstance(recomendaciones, list):
            return _normalizar_lista(recomendaciones)
    except json.JSONDecodeError:
        pass

    # Intento B: lista en texto (lineas con guiones o numeracion).
    lineas = []
    for linea in contenido.splitlines():
        txt = linea.strip().lstrip("-*").strip()
        if txt and txt[0].isdigit() and "." in txt[:4]:
            txt = txt.split(".", 1)[1].strip()
        if txt:
            lineas.append(txt)

    return _normalizar_lista(lineas)


def _normalizar_lista(items: List[Any]) -> List[str] | None:
    unicas: List[str] = []
    for item in items:
        if not isinstance(item, str):
            continue
        txt = " ".join(item.split()).strip()
        if txt and txt not in unicas:
            unicas.append(txt)

    if not unicas:
        return None
    return unicas[:8]
