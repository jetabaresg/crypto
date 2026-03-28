#!/usr/bin/env bash
set -u

TARGET="${1:-}"
PORT="${2:-443}"

if [ -z "$TARGET" ]; then
  echo "Uso: openssl_probe.sh <dominio_o_ip> [puerto]" >&2
  exit 2
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl no esta instalado" >&2
  exit 127
fi

# Envia una linea vacia para cerrar la sesion cuando el servidor responde.
printf '\n' | openssl s_client -connect "${TARGET}:${PORT}" -servername "$TARGET" 2>/dev/null
