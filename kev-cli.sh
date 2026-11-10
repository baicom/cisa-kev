#!/bin/sh
# Ejecuta kev.py dentro de Docker: ./kev-cli.sh
cd "$(dirname "$0")" && exec docker compose run --rm -T cli "$@"
