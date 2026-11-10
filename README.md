# cisa-kev

Buscador CLI del catálogo CISA KEV sobre la API https://kevin.gtfkd.com/ (solo stdlib de Python 3).

```bash
./kev.py search log4j                          # términos AND sobre CVE/vendor/producto/nombre/descripción
./kev.py search --vendor cisco --ransomware --severity critical --since 2025-01-01
./kev.py search --days 7                       # agregados en los últimos 7 días
./kev.py show CVE-2021-44228 [--details] [--json]   # --details agrega /vuln/{cve}
./kev.py check CVE-2021-44228 CVE-2024-0001    # exit 1 si alguno no está en KEV
./kev.py stats | sync | clear
./kev.py --refresh search ...                  # fuerza refresco del cache
```

## Cache
SQLite `kev_cache.db`: catálogo completo (18 requests, 100/página) con TTL 3 h; detalle `/vuln/{cve}` con TTL 24 h.
Las búsquedas son locales. Límite de la API: 2 req/s por IP, bloqueo de 1 h si se excede (el script espacia 0.8 s y aborta ante 429).
Si la red falla, usa el cache vencido con un aviso.

## Web (`serve`)
```bash
USERS='ana:secreto,bob:otra' ./kev.py serve --port 8080      # 127.0.0.1 por defecto
```
Página con búsqueda en `/`, API JSON en `/api/search?q=&vendor=&product=&severity=&ransomware=1&days=&since=&limit=`,
`/api/cve/{cve}` y `/healthz`. HTTP Basic Auth con `USERS=user:pass,user2:pass2` (el password puede tener `:` pero no `,`).
Si `USERS` está vacío o no existe, el servidor corre **sin autenticación**. Basic auth no cifra: publicarlo solo detrás de TLS.

## Docker
```bash
cp .env.example .env   # editar USERS=user:pass,user2:pass2 (compose y `serve` lo leen solos)
docker compose up -d --build kev          # web en http://127.0.0.1:8080 (la primera vez sincroniza ~15 s antes de escuchar)
docker compose run --rm cli search log4j  # CLI, comparte el cache (volumen kev-data)
docker compose run --rm cli show CVE-2021-44228 --details
```

## Actualización incremental
- `serve` corre un hilo que actualiza cada `KEV_REFRESH_HOURS` (24; `0` = off) con `GET /kev/recent?days=N` + un chequeo de conteo con `/kev` → ~2 requests/día. Las requests web nunca esperan un sync.
- Cada `KEV_FULL_REFRESH_DAYS` (7) hace un resync completo (18 requests), porque `/kev/recent` solo trae entradas *nuevas* y no ve cambios en viejas (p. ej. flag de ransomware). También lo hace si el conteo no coincide con la API o si el cache tiene >90 días.
- Si falla (red/429) conserva el cache y reintenta en 1 h.
- Manual: `./kev.py update` (incremental) o `./kev.py sync` (completo); en Docker: `docker compose run --rm cli update`.

La severidad se colorea (CRITICAL/HIGH rojo, MEDIUM naranja, LOW amarillo) en la web y en el CLI; el CLI no colorea si la salida no es una terminal o si está definida `NO_COLOR`.
