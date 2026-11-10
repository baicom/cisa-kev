#!/usr/bin/env python3
"""Buscador de CVEs del catalogo CISA KEV, usando la API https://kevin.gtfkd.com/

Cache local en SQLite (kev_cache.db junto a este script):
  - Catalogo KEV completo (se baja paginado, 100 por pagina) con TTL de 3h
    (la API misma puede estar atrasada hasta 3h).
  - Detalle /vuln/{cve} cacheado por CVE (TTL 24h).
Busquedas, filtros y estadisticas se resuelven localmente sobre el cache, asi se
respeta el limite de la API (2 req/s por IP; bloqueo de 1 hora si se excede).
"""
import argparse, json, os, re, sqlite3, sys, time
import urllib.error, urllib.parse, urllib.request
from datetime import date, timedelta

BASE = "https://kevin.gtfkd.com"
DB = os.environ.get("KEV_DB") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "kev_cache.db")
KEV_TTL = 3 * 3600
VULN_TTL = 24 * 3600
MIN_INTERVAL = 0.8  # segundos entre requests (limite API: 2 req/s)
_last = 0.0


def http_get(path, params=None):
    global _last
    wait = MIN_INTERVAL - (time.time() - _last)
    if wait > 0:
        time.sleep(wait)
    url = BASE + path + ("?" + urllib.parse.urlencode(params) if params else "")
    req = urllib.request.Request(url, headers={"User-Agent": "cisa-kev-cli/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        if e.code == 429:
            sys.exit("Rate limit de la API (429). NO reintentar: bloqueo de 1h. Espera y usa el cache.")
        raise
    finally:
        _last = time.time()


def db():
    c = sqlite3.connect(DB, timeout=30)
    c.execute("PRAGMA journal_mode=WAL")
    c.row_factory = sqlite3.Row
    c.executescript("""
    CREATE TABLE IF NOT EXISTS kev(cve TEXT PRIMARY KEY, vendor TEXT, product TEXT, name TEXT,
        added TEXT, due TEXT, ransomware TEXT, score REAL, severity TEXT, raw TEXT);
    CREATE TABLE IF NOT EXISTS vuln(cve TEXT PRIMARY KEY, fetched REAL, raw TEXT);
    CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
    """)
    return c


def meta(c, k, v=None):
    if v is None:
        r = c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r[0] if r else None
    c.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (k, str(v)))


def scalar(x, want):
    """La API a veces devuelve estructuras anidadas; aplanar a escalar o None."""
    if isinstance(x, dict):
        for k in ("score", "value", "baseScore", "baseSeverity", "severity"):
            if k in x:
                return scalar(x[k], want)
        return None
    if isinstance(x, list):
        return scalar(x[0], want) if x else None
    if want == "num":
        try:
            return float(x)
        except (TypeError, ValueError):
            return None
    return None if x is None else str(x)


def best_nvd(v):
    """Primer nvdData con score; devuelve dict con baseScore/baseSeverity ya normalizados."""
    nd = v.get("nvdData")
    nd = nd if isinstance(nd, list) else [nd]
    out = {"baseScore": None, "baseSeverity": None}
    for n in nd:
        if not isinstance(n, dict):
            continue
        sc = scalar(n.get("baseScore"), "num")
        if sc is not None:
            return {"baseScore": sc, "baseSeverity": scalar(n.get("baseSeverity"), "str")}
    return out


def fetch_all(quiet=False):
    rows, page, pages = [], 1, 1
    while page <= pages:
        d = http_get("/kev", {"page": page, "per_page": 100})
        if not isinstance(d, dict) or "vulnerabilities" not in d:
            raise RuntimeError(f"respuesta inesperada de la API: {str(d)[:100]}")
        pages = d["total_pages"]
        rows += d["vulnerabilities"]
        if not quiet:
            print(f"\r  sync {page}/{pages}", end="", file=sys.stderr, flush=True)
        page += 1
    if not quiet:
        print(file=sys.stderr)
    return rows


def upsert_rows(c, rows):
    for v in rows:
        nvd = best_nvd(v)
        c.execute("INSERT OR REPLACE INTO kev VALUES(?,?,?,?,?,?,?,?,?,?)", (
            v["cveID"], v.get("vendorProject"), v.get("product"), v.get("vulnerabilityName"),
            v.get("dateAdded"), v.get("dueDate"), scalar(v.get("knownRansomwareCampaignUse"), "str") or "Unknown",
            nvd.get("baseScore"), nvd.get("baseSeverity"), json.dumps(v)))


def sync(c, quiet=False):
    """Resync COMPLETO. Solo reemplaza el cache si la descarga completa funciono."""
    rows = fetch_all(quiet)
    with c:
        c.execute("DELETE FROM kev")
        upsert_rows(c, rows)
        meta(c, "synced", time.time())
        meta(c, "full_synced", time.time())
    return len(rows)


MAX_RECENT_DAYS = 90  # la API acepta ~100 como maximo (180 -> error)


def count_local(c):
    return c.execute("SELECT COUNT(*) FROM kev").fetchone()[0]


def update_incremental(c, quiet=False):
    """Actualizacion incremental (~2 requests). Devuelve (modo, n).
    Cae a resync completo si: cache vacio/muy viejo, toca el resync periodico
    (KEV_FULL_REFRESH_DAYS, default 7: capta cambios en entradas viejas como el
    flag de ransomware, que /kev/recent no trae) o el conteo no coincide con la API."""
    now = time.time()
    last, full = float(meta(c, "synced") or 0), float(meta(c, "full_synced") or 0)
    full_days = float(os.environ.get("KEV_FULL_REFRESH_DAYS") or 7)
    gap = int((now - last) // 86400) + 2  # margen: dateAdded tiene granularidad diaria
    if not last or not full or count_local(c) == 0 or gap > MAX_RECENT_DAYS \
            or (full_days > 0 and now - full >= full_days * 86400):
        return "full", sync(c, quiet)
    rows = http_get("/kev/recent", {"days": gap})
    if not isinstance(rows, list):
        raise RuntimeError(f"respuesta inesperada de /kev/recent: {str(rows)[:100]}")
    with c:
        upsert_rows(c, rows)
    total = (http_get("/kev", {"page": 1, "per_page": 1}) or {}).get("total_vulns")
    if total is not None and total != count_local(c):
        print(f"[aviso] conteo local {count_local(c)} != API {total}: resync completo", file=sys.stderr)
        return "full", sync(c, quiet)
    with c:
        meta(c, "synced", time.time())
    return "incremental", len(rows)


def ensure(c, force=False):
    age = time.time() - float(meta(c, "synced") or 0)
    if force or age > KEV_TTL:
        try:
            mode, n = update_incremental(c)
            print(f"Cache actualizado ({mode}): {n} CVEs", file=sys.stderr)
        except (Exception, SystemExit) as e:  # red caida: usar cache viejo si existe
            if not meta(c, "synced"):
                raise
            print(f"[aviso] no se pudo actualizar ({e}); usando cache de hace {int(age/60)} min", file=sys.stderr)


SEV_ANSI = {"CRITICAL": "1;31", "HIGH": "31", "MEDIUM": "38;5;208", "LOW": "93"}


def color_on():
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def paint(text, sev, width=0):
    """Colorea `text` segun severidad; el padding se calcula antes de agregar ANSI."""
    t = f"{text:<{width}}" if width else str(text)
    code = SEV_ANSI.get((sev or "").upper())
    return f"\033[{code}m{t}\033[0m" if code and color_on() else t


def show_rows(rows, as_json):
    if as_json:
        print(json.dumps([json.loads(r["raw"]) for r in rows], indent=2, ensure_ascii=False))
        return
    if not rows:
        print("Sin resultados.")
        return
    print(f"{'CVE':<17}{'ADDED':<11}{'SCORE':<6}{'SEV':<10}{'RANSOM':<8}{'VENDOR/PRODUCT':<36}NAME")
    for r in rows:
        vp = f"{r['vendor']}/{r['product']}"[:35]
        rw = "YES" if r["ransomware"] == "Known" else "-"
        sc = "" if r["score"] is None else r["score"]
        print(f"{r['cve']:<17}{r['added'] or '':<11}{sc!s:<6}{paint(r['severity'] or '-', r['severity'], 10)}{rw:<8}{vp:<36}{(r['name'] or '')[:60]}")
    print(f"\n{len(rows)} resultado(s)")


MAX_TERMS, MAX_LEN, MAX_DAYS = 8, 100, 3650


def like(v):
    """Patron LIKE literal: escapa % _ \\ (se usa con ESCAPE '\\') y limita el largo."""
    v = str(v)[:MAX_LEN].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{v}%"


def query_rows(c, terms=(), vendor=None, product=None, ransomware=False, severity=None,
               min_score=None, since=None, days=None, limit=25, vendor_exact=False, product_exact=False,
               offset=0, with_total=False):
    where, args = [], []
    for term in list(terms)[:MAX_TERMS]:  # todos los terminos deben aparecer (AND), en cualquier campo
        where.append("(cve LIKE ? ESCAPE '\\' OR vendor LIKE ? ESCAPE '\\' OR product LIKE ? ESCAPE '\\'"
                     " OR name LIKE ? ESCAPE '\\' OR raw LIKE ? ESCAPE '\\')")
        args += [like(term)] * 5
    if vendor and vendor_exact:
        where.append("vendor = ? COLLATE NOCASE"); args.append(str(vendor)[:MAX_LEN])
    elif vendor:
        where.append("vendor LIKE ? ESCAPE '\\'"); args.append(like(vendor))
    if product and product_exact:
        where.append("product = ? COLLATE NOCASE"); args.append(str(product)[:MAX_LEN])
    elif product:
        where.append("product LIKE ? ESCAPE '\\'"); args.append(like(product))
    if ransomware:
        where.append("ransomware='Known'")
    if severity:
        where.append("UPPER(severity)=?"); args.append(severity.upper())
    if min_score is not None:
        where.append("score>=?"); args.append(min_score)
    if since:
        where.append("added>=?"); args.append(since)
    if days and days > 0:
        where.append("added>=?"); args.append((date.today() - timedelta(days=min(days, MAX_DAYS))).isoformat())
    cond = (" WHERE " + " AND ".join(where)) if where else ""
    rows = c.execute(f"SELECT * FROM kev{cond} ORDER BY added DESC, cve DESC LIMIT ? OFFSET ?",
                     args + [limit, offset]).fetchall()
    if with_total:
        return rows, c.execute(f"SELECT COUNT(*) FROM kev{cond}", args).fetchone()[0]
    return rows


def cmd_search(a, c):
    ensure(c, a.refresh)
    show_rows(query_rows(c, a.query, a.vendor, a.product, a.ransomware, a.severity,
                         a.min_score, a.since, a.days, a.limit), a.json)


def cmd_show(a, c):
    ensure(c, a.refresh)
    cve = a.cve.upper()
    r = c.execute("SELECT * FROM kev WHERE cve=?", (cve,)).fetchone()
    if not r:
        print(f"{cve}: NO esta en el catalogo CISA KEV")
        return 1
    k = json.loads(r["raw"])
    if a.json and not a.details:
        print(json.dumps(k, indent=2, ensure_ascii=False)); return
    print(f"{cve} - {k.get('vulnerabilityName')}")
    print(f"  Vendor/Product : {k.get('vendorProject')} / {k.get('product')}")
    print(f"  Agregado       : {k.get('dateAdded')}   Vence: {k.get('dueDate')}")
    print(f"  Ransomware     : {k.get('knownRansomwareCampaignUse')}")
    print(f"  CVSS           : {r['score']} {paint(r['severity'] or '', r['severity'])}")
    print(f"  Descripcion    : {k.get('shortDescription')}")
    print(f"  Accion         : {k.get('requiredAction')}")
    if k.get("notes"):
        print(f"  Notas          : {k['notes']}")
    if k.get("githubPocs"):
        print("  PoCs GitHub    : " + ", ".join(map(str, k["githubPocs"][:5])))
    if a.details:
        v = get_vuln(c, cve, a.refresh)
        print("\n--- /vuln (cache 24h) ---")
        print(json.dumps(v, indent=2, ensure_ascii=False)[:6000] if v else "sin datos")


def get_vuln(c, cve, refresh=False):
    r = c.execute("SELECT * FROM vuln WHERE cve=?", (cve,)).fetchone()
    if r and not refresh and time.time() - r["fetched"] < VULN_TTL:
        return json.loads(r["raw"])
    d = http_get(f"/vuln/{cve}")
    if d is not None:
        with c:
            c.execute("INSERT OR REPLACE INTO vuln VALUES(?,?,?)", (cve, time.time(), json.dumps(d)))
    return d


def cmd_check(a, c):
    ensure(c, a.refresh)
    rc = 0
    for cve in a.cves:
        hit = c.execute("SELECT 1 FROM kev WHERE cve=?", (cve.upper(),)).fetchone()
        print(f"{cve.upper()}: {'EN KEV' if hit else 'no esta en KEV'}")
        rc |= 0 if hit else 1
    return rc


def cmd_stats(a, c):
    ensure(c, a.refresh)
    n = c.execute("SELECT COUNT(*) FROM kev").fetchone()[0]
    ts = float(meta(c, "synced") or 0)
    print(f"Total KEV: {n}   (cache: {time.strftime('%Y-%m-%d %H:%M', time.localtime(ts))})")
    print(f"Ransomware conocido: {c.execute(chr(83)+'ELECT COUNT(*) FROM kev WHERE ransomware=?', ('Known',)).fetchone()[0]}")
    print("Top vendors:")
    for r in c.execute("SELECT vendor, COUNT(*) n FROM kev GROUP BY vendor ORDER BY n DESC LIMIT 10"):
        print(f"  {r['n']:>4}  {r['vendor']}")


PAGE = """<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>CISA KEV</title>
<style>
:root{--bg:#f7f8f9;--fg:#111827;--mut:#5c6570;--line:#e3e5e8;--card:#fff;--acc:#b42318;--red:#b42318;--org:#b45309;--yel:#8a6a00}
@media(prefers-color-scheme:dark){:root{--bg:#111418;--fg:#e8eaed;--mut:#98a2b3;--line:#2a2f36;--card:#1a1e24;--acc:#f97066;--red:#f97066;--org:#fb923c;--yel:#facc15}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:20px 16px}
form{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}
input,select,button{padding:7px 9px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg);font:inherit}
input[name=q]{flex:1 1 260px}button{cursor:pointer}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line)}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:13px}tr.r{cursor:pointer}tr.r:hover{background:var(--bg)}
.ran{color:var(--acc);font-weight:600}.mut{color:var(--mut)}
.det td{background:var(--bg);word-break:break-word;padding:14px 16px}
.dg{display:grid;grid-template-columns:150px 1fr;gap:10px 16px;max-width:900px;line-height:1.5}
.dl{color:var(--mut);font-weight:600;font-size:13px;padding-top:1px}
.dg ul{margin:0;padding-left:18px}.dg li{margin:0 0 5px}.dg a{color:var(--acc)}
@media(max-width:600px){.dg{grid-template-columns:1fr;gap:2px}.dl{margin-top:8px}}
.tw{overflow-x:auto}
.dy{display:flex;align-items:center;gap:6px;color:var(--mut)}
.pg{display:flex;gap:8px;align-items:center;justify-content:center;margin:14px 0;flex-wrap:wrap}.pg button:disabled{opacity:.4;cursor:default}
.mut a{color:var(--acc)}a.vl{color:inherit}a.vl:hover{color:var(--acc)}
footer{margin:28px 0 8px;text-align:center;font-size:13px;color:var(--mut)}
footer a{color:var(--mut)}footer a:hover{color:var(--fg)}
.sev{display:inline-block;padding:1px 7px;border-radius:10px;font-size:12px;font-weight:600;border:1px solid currentColor;background:color-mix(in srgb,currentColor 12%,transparent)}
.sev-CRITICAL{color:var(--red);font-weight:800}.sev-HIGH{color:var(--red)}.sev-MEDIUM{color:var(--org)}.sev-LOW{color:var(--yel)}
</style></head><body><main>
<h1><a href="/" style="color:inherit;text-decoration:none">CISA KEV</a></h1><div id="one" hidden></div><div id="search"><div class="mut" id="meta"></div>
<form id="f"><input name="q" placeholder="log4j, fortinet, CVE-2024-... (terminos AND)" autofocus>
<input name="vendor" placeholder="vendor" size="12"><input name="product" placeholder="producto" size="12">
<select name="severity"><option value="">severidad</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select>
<label class="dy" title="vaciar el campo para ver todo el catalogo">ultimos <input name="days" type="number" min="1" placeholder="todo" style="width:70px"> dias</label>
<label><input type="checkbox" name="ransomware" value="1"> ransomware</label>
<button>Buscar</button></form>
<div class="tw"><table><thead><tr><th>CVE</th><th>Agregado</th><th>CVSS</th><th>Ransom.</th><th>Vendor / Producto</th><th>Nombre</th></tr></thead>
<tbody id="b"></tbody></table></div><div id="pg" class="pg"></div></div>
<script>
const $=s=>document.querySelector(s),esc=t=>String(t??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
let VENDOR_EXACT="",PRODUCT_EXACT="";
const SEV=new Set(["CRITICAL","HIGH","MEDIUM","LOW"]);
let PAGE_N=Math.max(1,parseInt(new URLSearchParams(location.search).get("page"))||1);
function setUrlPage(n){const u=new URL(location.href);
  if(n>1)u.searchParams.set("page",n);else u.searchParams.delete("page");
  if(u.href!==location.href)history.replaceState(null,"",u)}
window.onpopstate=()=>{PAGE_N=Math.max(1,parseInt(new URLSearchParams(location.search).get("page"))||1);go()};
async function go(n){
  if(n)PAGE_N=n;
  const p=new URLSearchParams();for(const [k,v] of new FormData($("#f")))if(v)p.set(k,v);
  if(VENDOR_EXACT&&p.get("vendor")===VENDOR_EXACT)p.set("vendor_exact","1");
  if(PRODUCT_EXACT&&p.get("product")===PRODUCT_EXACT)p.set("product_exact","1");
  p.set("page",PAGE_N);
  const r=await fetch("/api/search?"+p);if(!r.ok){$("#b").innerHTML="<tr><td colspan=6>Error "+r.status+"</td></tr>";return}
  const d=await r.json();PAGE_N=d.page;setUrlPage(d.page);$("#meta").textContent=d.count+" resultado(s) - pagina "+d.page+" de "+d.pages+" - cache: "+d.cache;
  $("#pg").innerHTML=d.pages>1?`<button data-p="1" ${d.page<=1?"disabled":""}>&laquo;</button><button data-p="${d.page-1}" ${d.page<=1?"disabled":""}>&lsaquo; Anterior</button>
   <span class="mut">${d.page} / ${d.pages}</span><button data-p="${d.page+1}" ${d.page>=d.pages?"disabled":""}>Siguiente &rsaquo;</button><button data-p="${d.pages}" ${d.page>=d.pages?"disabled":""}>&raquo;</button>`:"";
  $("#b").innerHTML=d.results.map(x=>`<tr class="r" data-c="${esc(x.cve)}"><td>${esc(x.cve)}</td><td>${esc(x.added)}</td>
  <td>${esc(x.score)} ${x.severity?`<br><span class="sev ${SEV.has(x.severity)?"sev-"+x.severity:"mut"}">${esc(x.severity)}</span>`:""}</td><td class="${x.ransomware=="Known"?"ran":"mut"}">${x.ransomware=="Known"?"SI":"-"}</td>
  <td><a class="vl" href="/vendor/${encodeURIComponent(x.vendor)}">${esc(x.vendor)}</a> / <a class="vl" href="/product/${encodeURIComponent(x.product)}">${esc(x.product)}</a></td><td>${esc(x.name)}</td></tr>`).join("")||"<tr><td colspan=6>Sin resultados</td></tr>";
}
$("#f").onsubmit=e=>{e.preventDefault();go(1)};
$("#pg").onclick=e=>{const b=e.target.closest("button[data-p]");if(b&&!b.disabled){const u=new URL(location.href);+b.dataset.p>1?u.searchParams.set("page",b.dataset.p):u.searchParams.delete("page");
  history.pushState(null,"",u);go(+b.dataset.p);window.scrollTo(0,0)}};
function detailGrid(k){
   const row=(l,v)=>v?`<div class="dl">${l}</div><div>${v}</div>`:"";
   const link=u=>`<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u)}</a>`;
   const notes=String(k.notes||"").split(";").map(x=>x.trim()).filter(Boolean).map(x=>{
     const m=x.match(/^(.*?)(https?:\\/\\/\\S+)$/);return m&&/^https?:\\/\\//.test(m[2])?`<li>${m[1]?esc(m[1]):""}${link(m[2])}</li>`:`<li>${esc(x)}</li>`}).join("");
   const pocs=(k.githubPocs||[]).filter(u=>/^https?:\\/\\//.test(u)).slice(0,10).map(u=>`<li>${link(u)}</li>`).join("");
   return `<div class="dg">`+row("Descripcion",esc(k.shortDescription))+row("Accion requerida",esc(k.requiredAction))+
     row("Vence",esc(k.dueDate))+row("Notas",notes?`<ul>${notes}</ul>`:"")+row("PoCs en GitHub",pocs?`<ul>${pocs}</ul>`:"")+
     row("Enlace",`<a href="/vuln/${encodeURIComponent(k.cveID)}">/vuln/${esc(k.cveID)}</a>`)+`</div>`}
$("#b").onclick=e=>{if(e.target.closest("a"))return;const tr=e.target.closest("tr.r");if(!tr)return;const n=tr.nextElementSibling;
  if(n&&n.classList.contains("det")){n.remove();return}
  fetch("/api/cve/"+encodeURIComponent(tr.dataset.c)).then(r=>r.json()).then(k=>{const t=document.createElement("tr");t.className="det";
   t.innerHTML=`<td colspan=6>${detailGrid(k)}</td>`;tr.after(t)})};
const mv=location.pathname.match(/^\\/vuln\\/(CVE-\\d{4}-\\d+)\\/?$/i);
if(mv){
  const cve=mv[1].toUpperCase();document.title=cve+" - CISA KEV";
  $("#search").hidden=true;$("#one").hidden=false;
  fetch("/api/cve/"+cve).then(async r=>{
    if(!r.ok){$("#one").innerHTML=`<h2>${esc(cve)}</h2><p>No esta en el catalogo CISA KEV.</p>`;return}
    const k=await r.json(),sv=k._severity;
    $("#one").innerHTML=`<h2>${esc(cve)} - ${esc(k.vulnerabilityName)}</h2>
     <p class="mut">${esc(k.vendorProject)} / ${esc(k.product)} - agregado ${esc(k.dateAdded)}</p>
     <p>CVSS ${esc(k._score??"-")} ${sv?`<span class="sev ${SEV.has(sv)?"sev-"+sv:"mut"}">${esc(sv)}</span>`:""}
     &nbsp; Ransomware: <b class="${k.knownRansomwareCampaignUse=="Known"?"ran":"mut"}">${k.knownRansomwareCampaignUse=="Known"?"SI":"no conocido"}</b></p>`+detailGrid(k)})
}else{
  const vm=location.pathname.match(/^\\/vendor\\/([^/]+)\\/?$/i);
  if(vm){try{VENDOR_EXACT=decodeURIComponent(vm[1])}catch(e){VENDOR_EXACT=vm[1]}
    $("#f").vendor.value=VENDOR_EXACT;document.title=VENDOR_EXACT+" - CISA KEV";
    $("h1").insertAdjacentHTML("afterend",`<p class="mut">Vendor: <b>${esc(VENDOR_EXACT)}</b> - <a href="/">quitar filtro</a></p>`)}
  const pm=location.pathname.match(/^\\/product\\/([^/]+)\\/?$/i);
  if(pm){try{PRODUCT_EXACT=decodeURIComponent(pm[1])}catch(e){PRODUCT_EXACT=pm[1]}
    $("#f").product.value=PRODUCT_EXACT;document.title=PRODUCT_EXACT+" - CISA KEV";
    $("h1").insertAdjacentHTML("afterend",`<p class="mut">Producto: <b>${esc(PRODUCT_EXACT)}</b> - <a href="/">quitar filtro</a></p>`)}
  if(!vm&&!pm)$("#f").days.value=30;  // portada: ultimos 30 dias (vaciar el campo para ver todo)
  go();
}
</script>
<footer><a href="https://github.com/baicom/cisa-kev" target="_blank" rel="noopener noreferrer">github</a></footer>
</main></body></html>"""


def load_dotenv(path=None):
    """Carga KEY=VALUE de .env (junto al script) sin pisar variables ya definidas."""
    path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError:
        return
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("#") or "=" not in ln:
            continue
        k, _, v = ln.partition("=")
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        os.environ.setdefault(k.strip(), v)


def parse_users(env):
    users = {}
    for item in (env or "").split(","):
        item = item.strip()
        if not item:
            continue
        u, sep, p = item.partition(":")  # el password puede contener ':' (no ',')
        if not sep or not u or not p:
            sys.exit("USERS invalido: formato user:pass,user2:pass2")
        users[u] = p
    return users


def make_handler(users, lock):
    import base64, hmac
    from http.server import BaseHTTPRequestHandler

    class H(BaseHTTPRequestHandler):
        server_version = "kev"

        def log_message(self, fmt, *args):  # sin credenciales: solo metodo/path/status
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

        def authed(self):
            if users is None:
                return True
            h = self.headers.get("Authorization", "")
            if h.startswith("Basic "):
                try:
                    u, _, p = base64.b64decode(h[6:]).decode().partition(":")
                    exp = users.get(u)
                    # comparacion en tiempo constante; siempre se compara algo
                    if hmac.compare_digest((exp or "\0").encode(), p.encode()) and exp is not None:
                        return True
                except Exception:
                    pass
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="KEV", charset="UTF-8"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False

        def send(self, code, body, ctype):
            b = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            if not self.authed():
                return
            u = urllib.parse.urlparse(self.path)
            q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
            if u.path == "/" or re.fullmatch(r"/(vuln/CVE-\d{4}-\d+|vendor/[^/]+|product/[^/]+)/?", u.path, re.I):
                return self.send(200, PAGE, "text/html; charset=utf-8")
            c = db()
            try:
                if u.path == "/api/search":
                    def num(k, t, d=None):
                        try:
                            return t(q[k]) if q.get(k) else d
                        except ValueError:
                            return d
                    per = max(1, min(num("limit", int, 50), 500))
                    page = max(1, num("page", int, 1))
                    rows, total = query_rows(c, q.get("q", "")[:500].split(), q.get("vendor"), q.get("product"),
                                             bool(q.get("ransomware")), q.get("severity"), num("min_score", float),
                                             q.get("since"), num("days", int), per,
                                             vendor_exact=bool(q.get("vendor_exact")), product_exact=bool(q.get("product_exact")),
                                             offset=(page - 1) * per, with_total=True)
                    if total and not rows:  # pagina fuera de rango: ir a la ultima
                        page = -(-total // per)
                        rows = query_rows(c, q.get("q", "")[:500].split(), q.get("vendor"), q.get("product"),
                                          bool(q.get("ransomware")), q.get("severity"), num("min_score", float),
                                          q.get("since"), num("days", int), per,
                                          vendor_exact=bool(q.get("vendor_exact")), product_exact=bool(q.get("product_exact")), offset=(page - 1) * per)
                    ts = float(meta(c, "synced") or 0)
                    out = {"count": total, "page": page, "per_page": per, "pages": max(1, -(-total // per)),
                           "cache": time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)),
                           "results": [{k: r[k] for k in ("cve", "vendor", "product", "name", "added",
                                                         "due", "ransomware", "score", "severity")} for r in rows]}
                    return self.send(200, json.dumps(out), "application/json")
                if u.path.startswith("/api/cve/"):
                    r = c.execute("SELECT raw, score, severity FROM kev WHERE cve=?", (u.path[9:].upper(),)).fetchone()
                    if not r:
                        return self.send(404, '{"error":"not in KEV"}', "application/json")
                    k = json.loads(r["raw"])
                    k["_score"], k["_severity"] = r["score"], r["severity"]
                    return self.send(200, json.dumps(k), "application/json")
                if u.path == "/healthz":
                    return self.send(200, "ok", "text/plain")
                self.send(404, "not found", "text/plain")
            except Exception as e:
                sys.stderr.write(f"error: {e}\n")
                self.send(500, '{"error":"internal"}', "application/json")
            finally:
                c.close()

    return H


def refresher(hours, age_h, lock):
    """Hilo de fondo: update incremental cada `hours`; si falla, reintenta en 1 h (nunca en bucle)."""
    wait = max(0.0, hours - age_h) * 3600
    while True:
        time.sleep(wait)
        try:
            with lock:
                c = db()
                try:
                    mode, n = update_incremental(c, quiet=True)
                finally:
                    c.close()
            sys.stderr.write(f"[refresh] OK ({mode}): {n} CVEs {time.strftime('%F %T')}\n")
            wait = hours * 3600
        except (Exception, SystemExit) as e:
            sys.stderr.write(f"[refresh] fallo: {e}; reintento en 1 h\n")
            wait = 3600


def cmd_serve(a, c):
    import threading
    from http.server import ThreadingHTTPServer
    load_dotenv()
    lock = threading.Lock()
    users = parse_users(os.environ.get("USERS"))
    if not users:
        print("[aviso] USERS vacio o no definido: SIN autenticacion", file=sys.stderr)
    with lock:
        if not meta(c, "synced") or count_local(c) == 0:  # cache vacio: sync inicial
            sync(c)
    age_h = (time.time() - float(meta(c, "synced") or 0)) / 3600
    c.close()
    hours = float(os.environ.get("KEV_REFRESH_HOURS") or 24)
    if hours > 0:
        threading.Thread(target=refresher, args=(hours, age_h, lock), daemon=True).start()
    print(f"Refresco incremental cada {hours:g} h" if hours > 0 else "Refresco automatico desactivado", file=sys.stderr)
    srv = ThreadingHTTPServer((a.host, a.port), make_handler(users or None, lock))
    print(f"Sirviendo en http://{a.host}:{a.port}  auth={'si (%d usuario/s)' % len(users) if users else 'NO'}", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


def cmd_sync(a, c):
    print(f"{sync(c)} CVEs KEV en cache (resync completo)")


def cmd_update(a, c):
    mode, n = update_incremental(c)
    print(f"Actualizacion {mode}: {n} CVEs procesados, {count_local(c)} en cache")


def cmd_clear(a, c):
    c.close()
    if os.path.exists(DB):
        os.remove(DB)
    print("Cache borrado")


def main():
    p = argparse.ArgumentParser(description="Buscador CISA KEV (API kevin.gtfkd.com) con cache SQLite")
    p.add_argument("--refresh", action="store_true", help="forzar actualizacion del cache")
    sp = p.add_subparsers(dest="cmd", required=True)
    s = sp.add_parser("search", help="buscar en el catalogo (local, sobre cache)")
    s.add_argument("query", nargs="*", help="terminos (AND) sobre CVE/vendor/producto/nombre/descripcion")
    s.add_argument("--vendor"); s.add_argument("--product")
    s.add_argument("--ransomware", action="store_true", help="solo usados en campanas de ransomware")
    s.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL", "low", "medium", "high", "critical"])
    s.add_argument("--min-score", type=float); s.add_argument("--since", help="YYYY-MM-DD (dateAdded)")
    s.add_argument("--days", type=int, help="agregados en los ultimos N dias")
    s.add_argument("--limit", type=int, default=25); s.add_argument("--json", action="store_true")
    s.set_defaults(f=cmd_search)
    s = sp.add_parser("show", help="detalle de un CVE"); s.add_argument("cve")
    s.add_argument("--details", action="store_true", help="agrega /vuln/{cve} (cacheado 24h)")
    s.add_argument("--json", action="store_true"); s.set_defaults(f=cmd_show)
    s = sp.add_parser("check", help="¿estan estos CVEs en KEV? (exit 1 si alguno no)")
    s.add_argument("cves", nargs="+"); s.set_defaults(f=cmd_check)
    sp.add_parser("stats", help="resumen").set_defaults(f=cmd_stats)
    sp.add_parser("update", help="actualizacion incremental (/kev/recent)").set_defaults(f=cmd_update)
    sp.add_parser("sync", help="forzar descarga completa").set_defaults(f=cmd_sync)
    s = sp.add_parser("serve", help="pagina web + API JSON con HTTP basic auth (env USERS=user:pass,...; si esta vacio/no existe, sin auth)")
    s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8080)
    s.set_defaults(f=cmd_serve)
    sp.add_parser("clear", help="borrar cache").set_defaults(f=cmd_clear)
    load_dotenv()
    a = p.parse_args()
    c = db() if a.cmd != "clear" else None
    sys.exit(a.f(a, c) or 0)


if __name__ == "__main__":
    main()
