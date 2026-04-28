"""
CVE Intelligence Router
-----------------------
Integra tres fuentes públicas de vulnerabilidades:
  1. NVD  - National Vulnerability Database (NIST)      https://nvd.nist.gov
  2. MITRE - Diccionario oficial CVE (cve.org)          https://cve.mitre.org
  3. CISA  - Known Exploited Vulnerabilities Catalog    https://www.cisa.gov

Roles:
  - Analista  (is_admin=False): consulta y visualización (datos en caché)
  - Administrador (is_admin=True): puede forzar actualización del caché
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from app.models.user import User
from app.routers.logs import get_current_user
import urllib.request
import urllib.parse
import json
import time
import os
from datetime import datetime, timezone

router = APIRouter(prefix="/cve-intel", tags=["cve-intel"])

# ---------------------------------------------------------------------------
# Caché en memoria: { key: (data_dict, timestamp_float) }
# ---------------------------------------------------------------------------
_cache: dict = {}
TTL_NVD   = 1800   # 30 min (NVD impone límite de tasa sin API key)
TTL_MITRE = 3600   # 1 hora
TTL_CISA  = 3600   # 1 hora

NVD_API_KEY = os.getenv("NVD_API_KEY", "")   # Opcional – funciona sin clave


def _cache_get(key: str, ttl: int):
    entry = _cache.get(key)
    if entry and (time.time() - entry[1]) < ttl:
        return entry[0]
    return None


def _cache_set(key: str, data: dict):
    _cache[key] = (data, time.time())


def _cache_clear(key: str):
    _cache.pop(key, None)


def _cache_age_seconds(key: str) -> int | None:
    entry = _cache.get(key)
    if entry:
        return int(time.time() - entry[1])
    return None


# ---------------------------------------------------------------------------
# Funciones de consulta a cada fuente
# ---------------------------------------------------------------------------

def _fetch_json(url: str, extra_headers: dict | None = None, timeout: int = 20) -> dict | list:
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "ForensiLog-CveIntel/1.0")
    if extra_headers:
        for k, v in extra_headers.items():
            req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


# --- NVD ---

def _fetch_nvd(year: int, limit: int) -> dict:
    params = urllib.parse.urlencode({
        "pubStartDate": f"{year}-01-01T00:00:00.000",
        "pubEndDate":   f"{year}-12-31T23:59:59.999",
        "resultsPerPage": limit,
        "startIndex": 0,
    })
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}"
    hdrs = {}
    if NVD_API_KEY:
        hdrs["apiKey"] = NVD_API_KEY

    raw = _fetch_json(url, extra_headers=hdrs, timeout=25)

    vulns = []
    for item in raw.get("vulnerabilities", []):
        cve = item.get("cve", {})
        # Descripción en inglés
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "Sin descripción",
        )
        # Métricas CVSS (v3.1 > v3.0 > v2)
        score, severity, vector = None, None, None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            if metrics.get(key):
                m = metrics[key][0].get("cvssData", {})
                score    = m.get("baseScore")
                severity = m.get("baseSeverity")
                vector   = m.get("vectorString")
                break
        if score is None and metrics.get("cvssMetricV2"):
            m = metrics["cvssMetricV2"][0]
            score    = m.get("cvssData", {}).get("baseScore")
            severity = m.get("baseSeverity")
            vector   = m.get("cvssData", {}).get("vectorString")

        cve_id = cve.get("id", "")
        vulns.append({
            "id":           cve_id,
            "published":    cve.get("published", ""),
            "lastModified": cve.get("lastModified", ""),
            "description":  desc[:400],
            "cvss_score":   score,
            "severity":     severity,
            "cvss_vector":  vector,
            "url":          f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

    return {
        "source":        "NVD",
        "source_full":   "National Vulnerability Database (NIST)",
        "api_version":   raw.get("version", "2.0"),
        "api_format":    raw.get("format", "NVD_CVE"),
        "timestamp":     raw.get("timestamp", ""),
        "total_results": raw.get("totalResults", 0),
        "year_queried":  year,
        "results_shown": len(vulns),
        "vulnerabilities": vulns,
    }


# --- MITRE CVE ---

def _fetch_mitre(limit: int) -> dict:
    # Versión del catálogo → última release del repositorio oficial de MITRE en GitHub
    version, version_date, release_url = "N/A", "N/A", ""
    try:
        gh = _fetch_json(
            "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest",
            timeout=10,
        )
        version      = gh.get("tag_name", "N/A")
        version_date = (gh.get("published_at") or "")[:10]
        release_url  = gh.get("html_url", "")
    except Exception:
        pass

    # CVEs recientes via NVD (enriquecidos con datos de MITRE)
    # Mostramos los últimos 'limit' CVEs publicados en el año actual
    current_year = datetime.now(timezone.utc).year
    params = urllib.parse.urlencode({
        "pubStartDate":   f"{current_year}-01-01T00:00:00.000",
        "pubEndDate":     f"{current_year}-12-31T23:59:59.999",
        "resultsPerPage": limit,
        "startIndex":     0,
    })
    hdrs = {}
    if NVD_API_KEY:
        hdrs["apiKey"] = NVD_API_KEY

    raw = _fetch_json(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}",
        extra_headers=hdrs,
        timeout=25,
    )

    vulns = []
    for item in raw.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "Sin descripción",
        )
        # Para MITRE resaltamos el estado, asignador y fecha de publicación
        refs = [r.get("url", "") for r in cve.get("references", [])[:3]]
        vulns.append({
            "id":           cve_id,
            "published":    cve.get("published", ""),
            "lastModified": cve.get("lastModified", ""),
            "description":  desc[:400],
            "references":   refs,
            "url":          f"https://www.cve.org/CVERecord?id={cve_id}",
        })

    return {
        "source":             "MITRE",
        "source_full":        "Diccionario Oficial CVE (MITRE / cve.org)",
        "catalog_version":    version,
        "version_date":       version_date,
        "release_url":        release_url,
        "year_queried":       current_year,
        "total_results":      raw.get("totalResults", 0),
        "results_shown":      len(vulns),
        "vulnerabilities":    vulns,
    }


# --- CISA KEV ---

def _fetch_cisa() -> dict:
    raw = _fetch_json(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        timeout=25,
    )
    all_vulns = raw.get("vulnerabilities", [])
    # Más recientes primero
    all_vulns.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
    latest = all_vulns[:20]

    vulns = []
    for v in latest:
        vulns.append({
            "id":          v.get("cveID", ""),
            "vendor":      v.get("vendorProject", ""),
            "product":     v.get("product", ""),
            "name":        v.get("vulnerabilityName", ""),
            "dateAdded":   v.get("dateAdded", ""),
            "description": (v.get("shortDescription") or "")[:400],
            "action":      v.get("requiredAction", ""),
            "dueDate":     v.get("dueDate", ""),
            "ransomware":  v.get("knownRansomwareCampaignUse", "Unknown"),
            "url":         "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        })

    return {
        "source":          "CISA",
        "source_full":     "CISA Known Exploited Vulnerabilities Catalog",
        "catalog_version": raw.get("catalogVersion", "N/A"),
        "date_released":   raw.get("dateReleased", ""),
        "total_count":     raw.get("count", len(all_vulns)),
        "results_shown":   len(vulns),
        "vulnerabilities": vulns,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/nvd")
def get_nvd(
    year: int = Query(
        default=None,
        description="Año de publicación a consultar (1999 – año actual)",
    ),
    limit: int = Query(default=20, ge=1, le=50),
    force_refresh: bool = Query(default=False),
    current_user: User = Depends(get_current_user),
):
    """
    Consulta la NVD (NIST) para obtener CVEs publicados en el año indicado.
    Caché de 30 minutos. Solo administradores pueden forzar actualización.
    """
    if year is None:
        year = datetime.now(timezone.utc).year

    if not (1999 <= year <= datetime.now(timezone.utc).year):
        raise HTTPException(status_code=400, detail="Año fuera de rango (1999 – año actual)")

    if force_refresh and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Solo administradores pueden forzar actualización")

    cache_key = f"nvd_{year}_{limit}"
    if not force_refresh:
        cached = _cache_get(cache_key, TTL_NVD)
        if cached:
            age = _cache_age_seconds(cache_key)
            return {**cached, "cached": True, "cache_age_seconds": age}

    try:
        data = _fetch_nvd(year, limit)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Error al consultar NVD: {exc}")

    _cache_set(cache_key, data)
    return {**data, "cached": False, "cache_age_seconds": 0,
            "user_role": "Administrador" if current_user.is_admin else "Analista"}


@router.get("/mitre")
def get_mitre(
    limit: int = Query(default=20, ge=1, le=50),
    force_refresh: bool = Query(default=False),
    current_user: User = Depends(get_current_user),
):
    """
    Consulta la versión del catálogo CVE de MITRE (GitHub releases) y obtiene
    los CVEs más recientes del año actual via NVD, con enlace a cve.org.
    Caché de 1 hora. Solo administradores pueden forzar actualización.
    """
    if force_refresh and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Solo administradores pueden forzar actualización")

    cache_key = f"mitre_{limit}"
    if not force_refresh:
        cached = _cache_get(cache_key, TTL_MITRE)
        if cached:
            age = _cache_age_seconds(cache_key)
            return {**cached, "cached": True, "cache_age_seconds": age}

    try:
        data = _fetch_mitre(limit)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Error al consultar MITRE CVE: {exc}")

    _cache_set(cache_key, data)
    return {**data, "cached": False, "cache_age_seconds": 0,
            "user_role": "Administrador" if current_user.is_admin else "Analista"}


@router.get("/cisa")
def get_cisa(
    force_refresh: bool = Query(default=False),
    current_user: User = Depends(get_current_user),
):
    """
    Consulta el catálogo CISA KEV (Known Exploited Vulnerabilities).
    Incluye versión del catálogo, fecha de publicación y total de entradas.
    Caché de 1 hora. Solo administradores pueden forzar actualización.
    """
    if force_refresh and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Solo administradores pueden forzar actualización")

    cache_key = "cisa"
    if not force_refresh:
        cached = _cache_get(cache_key, TTL_CISA)
        if cached:
            age = _cache_age_seconds(cache_key)
            return {**cached, "cached": True, "cache_age_seconds": age}

    try:
        data = _fetch_cisa()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Error al consultar CISA KEV: {exc}")

    _cache_set(cache_key, data)
    return {**data, "cached": False, "cache_age_seconds": 0,
            "user_role": "Administrador" if current_user.is_admin else "Analista"}


@router.get("/summary")
def get_summary(current_user: User = Depends(get_current_user)):
    """
    Devuelve el estado del caché de las tres fuentes:
    versión, fecha y antigüedad del caché. No hace llamadas externas.
    """
    result: dict = {
        "user_role": "Administrador" if current_user.is_admin else "Analista",
        "sources": {},
    }

    # NVD – buscar cualquier entrada cacheada
    for k, (d, ts) in list(_cache.items()):
        if k.startswith("nvd_"):
            result["sources"]["nvd"] = {
                "source_full":   d.get("source_full"),
                "api_version":   d.get("api_version"),
                "timestamp":     d.get("timestamp"),
                "year_queried":  d.get("year_queried"),
                "total_results": d.get("total_results"),
                "cache_age_s":   int(time.time() - ts),
                "cached":        True,
            }
            break

    # MITRE
    for k, (d, ts) in list(_cache.items()):
        if k.startswith("mitre_"):
            result["sources"]["mitre"] = {
                "source_full":      d.get("source_full"),
                "catalog_version":  d.get("catalog_version"),
                "version_date":     d.get("version_date"),
                "release_url":      d.get("release_url"),
                "total_results":    d.get("total_results"),
                "cache_age_s":      int(time.time() - ts),
                "cached":           True,
            }
            break

    # CISA
    if "cisa" in _cache:
        d, ts = _cache["cisa"]
        result["sources"]["cisa"] = {
            "source_full":     d.get("source_full"),
            "catalog_version": d.get("catalog_version"),
            "date_released":   d.get("date_released"),
            "total_count":     d.get("total_count"),
            "cache_age_s":     int(time.time() - ts),
            "cached":          True,
        }

    return result
