"""
Script para descargar CVEs desde NVD API 2.0 a PostgreSQL local.
Paginacion directa sin filtros de fecha — mas robusto.

Uso:
    docker exec forensic_backend python scripts/load_cve_feeds.py --mode all
    docker exec forensic_backend python scripts/load_cve_feeds.py --mode recent
    docker exec forensic_backend python scripts/load_cve_feeds.py --mode stats
    docker exec forensic_backend python scripts/load_cve_feeds.py --mode all --resume 40000
"""
import os, sys, json, time, argparse
from datetime import datetime, timedelta
import requests

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.dialects.postgresql import insert as pg_insert
from app.database import SessionLocal, engine, Base
from app.models.cve import CveData

NVD_API    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PER_PAGE   = 2000
BATCH_SIZE = 500
TIMEOUT    = 30
API_KEY    = os.getenv("NVD_API_KEY", "")
SLEEP_SEC  = 0.7 if API_KEY else 6.5


def headers():
    h = {"User-Agent": "ForensiLog/1.0"}
    if API_KEY:
        h["apiKey"] = API_KEY
    return h


def parse_vuln(v: dict):
    try:
        cve    = v.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        summary = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            ""
        )

        cvss_score = cvss_vector = severity = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {}).get(key)
            if metrics:
                data       = metrics[0].get("cvssData", {})
                cvss_score  = data.get("baseScore")
                cvss_vector = data.get("vectorString", "")
                severity    = (data.get("baseSeverity") or metrics[0].get("baseSeverity", "")).upper() or None
                break

        if not severity and cvss_score is not None:
            severity = "CRITICAL" if cvss_score >= 9 else "HIGH" if cvss_score >= 7 else "MEDIUM" if cvss_score >= 4 else "LOW"

        refs      = [r["url"] for r in cve.get("references", []) if r.get("url")][:10]
        published = (cve.get("published") or "")[:10]

        return {
            "cve_id":         cve_id,
            "summary":        summary[:2000],
            "cvss_score":     cvss_score,
            "cvss_vector":    (cvss_vector or "")[:200],
            "severity":       severity,
            "published_date": published,
            "references":     json.dumps(refs),
        }
    except Exception:
        return None


def upsert_batch(db, batch: list):
    if not batch:
        return
    stmt = pg_insert(CveData).values(batch).on_conflict_do_update(
        index_elements=["cve_id"],
        set_={k: getattr(pg_insert(CveData).excluded, k)
              for k in ("summary","cvss_score","cvss_vector","severity","published_date","references")},
    )
    # rebuild properly
    ins = pg_insert(CveData).values(batch)
    ins = ins.on_conflict_do_update(
        index_elements=["cve_id"],
        set_={
            "summary":        ins.excluded.summary,
            "cvss_score":     ins.excluded.cvss_score,
            "cvss_vector":    ins.excluded.cvss_vector,
            "severity":       ins.excluded.severity,
            "published_date": ins.excluded.published_date,
            "references":     ins.excluded.references,
            "loaded_at":      datetime.utcnow(),
        }
    )
    db.execute(ins)
    db.commit()


def fetch_page(params: dict, retries: int = 5) -> dict:
    for attempt in range(retries):
        try:
            r = requests.get(NVD_API, params=params, headers=headers(), timeout=TIMEOUT)
            if r.status_code == 200:
                return r.json()
            if r.status_code == 429:
                wait = 35
                print(f"\n  Rate limit — esperando {wait}s...")
                time.sleep(wait)
                continue
            # 403 / 404 / 503 — esperar y reintentar
            wait = 15 * (attempt + 1)
            print(f"\n  HTTP {r.status_code} — reintento {attempt+1}/{retries} en {wait}s...")
            time.sleep(wait)
        except requests.RequestException as e:
            wait = 10 * (attempt + 1)
            print(f"\n  Error red: {e} — reintento {attempt+1}/{retries} en {wait}s...")
            time.sleep(wait)
    return {}


def load_all(resume_from: int = 0):
    print("=" * 58)
    print("  NVD API 2.0 — Carga completa de CVEs")
    if API_KEY:
        print("  Modo rapido (API Key detectada)")
    else:
        print("  Modo normal — ~25 min")
        print("  Para modo rapido, obtener API Key GRATIS en:")
        print("  https://nvd.nist.gov/developers/request-an-api-key")
        print("  Luego: docker exec -e NVD_API_KEY=<key> forensic_backend \\")
        print("         python scripts/load_cve_feeds.py --mode all")
    print("=" * 58)

    db           = SessionLocal()
    start_index  = resume_from
    total        = None
    imported     = 0
    batch        = []
    t0           = time.time()

    if resume_from > 0:
        print(f"  Reanudando desde posicion {resume_from:,}")

    while True:
        data = fetch_page({"startIndex": start_index, "resultsPerPage": PER_PAGE})
        if not data:
            print("\n  No se pudo obtener datos. Intenta de nuevo con:")
            print(f"  --mode all --resume {start_index}")
            break

        if total is None:
            total = data.get("totalResults", 0)
            print(f"  Total CVEs disponibles: {total:,}\n")

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        for v in vulns:
            p = parse_vuln(v)
            if p:
                batch.append(p)
            if len(batch) >= BATCH_SIZE:
                upsert_batch(db, batch)
                imported += len(batch)
                batch = []

        start_index += len(vulns)
        elapsed = time.time() - t0
        rate    = imported / elapsed if elapsed > 0 else 0
        pct     = start_index / total * 100 if total else 0
        eta_s   = int((total - start_index) / (start_index / elapsed)) if start_index > 0 and elapsed > 0 else 0
        eta_m   = eta_s // 60
        print(f"  {start_index:,}/{total:,} ({pct:.1f}%)  {rate:.0f} CVEs/s  ETA: {eta_m}min   ", end="\r")

        if start_index >= (total or 0):
            break

        time.sleep(SLEEP_SEC)

    if batch:
        upsert_batch(db, batch)
        imported += len(batch)

    db.close()
    elapsed = time.time() - t0
    print(f"\n\n  Importados: {imported:,} CVEs en {elapsed/60:.1f} min")


def load_recent(days: int = 120):
    end   = datetime.utcnow()
    start = end - timedelta(days=days)
    fmt   = "%Y-%m-%dT%H:%M:%S.000"
    print(f"Actualizando CVEs modificados en los ultimos {days} dias...")

    db       = SessionLocal()
    imported = 0
    batch    = []
    start_i  = 0
    total    = None

    while True:
        params = {
            "startIndex":       start_i,
            "resultsPerPage":   PER_PAGE,
            "lastModStartDate": start.strftime(fmt),
            "lastModEndDate":   end.strftime(fmt),
        }
        data  = fetch_page(params)
        if not data:
            break
        if total is None:
            total = data.get("totalResults", 0)
            print(f"  CVEs modificados: {total:,}")

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        for v in vulns:
            p = parse_vuln(v)
            if p:
                batch.append(p)
            if len(batch) >= BATCH_SIZE:
                upsert_batch(db, batch)
                imported += len(batch)
                batch = []

        start_i += len(vulns)
        print(f"  {start_i:,}/{total:,}", end="\r")
        if start_i >= (total or 0):
            break
        time.sleep(SLEEP_SEC)

    if batch:
        upsert_batch(db, batch)
        imported += len(batch)

    db.close()
    print(f"\n  Actualizados: {imported:,} CVEs")


def show_stats():
    from sqlalchemy import func, text
    db    = SessionLocal()
    total = db.query(func.count(CveData.id)).scalar()
    rows  = db.execute(
        text("SELECT severity, COUNT(*) FROM cve_data GROUP BY severity ORDER BY COUNT(*) DESC")
    ).fetchall()
    db.close()
    print(f"\nCVEs en base de datos local: {total:,}")
    print("Por severidad:")
    for sev, cnt in rows:
        print(f"  {(sev or 'N/A'):10s}: {cnt:,}")


def ensure_table():
    Base.metadata.create_all(bind=engine, tables=[CveData.__table__])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode",   choices=["all", "recent", "stats"], default="all")
    parser.add_argument("--resume", type=int, default=0,   help="Reanudar desde este indice")
    parser.add_argument("--days",   type=int, default=120, help="Dias para --mode recent")
    args = parser.parse_args()

    ensure_table()

    if args.mode == "all":
        load_all(resume_from=args.resume)
    elif args.mode == "recent":
        load_recent(days=args.days)
    elif args.mode == "stats":
        show_stats()

    show_stats()
