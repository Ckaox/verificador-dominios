"""
Procesador local de CSVs con dominios.

Para cada fila:
  1. Verifica DNS (MX, SPF, DMARC, DKIM) del dominio
  2. Genera variantes y detecta dominios secundarios activos (cold email)
  3. Detecta cuáles de esos secundarios redirigen al dominio principal

Procesa N filas en paralelo (configurable, default 5).
Soporta pausar / reanudar / saltar / detener.
Persiste estado en disco para retomar después de cerrar el programa.

El CSV de salida se escribe en orden de finalización (no de entrada);
incluye `rf_original_index` para reordenar al descargar.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import csv
import json
import os
import re
import time
import uuid

try:
    import whois as _whois_lib  # python-whois
    # Silenciar errores ruidosos de la librería whois: timeouts y servers
    # caídos son normales y los atrapamos nosotros — no queremos spam de logs.
    import logging as _logging
    for _name in ("whois", "whois.whois"):
        _lg = _logging.getLogger(_name)
        _lg.setLevel(_logging.CRITICAL)
        _lg.propagate = False
except ImportError:
    _whois_lib = None
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .dns_checker import DNSChecker
from .domain_discovery import DomainDiscovery


# ---------------------------------------------------------------------------
# Configuración de almacenamiento
# ---------------------------------------------------------------------------

DATA_DIR = Path(os.environ.get("CSV_JOBS_DIR", "./data/jobs")).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)


# Columnas que añadimos al CSV de salida
OUTPUT_COLUMNS = [
    "rf_original_index",        # índice original en el CSV de entrada (para ordenar)
    "rf_status",                # ok | skipped | error | timeout
    "rf_processed_at",
    "rf_seconds",
    "rf_has_mx",
    "rf_mx_provider",
    "rf_mx_servers",
    "rf_has_spf",
    "rf_spf_record",
    "rf_has_dmarc",
    "rf_dmarc_policy",
    "rf_has_dkim",
    "rf_security_score",
    "rf_variants_active",
    "rf_active_domains",            # TODOS los activos (resuelven O con MX)
    "rf_cold_email_domains",        # solo los activos con MX (capaces de recibir email)
    "rf_cold_email_count",
    "rf_cold_email_ready_domains",  # activos con MX + DKIM + DMARC (stack completo)
    "rf_cold_email_ready_count",
    "rf_redirecting_domains",       # TODOS los que redirigen (a cualquier destino)
    "rf_redirecting_count",         # count de los que redirigen (cualquier destino)
    "rf_redirecting_to_main",       # solo los que redirigen al dominio principal
    "rf_redirecting_to_main_count", # count de los que redirigen al main
    "rf_whois_main_entity",         # entidad del dominio principal (org o name)
    "rf_whois_main_registrar",
    "rf_whois_same_entity_count",   # variantes activas con la misma entidad
    "rf_whois_all_match",           # true si TODAS las variantes activas matchean al main
    "rf_whois_data",                # JSON {domain: {name, org, registrar, creation, ...}}
    "rf_error",
]


def _clean_domain(raw: str) -> str:
    if not raw:
        return ""
    d = raw.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = re.sub(r"^www\.", "", d)
    d = d.split("/")[0].split("?")[0].strip()
    return d


def _is_valid_domain(d: str) -> bool:
    if not d:
        return False
    return bool(re.match(r"^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$", d))


def _registrable_brand(domain: str) -> str:
    """Devuelve la parte de la marca (antes del primer punto)."""
    return domain.split(".", 1)[0] if "." in domain else domain


def _calc_score(has_spf: bool, has_dmarc: bool, has_dkim: bool) -> str:
    n = sum([has_spf, has_dmarc, has_dkim])
    return ["Poor", "Fair", "Good", "Excellent"][n]


# ---------------------------------------------------------------------------
# WHOIS lookup + normalización de entidades
# ---------------------------------------------------------------------------

_REDACTED_KEYWORDS = [
    "redacted", "privacy", "whoisguard", "data protected", "domain admin",
    "private", "gdpr", "masked", "withheld", "not disclosed", "perfect privacy",
    "contact privacy", "domains by proxy",
]

_LEGAL_SUFFIXES = [
    " s.l.", " s.l", " sl", " s.a.", " s.a", " sa", " sas",
    " inc.", " inc", " ltd.", " ltd", " llc.", " llc",
    " gmbh", " corp.", " corp", " bv", " ag", " plc",
    " limited", " corporation", " company", " co.", " co",
    " group", " holding", " holdings",
]


def _wh_first(v):
    if v is None:
        return None
    if isinstance(v, list):
        v = v[0] if v else None
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


def _is_redacted(name: Optional[str], org: Optional[str]) -> bool:
    for v in (name, org):
        if v and any(k in v.lower() for k in _REDACTED_KEYWORDS):
            return True
    return False


def _entity_key(name: Optional[str], org: Optional[str]) -> Optional[str]:
    """Normaliza una entidad para comparación. Devuelve None si está redacted/vacío."""
    if _is_redacted(name, org):
        return None
    raw = org or name
    if not raw:
        return None
    s = raw.lower().strip()
    # Quitar sufijos legales repetidamente
    changed = True
    while changed:
        changed = False
        for suf in _LEGAL_SUFFIXES:
            if s.endswith(suf):
                s = s[:-len(suf)].strip()
                changed = True
    # Quitar puntuación y espacios extra
    s = re.sub(r"[,.\-_/&]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) >= 2 else None


def _redacted_fingerprint(rec: Dict[str, Any]) -> Optional[str]:
    """Para registros redacted: huella exacta basada en metadatos públicos.

    Si dos dominios redacted comparten exactamente registrar+country+address+
    emails+creation_date, casi con seguridad son del mismo dueño.
    """
    parts = [
        (rec.get("registrar") or "").strip().lower(),
        (rec.get("country") or "").strip().lower(),
        (rec.get("address") or "").strip().lower(),
        "|".join(sorted(e.lower().strip() for e in (rec.get("emails") or []))),
        (rec.get("creation_date") or "").strip(),
    ]
    fp = "::".join(parts)
    # Necesitamos al menos 2 campos no vacíos para que el fingerprint sea informativo
    non_empty = sum(1 for p in parts if p)
    return fp if non_empty >= 2 else None


def _whois_lookup_sync(domain: str) -> Dict[str, Any]:
    """Llamada síncrona a python-whois. Maneja errores devolviéndolos en el dict."""
    if _whois_lib is None:
        return {"domain": domain, "error": "whois library no instalada"}
    try:
        w = _whois_lib.whois(domain)
        name = _wh_first(getattr(w, "name", None))
        org = (_wh_first(getattr(w, "org", None))
               or _wh_first(getattr(w, "organization", None)))
        registrar = _wh_first(getattr(w, "registrar", None))
        country = _wh_first(getattr(w, "country", None))
        # Address puede venir como string o lista de líneas
        address = getattr(w, "address", None)
        if isinstance(address, list):
            address = ", ".join(str(a) for a in address if a)
        address = _wh_first(address)
        city = _wh_first(getattr(w, "city", None))
        state = _wh_first(getattr(w, "state", None))
        zipcode = _wh_first(getattr(w, "zipcode", None))
        # Combinar address completa si hay piezas separadas
        if not address and any([city, state, zipcode]):
            address = ", ".join(p for p in [city, state, zipcode] if p)

        emails = getattr(w, "emails", None)
        if isinstance(emails, list):
            emails = [str(e) for e in emails if e]
        elif emails:
            emails = [str(emails)]
        else:
            emails = []
        creation = getattr(w, "creation_date", None)
        if isinstance(creation, list):
            creation = creation[0] if creation else None
        creation_iso = creation.isoformat() if hasattr(creation, "isoformat") else (
            str(creation) if creation else None)

        rec = {
            "domain": domain,
            "registrant_name": name,
            "registrant_org": org,
            "registrar": registrar,
            "country": country,
            "address": address,
            "emails": emails[:5],
            "creation_date": creation_iso,
            "redacted": _is_redacted(name, org),
        }
        rec["entity_key"] = _entity_key(name, org)
        rec["redacted_fp"] = _redacted_fingerprint(rec) if rec["redacted"] else None
        return rec
    except Exception as e:
        return {"domain": domain, "error": str(e)[:200]}


async def _whois_lookup_async(domain: str) -> Dict[str, Any]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _whois_lookup_sync, domain)


def _safe_str(v: Any) -> str:
    """Convierte cualquier valor a string ASCII-safe para CSV/JSON.

    Filtra surrogate pairs y caracteres de control que pueden romper la
    escritura del archivo o el json.dumps del state.
    """
    if v is None:
        return ""
    if isinstance(v, bool):
        return str(v)
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    # Quitar surrogates aislados y caracteres de control (excepto tab/newline)
    cleaned = []
    for ch in s:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF:
            continue
        if cp < 0x20 and ch not in ("\t",):
            continue
        cleaned.append(ch)
    return "".join(cleaned)


# ---------------------------------------------------------------------------
# Estado serializable
# ---------------------------------------------------------------------------

@dataclass
class JobState:
    id: str
    input_name: str
    domain_column: str
    total: int
    done_indices: List[int] = field(default_factory=list)   # filas completas (ok+skip+error+timeout)
    status: str = "pending"        # pending|running|paused|completed|stopped|error
    created_at: str = ""
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    options: Dict[str, Any] = field(default_factory=dict)
    last_error: Optional[str] = None
    stats: Dict[str, int] = field(default_factory=lambda: {
        "ok": 0, "skipped": 0, "error": 0, "timeout": 0
    })
    aggregates: Dict[str, int] = field(default_factory=lambda: {
        "score_poor": 0, "score_fair": 0, "score_good": 0, "score_excellent": 0,
        "with_active_domains": 0,        # empresas con >=1 variante activa
        "with_redirecting": 0,           # empresas con >=1 variante que redirige
        "with_redirect_to_main": 0,      # empresas con >=1 variante que redirige al main
        "with_whois_match": 0,           # empresas con >=1 variante de la misma entidad
        "with_cold_email_ready": 0,      # empresas con >1 variante con MX+DKIM+DMARC (indica infra cold email dedicada)
        "total_variants_active": 0,      # suma de variantes activas (todas las empresas)
        "total_cold_email_variants": 0,  # suma de variantes con MX
        "total_cold_email_ready": 0,     # suma de variantes con MX+DKIM+DMARC
    })


# ---------------------------------------------------------------------------
# Worker — estado en vivo de cada slot de paralelismo
# ---------------------------------------------------------------------------

class WorkerSlot:
    def __init__(self, slot_id: int):
        self.id = slot_id
        self.index: Optional[int] = None
        self.domain: Optional[str] = None
        self.step: str = ""
        self.started_at: Optional[float] = None
        self.skip_event: asyncio.Event = asyncio.Event()
        self.task: Optional[asyncio.Task] = None

    def snapshot(self) -> Dict[str, Any]:
        elapsed = (time.time() - self.started_at) if (self.started_at and self.domain) else None
        return {
            "id": self.id,
            "index": self.index,
            "domain": self.domain,
            "step": self.step,
            "elapsed": round(elapsed, 1) if elapsed else None,
            "active": self.domain is not None,
        }


# ---------------------------------------------------------------------------
# Job
# ---------------------------------------------------------------------------

class Job:
    """Maneja el ciclo de vida de un procesamiento de CSV con N workers en paralelo."""

    def __init__(self, state: JobState):
        self.state = state
        self.dir = DATA_DIR / state.id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.input_csv = self.dir / "input.csv"
        self.output_csv = self.dir / "output.csv"
        self.state_path = self.dir / "state.json"

        self._done_set: Set[int] = set(state.done_indices)

        self._pause_event = asyncio.Event()
        self._pause_event.set()
        self._stop_flag = False
        self._main_task: Optional[asyncio.Task] = None
        self._subscribers: List[asyncio.Queue] = []
        self._workers: List[WorkerSlot] = []
        self._last_rows: List[Dict[str, Any]] = []
        self._write_lock = asyncio.Lock()
        self._headers_written = False

    # ------------------- Persistencia -------------------

    def save_state(self):
        self.state.done_indices = sorted(self._done_set)
        data = {
            "id": self.state.id,
            "input_name": self.state.input_name,
            "domain_column": self.state.domain_column,
            "total": self.state.total,
            "done_indices": self.state.done_indices,
            "status": self.state.status,
            "created_at": self.state.created_at,
            "started_at": self.state.started_at,
            "finished_at": self.state.finished_at,
            "options": self.state.options,
            "last_error": self.state.last_error,
            "stats": self.state.stats,
            "aggregates": self.state.aggregates,
        }
        tmp = self.state_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.state_path)

    @classmethod
    def load(cls, job_id: str) -> "Job":
        path = DATA_DIR / job_id / "state.json"
        if not path.exists():
            raise FileNotFoundError(f"Job {job_id} no existe")
        data = json.loads(path.read_text(encoding="utf-8"))
        # Backwards-compat: aceptar 'current_index' antiguo
        if "done_indices" not in data and "current_index" in data:
            data["done_indices"] = list(range(int(data["current_index"])))
            data.pop("current_index", None)
        # Sanear campos extra
        allowed = {f.name for f in JobState.__dataclass_fields__.values()}
        data = {k: v for k, v in data.items() if k in allowed}
        state = JobState(**data)
        job = cls(state)
        # Si quedó como "running" en disco es porque el proceso anterior se
        # cortó sin haberse marcado limpio. Lo bajamos a "stopped" para que
        # la UI muestre el botón de Reanudar.
        if state.status == "running":
            state.status = "stopped"
        # Recomputar si los aggregates están vacíos O si quedaron campos viejos
        needs_recompute = (
            not any(state.aggregates.values())
            or "with_redirecting" not in state.aggregates
            or "total_redirecting" in state.aggregates
        )
        if needs_recompute and job.output_csv.exists():
            job._recompute_aggregates()
        job.save_state()
        return job

    def _recompute_aggregates(self):
        """Reconstruye los contadores agregados a partir del output.csv existente."""
        # Reset al schema actual (descarta campos viejos como total_redirecting)
        agg = {
            "score_poor": 0, "score_fair": 0, "score_good": 0, "score_excellent": 0,
            "with_active_domains": 0, "with_redirecting": 0, "with_redirect_to_main": 0,
            "with_whois_match": 0, "with_cold_email_ready": 0,
            "total_variants_active": 0, "total_cold_email_variants": 0,
            "total_cold_email_ready": 0,
        }
        if not self.output_csv.exists():
            self.state.aggregates = agg
            return
        try:
            with self.output_csv.open("r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("rf_status") != "ok":
                        continue
                    score = (row.get("rf_security_score") or "").lower()
                    if score == "poor": agg["score_poor"] += 1
                    elif score == "fair": agg["score_fair"] += 1
                    elif score == "good": agg["score_good"] += 1
                    elif score == "excellent": agg["score_excellent"] += 1

                    def _to_int(v):
                        try:
                            return int(v) if v not in (None, "") else 0
                        except (ValueError, TypeError):
                            return 0

                    if _to_int(row.get("rf_variants_active")) > 0:
                        agg["with_active_domains"] += 1
                    if _to_int(row.get("rf_redirecting_count")) > 0:
                        agg["with_redirecting"] += 1
                    if _to_int(row.get("rf_redirecting_to_main_count")) > 0:
                        agg["with_redirect_to_main"] += 1
                    if _to_int(row.get("rf_whois_same_entity_count")) > 0:
                        agg["with_whois_match"] += 1
                    if _to_int(row.get("rf_cold_email_ready_count")) > 1:
                        agg["with_cold_email_ready"] += 1
                    agg["total_variants_active"] += _to_int(row.get("rf_variants_active"))
                    agg["total_cold_email_variants"] += _to_int(row.get("rf_cold_email_count"))
                    agg["total_cold_email_ready"] += _to_int(row.get("rf_cold_email_ready_count"))
        except Exception:
            pass
        self.state.aggregates = agg

    @classmethod
    def list_all(cls) -> List[Dict[str, Any]]:
        jobs = []
        for d in sorted(DATA_DIR.iterdir(), reverse=True):
            sp = d / "state.json"
            if sp.exists():
                try:
                    data = json.loads(sp.read_text(encoding="utf-8"))
                    done = data.get("done_indices") or list(range(data.get("current_index", 0)))
                    jobs.append({
                        "id": data["id"],
                        "input_name": data.get("input_name"),
                        "status": data.get("status"),
                        "total": data.get("total"),
                        "done_count": len(done),
                        "created_at": data.get("created_at"),
                        "stats": data.get("stats", {}),
                    })
                except Exception:
                    pass
        return jobs

    @classmethod
    def create(cls, input_bytes: bytes, input_name: str, domain_column: str,
               options: Optional[Dict[str, Any]] = None) -> "Job":
        job_id = uuid.uuid4().hex[:12]
        d = DATA_DIR / job_id
        d.mkdir(parents=True, exist_ok=True)

        input_path = d / "input.csv"
        try:
            text = input_bytes.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = input_bytes.decode("latin-1")
        input_path.write_text(text, encoding="utf-8", newline="")

        with input_path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames or domain_column not in reader.fieldnames:
                raise ValueError(
                    f"La columna '{domain_column}' no existe. Columnas: {reader.fieldnames}"
                )
            rows = sum(1 for _ in reader)

        state = JobState(
            id=job_id,
            input_name=input_name,
            domain_column=domain_column,
            total=rows,
            status="pending",
            created_at=datetime.utcnow().isoformat() + "Z",
            options=options or {},
        )
        job = cls(state)
        job.save_state()
        return job

    # ------------------- Suscriptores SSE -------------------

    async def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.append(q)
        await q.put({"type": "snapshot", "data": self.snapshot()})
        return q

    def unsubscribe(self, q: asyncio.Queue):
        try:
            self._subscribers.remove(q)
        except ValueError:
            pass

    def _emit(self, event_type: str, data: Any):
        for q in list(self._subscribers):
            try:
                q.put_nowait({"type": event_type, "data": data})
            except asyncio.QueueFull:
                pass

    def snapshot(self) -> Dict[str, Any]:
        return {
            "id": self.state.id,
            "input_name": self.state.input_name,
            "domain_column": self.state.domain_column,
            "total": self.state.total,
            "done_count": len(self._done_set),
            "status": self.state.status,
            "is_active": self.is_running(),
            "stats": dict(self.state.stats),
            "aggregates": dict(self.state.aggregates),
            "workers": [w.snapshot() for w in self._workers],
            "last_rows": list(self._last_rows[-50:]),
            "options": self.state.options,
            "started_at": self.state.started_at,
            "finished_at": self.state.finished_at,
            "last_error": self.state.last_error,
        }

    # ------------------- Control -------------------

    def pause(self):
        if self.state.status == "running":
            self._pause_event.clear()
            self.state.status = "paused"
            self.save_state()
            self._emit("status", {"status": "paused"})

    def resume(self):
        if self.state.status == "paused":
            self._pause_event.set()
            self.state.status = "running"
            self.save_state()
            self._emit("status", {"status": "running"})

    def skip(self, worker_id: Optional[int] = None):
        """Cancela el dominio actual de un worker (o de todos si worker_id=None)."""
        targets = [w for w in self._workers if (worker_id is None or w.id == worker_id)]
        for w in targets:
            w.skip_event.set()
            if w.task and not w.task.done():
                w.task.cancel()
        self._emit("skip_requested", {"worker_id": worker_id})

    def stop(self):
        self._stop_flag = True
        self._pause_event.set()
        for w in self._workers:
            if w.task and not w.task.done():
                w.task.cancel()
        if self._main_task and not self._main_task.done():
            self._main_task.cancel()

    def is_running(self) -> bool:
        return self._main_task is not None and not self._main_task.done()

    def start(self):
        if self.is_running():
            return
        if self.state.status == "completed":
            return
        self._stop_flag = False
        self._main_task = asyncio.create_task(self._run())

    # ------------------- Loop principal -------------------

    async def _run(self):
        # Agrandamos el ThreadPoolExecutor por defecto de asyncio para que las
        # consultas DNS sincronas (que corren via run_in_executor) no se
        # encolen y causen timeouts cuando hay muchos workers en paralelo.
        loop = asyncio.get_event_loop()
        if not getattr(loop, "_rf_big_executor", False):
            loop.set_default_executor(
                concurrent.futures.ThreadPoolExecutor(max_workers=256, thread_name_prefix="rf-dns")
            )
            loop._rf_big_executor = True

        self.state.status = "running"
        if not self.state.started_at:
            self.state.started_at = datetime.utcnow().isoformat() + "Z"
        self.save_state()
        self._emit("status", {"status": "running"})

        # Cargar filas
        with self.input_csv.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            input_headers = reader.fieldnames or []
            all_rows = list(reader)

        output_headers = list(input_headers)
        for c in OUTPUT_COLUMNS:
            if c not in output_headers:
                output_headers.append(c)
        self._output_headers = output_headers

        # Asegurar header en output.csv si no existe
        if not self.output_csv.exists() or self.output_csv.stat().st_size == 0:
            with self.output_csv.open("w", encoding="utf-8", newline="") as of:
                w = csv.DictWriter(of, fieldnames=output_headers, extrasaction="ignore")
                w.writeheader()

        per_row_timeout = float(self.state.options.get("per_row_timeout", 180))
        # variants_mode: "full" | "cold" | "none". Backwards-compat con discover_variants.
        variants_mode = self.state.options.get("variants_mode")
        if not variants_mode:
            variants_mode = "full" if self.state.options.get("discover_variants", True) else "none"
        max_concurrent = int(self.state.options.get("max_concurrent", 25))
        n_workers = max(1, min(20, int(self.state.options.get("parallel_workers", 5))))
        do_whois = bool(self.state.options.get("do_whois", False))

        # Crear workers
        self._workers = [WorkerSlot(i) for i in range(n_workers)]

        # Cola de índices pendientes
        queue: asyncio.Queue = asyncio.Queue()
        for i in range(self.state.total):
            if i not in self._done_set:
                queue.put_nowait(i)

        # Lanzar workers
        worker_tasks = [
            asyncio.create_task(
                self._worker_loop(w, queue, all_rows, per_row_timeout,
                                  variants_mode, max_concurrent, do_whois)
            )
            for w in self._workers
        ]

        try:
            # return_exceptions=True para que un worker que crashee no
            # propague la excepción y mate a los demás workers.
            results = await asyncio.gather(*worker_tasks, return_exceptions=True)
            worker_errors = [r for r in results if isinstance(r, Exception)
                             and not isinstance(r, asyncio.CancelledError)]
            if self._stop_flag:
                self.state.status = "stopped"
            elif len(self._done_set) >= self.state.total:
                self.state.status = "completed"
                self.state.finished_at = datetime.utcnow().isoformat() + "Z"
            elif worker_errors:
                # Todos los workers terminaron pero quedaron filas sin procesar:
                # algo se rompió. Guardamos error pero el job es reanudable.
                self.state.status = "error"
                self.state.last_error = f"{len(worker_errors)} worker(s) fallaron: " + \
                    "; ".join(str(e)[:120] for e in worker_errors[:3])
            else:
                # Workers exitaron limpiamente sin terminar — raro pero recoverable
                self.state.status = "stopped"
        except asyncio.CancelledError:
            self.state.status = "stopped"
            for t in worker_tasks:
                t.cancel()
        except Exception as e:
            self.state.status = "error"
            self.state.last_error = str(e)
        finally:
            for w in self._workers:
                w.domain = None
                w.index = None
                w.step = ""
                w.started_at = None
            self.save_state()
            self._emit("status", {"status": self.state.status})
            self._emit("finished", self.snapshot())

    async def _worker_loop(self, slot: WorkerSlot, queue: asyncio.Queue,
                           all_rows: List[Dict[str, str]],
                           per_row_timeout: float, variants_mode: str,
                           max_concurrent: int, do_whois: bool = False):
        dns_checker = DNSChecker()
        discovery = DomainDiscovery()

        while True:
            try:
                await self._pause_event.wait()
                if self._stop_flag:
                    return
                try:
                    idx = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return

                if idx in self._done_set:
                    continue

                await self._process_one_row(
                    slot, idx, all_rows, dns_checker, discovery,
                    per_row_timeout, variants_mode, max_concurrent, do_whois,
                )
            except asyncio.CancelledError:
                # Solo se propaga si es un stop real, no un skip
                if self._stop_flag:
                    raise
                # skip individual de fila — ya manejado dentro de _process_one_row
                continue
            except Exception as e:
                # Cualquier otra excepción en este worker (e.g. write fail) la
                # logueamos en last_rows pero el worker SIGUE vivo procesando.
                err_event = {
                    "worker": slot.id,
                    "index": slot.index,
                    "domain": slot.domain,
                    "status": "error",
                    "error": f"worker exception: {str(e)[:200]}",
                    "seconds": 0,
                }
                self._last_rows.append(err_event)
                self._emit("row_done", err_event)
                # No marcamos como done — la fila quedará pendiente para retry
                slot.domain = None
                slot.index = None
                slot.started_at = None
                slot.step = ""
                continue

    async def _process_one_row(self, slot: WorkerSlot, idx: int,
                               all_rows: List[Dict[str, str]],
                               dns_checker: DNSChecker, discovery: DomainDiscovery,
                               per_row_timeout: float, variants_mode: str,
                               max_concurrent: int, do_whois: bool = False):
        row = all_rows[idx]
        raw_domain = row.get(self.state.domain_column, "") or ""
        domain = _clean_domain(raw_domain)

        slot.index = idx
        slot.domain = domain or raw_domain
        slot.step = "iniciando"
        slot.started_at = time.time()
        slot.skip_event.clear()

        self._emit("row_start", {
            "worker": slot.id, "index": idx,
            "domain": slot.domain, "raw": raw_domain,
        })

        result_cols: Dict[str, Any] = {c: "" for c in OUTPUT_COLUMNS}
        result_cols["rf_original_index"] = idx
        result_cols["rf_processed_at"] = datetime.utcnow().isoformat() + "Z"

        t0 = time.time()

        if not _is_valid_domain(domain):
            result_cols["rf_status"] = "error"
            result_cols["rf_error"] = f"Dominio inválido: '{raw_domain}'"
            self.state.stats["error"] += 1
        else:
            slot.task = asyncio.create_task(
                self._process_domain(slot, domain, dns_checker, discovery,
                                     variants_mode, max_concurrent, do_whois)
            )
            try:
                result = await asyncio.wait_for(slot.task, timeout=per_row_timeout)
                result_cols.update(result)
                if slot.skip_event.is_set():
                    result_cols["rf_status"] = "skipped"
                    self.state.stats["skipped"] += 1
                else:
                    result_cols["rf_status"] = "ok"
                    self.state.stats["ok"] += 1
            except asyncio.TimeoutError:
                if slot.task and not slot.task.done():
                    slot.task.cancel()
                result_cols["rf_status"] = "timeout"
                result_cols["rf_error"] = f"Timeout (>{per_row_timeout}s)"
                self.state.stats["timeout"] += 1
            except asyncio.CancelledError:
                if self._stop_flag:
                    slot.domain = None
                    slot.index = None
                    slot.started_at = None
                    slot.task = None
                    raise
                result_cols["rf_status"] = "skipped"
                result_cols["rf_error"] = "Saltado por el usuario"
                self.state.stats["skipped"] += 1
            except Exception as e:
                result_cols["rf_status"] = "error"
                result_cols["rf_error"] = str(e)[:300]
                self.state.stats["error"] += 1
            finally:
                slot.task = None

        result_cols["rf_seconds"] = round(time.time() - t0, 2)

        # Sanitizar valores para que no rompan CSV/JSON (caracteres surrogate, etc.)
        merged = {**row, **result_cols}
        merged = {k: _safe_str(v) for k, v in merged.items()}

        try:
            async with self._write_lock:
                with self.output_csv.open("a", encoding="utf-8", newline="") as of:
                    w = csv.DictWriter(of, fieldnames=self._output_headers,
                                       extrasaction="ignore")
                    w.writerow(merged)
                self._done_set.add(idx)
                # Aggregates: solo cuentan filas "ok"
                if result_cols.get("rf_status") == "ok":
                    score = (result_cols.get("rf_security_score") or "").lower()
                    if score in ("poor", "fair", "good", "excellent"):
                        self.state.aggregates[f"score_{score}"] += 1
                    if int(result_cols.get("rf_variants_active") or 0) > 0:
                        self.state.aggregates["with_active_domains"] += 1
                    if int(result_cols.get("rf_redirecting_count") or 0) > 0:
                        self.state.aggregates["with_redirecting"] += 1
                    if int(result_cols.get("rf_redirecting_to_main_count") or 0) > 0:
                        self.state.aggregates["with_redirect_to_main"] += 1
                    if int(result_cols.get("rf_whois_same_entity_count") or 0) > 0:
                        self.state.aggregates["with_whois_match"] += 1
                    if int(result_cols.get("rf_cold_email_ready_count") or 0) > 1:
                        self.state.aggregates["with_cold_email_ready"] += 1
                    self.state.aggregates["total_variants_active"] += int(
                        result_cols.get("rf_variants_active") or 0)
                    self.state.aggregates["total_cold_email_variants"] += int(
                        result_cols.get("rf_cold_email_count") or 0)
                    self.state.aggregates["total_cold_email_ready"] += int(
                        result_cols.get("rf_cold_email_ready_count") or 0)
                self.save_state()
        except Exception as e:
            # Si falla la escritura no queremos romper el worker.
            # La fila queda como "no-done" y se reintentará si se reanuda.
            result_cols["rf_status"] = "error"
            result_cols["rf_error"] = f"write_fail: {str(e)[:200]}"

        row_event = {
            "worker": slot.id,
            "index": idx,
            "domain": slot.domain,
            "status": result_cols["rf_status"],
            "seconds": result_cols["rf_seconds"],
            "has_mx": result_cols.get("rf_has_mx"),
            "mx_provider": result_cols.get("rf_mx_provider"),
            "has_spf": result_cols.get("rf_has_spf"),
            "has_dmarc": result_cols.get("rf_has_dmarc"),
            "has_dkim": result_cols.get("rf_has_dkim"),
            "security_score": result_cols.get("rf_security_score"),
            "variants_active": result_cols.get("rf_variants_active"),
            "active_domains": result_cols.get("rf_active_domains"),
            "cold_email_count": result_cols.get("rf_cold_email_count"),
            "cold_email_domains": result_cols.get("rf_cold_email_domains"),
            "cold_email_ready_count": result_cols.get("rf_cold_email_ready_count"),
            "cold_email_ready_domains": result_cols.get("rf_cold_email_ready_domains"),
            "redirecting_count": result_cols.get("rf_redirecting_count"),
            "redirecting_domains": result_cols.get("rf_redirecting_domains"),
            "redirecting_to_main_count": result_cols.get("rf_redirecting_to_main_count"),
            "redirecting_to_main": result_cols.get("rf_redirecting_to_main"),
            "whois_main_entity": result_cols.get("rf_whois_main_entity"),
            "whois_same_entity_count": result_cols.get("rf_whois_same_entity_count"),
            "whois_all_match": result_cols.get("rf_whois_all_match"),
            "error": result_cols.get("rf_error"),
        }
        self._last_rows.append(row_event)
        if len(self._last_rows) > 200:
            self._last_rows = self._last_rows[-200:]
        self._emit("row_done", row_event)
        self._emit("progress", {
            "done_count": len(self._done_set),
            "total": self.state.total,
            "stats": dict(self.state.stats),
            "aggregates": dict(self.state.aggregates),
        })

        slot.domain = None
        slot.index = None
        slot.started_at = None
        slot.step = ""

    async def _process_domain(self, slot: WorkerSlot, domain: str,
                              dns_checker: DNSChecker, discovery: DomainDiscovery,
                              variants_mode: str, max_concurrent: int,
                              do_whois: bool = False) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        loop = asyncio.get_event_loop()

        slot.step = "DNS principal"
        self._emit("worker_step", {"worker": slot.id, "step": slot.step})

        mx_task = loop.run_in_executor(None, dns_checker.check_mx_records, domain)
        spf_task = loop.run_in_executor(None, dns_checker.check_spf_record, domain)
        dmarc_task = loop.run_in_executor(None, dns_checker.check_dmarc_record, domain)
        dkim_task = dns_checker.check_dkim_record_async(domain)

        mx, spf, dmarc, dkim = await asyncio.gather(mx_task, spf_task, dmarc_task, dkim_task)

        if slot.skip_event.is_set():
            return out

        has_mx = bool(mx.get("has_mx"))
        has_spf = bool(spf.get("has_spf") and spf.get("valid"))
        has_dmarc = bool(dmarc.get("has_dmarc") and dmarc.get("valid"))
        has_dkim = bool(dkim.get("has_dkim") and dkim.get("valid"))

        out["rf_has_mx"] = has_mx
        out["rf_mx_provider"] = mx.get("provider") or ""
        servers = mx.get("servers") or []
        out["rf_mx_servers"] = ";".join(s.get("server", "") for s in servers)
        out["rf_has_spf"] = has_spf
        out["rf_spf_record"] = spf.get("record") or ""
        out["rf_has_dmarc"] = has_dmarc
        out["rf_dmarc_policy"] = (
            (dmarc.get("policy") or {}).get("policy", "") if has_dmarc else ""
        )
        out["rf_has_dkim"] = has_dkim
        out["rf_security_score"] = _calc_score(has_spf, has_dmarc, has_dkim)

        if variants_mode != "none" and not slot.skip_event.is_set():
            try:
                chunk_size = max(10, max_concurrent)

                async def _process_list(variants_list: List[str], label: str,
                                        existing: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
                    """Procesa variantes en chunks emitiendo progreso."""
                    total = len(variants_list)
                    results: List[Dict[str, Any]] = list(existing)
                    base_done = len(existing)
                    for i in range(0, total, chunk_size):
                        if slot.skip_event.is_set():
                            break
                        chunk = variants_list[i:i + chunk_size]
                        r = await discovery._check_bulk_with_semaphore(chunk, max_concurrent)
                        results.extend(r)
                        n_active = sum(1 for x in results if x.get("likely_used"))
                        progressed = len(results) - base_done
                        slot.step = f"{label} {progressed}/{total} · {n_active} activas"
                        self._emit("worker_step", {"worker": slot.id, "step": slot.step})
                    return results

                if variants_mode == "cascade":
                    cold_variants = discovery.generate_variants_mode(domain, "cold")
                    full_variants = discovery.generate_variants_mode(domain, "full")
                    extra_variants = [v for v in full_variants if v not in set(cold_variants)]

                    all_results = await _process_list(cold_variants, "cold", [])
                    n_active_after_cold = sum(1 for r in all_results if r.get("likely_used"))

                    if n_active_after_cold > 0 and not slot.skip_event.is_set():
                        slot.step = f"cascada: expandiendo a +{len(extra_variants)} variantes"
                        self._emit("worker_step", {"worker": slot.id, "step": slot.step})
                        all_results = await _process_list(extra_variants, "full", all_results)
                else:
                    variants = discovery.generate_variants_mode(domain, variants_mode)
                    all_results = await _process_list(variants, "variantes", [])

                active_raw = [r for r in all_results if r.get("likely_used")]
                if active_raw and not slot.skip_event.is_set():
                    slot.step = f"verificando redirects de {len(active_raw)} activos"
                    self._emit("worker_step", {"worker": slot.id, "step": slot.step})
                    active = list(await asyncio.gather(
                        *[discovery._enrich_domain(r) for r in active_raw]
                    ))
                else:
                    active = active_raw

                cold = [a for a in active if a.get("has_mx")]
                cold_ready = [
                    a for a in cold
                    if a.get("has_dkim") and a.get("has_dmarc")
                ]
                brand = _registrable_brand(domain)

                def _redirects_to_main(a: Dict[str, Any]) -> bool:
                    if not a.get("redirects"):
                        return False
                    rt = (a.get("redirect_to") or "").lower()
                    if not rt:
                        return False
                    if rt == domain or rt.endswith("." + domain):
                        return True
                    return _registrable_brand(rt) == brand

                redirecting_all = [a for a in active if a.get("redirects") and a.get("redirect_to")]
                redirecting_main = [a for a in redirecting_all if _redirects_to_main(a)]

                out["rf_variants_active"] = len(active)
                # Todos los activos, con marcas: [mx dkim dmarc →destino]
                def _label(a: Dict[str, Any]) -> str:
                    tags = []
                    if a.get("has_mx"):     tags.append("mx")
                    if a.get("has_dkim"):   tags.append("dkim")
                    if a.get("has_dmarc"):
                        pol = a.get("dmarc_policy") or ""
                        tags.append(f"dmarc:{pol}" if pol else "dmarc")
                    if a.get("redirects") and a.get("redirect_to"):
                        tags.append(f"→{a['redirect_to']}")
                    return f"{a['domain']}" + (f"[{' '.join(tags)}]" if tags else "")
                out["rf_active_domains"] = ";".join(_label(a) for a in active)
                out["rf_cold_email_count"] = len(cold)
                out["rf_cold_email_domains"] = ";".join(a["domain"] for a in cold)
                out["rf_cold_email_ready_count"] = len(cold_ready)
                out["rf_cold_email_ready_domains"] = ";".join(_label(a) for a in cold_ready)
                out["rf_redirecting_count"] = len(redirecting_all)
                out["rf_redirecting_domains"] = ";".join(
                    f"{a['domain']}->{a.get('redirect_to') or ''}" for a in redirecting_all
                )
                out["rf_redirecting_to_main_count"] = len(redirecting_main)
                out["rf_redirecting_to_main"] = ";".join(
                    f"{a['domain']}->{a.get('redirect_to') or ''}" for a in redirecting_main
                )
            except Exception as e:
                out["rf_error"] = f"variantes: {str(e)[:200]}"
                active = []
        else:
            active = []

        # ----------------- WHOIS opcional -----------------
        if do_whois and not slot.skip_event.is_set():
            try:
                slot.step = "WHOIS principal"
                self._emit("worker_step", {"worker": slot.id, "step": slot.step})

                # WHOIS del main y de cada variante activa, en paralelo (cap 5)
                whois_sem = asyncio.Semaphore(5)

                async def _guarded_whois(d: str) -> Dict[str, Any]:
                    async with whois_sem:
                        return await _whois_lookup_async(d)

                variant_domains = [a["domain"] for a in active]
                whois_tasks = [_guarded_whois(domain)] + [
                    _guarded_whois(d) for d in variant_domains
                ]
                slot.step = f"WHOIS 0/{len(whois_tasks)}"
                self._emit("worker_step", {"worker": slot.id, "step": slot.step})

                whois_results = await asyncio.gather(*whois_tasks, return_exceptions=True)

                main_whois = whois_results[0] if not isinstance(whois_results[0], Exception) else {}
                variants_whois = [
                    r for r in whois_results[1:] if not isinstance(r, Exception)
                ]

                # Para el JSON del CSV, no exportamos campos internos
                _internal = {"entity_key", "redacted_fp"}
                whois_data = {}
                if main_whois:
                    whois_data[domain] = {
                        k: v for k, v in main_whois.items() if k not in _internal
                    }
                for vw in variants_whois:
                    whois_data[vw["domain"]] = {
                        k: v for k, v in vw.items() if k not in _internal
                    }

                main_key = main_whois.get("entity_key") if main_whois else None
                main_fp = main_whois.get("redacted_fp") if main_whois else None
                matching_variants = []
                matching_via_redacted: List[str] = []
                for vw in variants_whois:
                    v_key = vw.get("entity_key")
                    v_fp = vw.get("redacted_fp")
                    matched = False
                    # 1) match por entidad normalizada (los que NO están redacted)
                    if main_key and v_key and main_key == v_key:
                        matched = True
                    # 2) match por fingerprint exacto cuando AMBOS están redacted
                    elif main_fp and v_fp and main_fp == v_fp:
                        matched = True
                        matching_via_redacted.append(vw["domain"])
                    if matched:
                        matching_variants.append(vw["domain"])

                out["rf_whois_main_entity"] = (
                    main_whois.get("registrant_org")
                    or main_whois.get("registrant_name")
                    or ""
                ) if main_whois else ""
                out["rf_whois_main_registrar"] = (
                    main_whois.get("registrar") or ""
                ) if main_whois else ""
                out["rf_whois_same_entity_count"] = len(matching_variants)
                out["rf_whois_all_match"] = (
                    len(matching_variants) == len(variants_whois) and len(variants_whois) > 0
                )
                out["rf_whois_data"] = json.dumps(
                    whois_data, default=str, ensure_ascii=False
                )
            except Exception as e:
                # No reventar la fila por un fallo de WHOIS — solo registrar
                prev = out.get("rf_error") or ""
                out["rf_error"] = (prev + f" | whois: {str(e)[:120]}").strip(" |")

        return out

    # ------------------- Descarga ordenada -------------------

    def get_sorted_output_path(self) -> Path:
        """Devuelve un CSV ordenado por rf_original_index para descargar."""
        if not self.output_csv.exists():
            return self.output_csv
        sorted_path = self.dir / "output_sorted.csv"
        with self.output_csv.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames
            rows = list(reader)
        try:
            rows.sort(key=lambda r: int(r.get("rf_original_index") or 0))
        except Exception:
            pass
        with sorted_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
            writer.writeheader()
            for r in rows:
                writer.writerow(r)
        return sorted_path
