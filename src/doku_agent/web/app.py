"""FastAPI-App: server-gerendert, ohne externe Ressourcen, mit Basic-Auth und CSRF-Schutz."""

from __future__ import annotations

import json
import secrets
import threading
import uuid
from pathlib import Path
from urllib.parse import quote, urlsplit

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from doku_agent import markdown
from doku_agent.apply import ApplyError, apply_proposal, reject_proposal, validate_selection
from doku_agent.context import Context
from doku_agent.egress import allowed_hosts
from doku_agent.extract import MAX_BYTES
from doku_agent.jobs import JOBS, STARTABLE
from doku_agent.netbox_plan import PlanError, validate_plan
from doku_agent.netbox_sync import CATEGORY_LABELS

HERE = Path(__file__).parent
CSRF_COOKIE = "doku_csrf"
STATUS_LABELS = {"pending": "offen", "applied": "übernommen", "rejected": "abgelehnt", "failed": "fehlgeschlagen",
                 "queued": "wartet", "running": "läuft", "done": "fertig"}


def diff_lines(diff: str) -> list[tuple[str, str]]:
    out = []
    for line in diff.splitlines():
        if line.startswith(("+++", "---", "#")):
            cls = "meta"
        elif line.startswith("@@"):
            cls = "hunk"
        elif line.startswith("+"):
            cls = "add"
        elif line.startswith("-"):
            cls = "del"
        else:
            cls = "ctx"
        out.append((cls, line))
    return out


def _redirect(url: str, msg: str = "", error: bool = False) -> RedirectResponse:
    if msg:
        url += ("&" if "?" in url else "?") + ("err=" if error else "msg=") + quote(msg)
    return RedirectResponse(url, status_code=303)


def _apply_wiki_edits(ctx: Context, pid: int, payload: dict, title, path, tags, content) -> None:
    content = content.replace("\r\n", "\n") if content is not None else None
    new_tags = [t.strip() for t in tags.split(",") if t.strip()] if tags is not None else None
    new_path = path.strip().strip("/") if path and payload["action"] == "create" else None
    changed = False
    for key, value in (("title", title), ("content", content), ("tags", new_tags), ("path", new_path)):
        if value is not None and value != payload.get(key):
            payload[key] = value
            changed = True
    if changed:
        payload["edited"] = True
        current = "" if payload["action"] == "create" else ctx.wiki.get_page(int(payload["page_id"])).content
        diff = markdown.unified_diff(current, payload["content"], payload["path"])
        ctx.store.update_proposal(pid, payload=payload, diff=diff)


def create_app(ctx: Context) -> FastAPI:
    if not ctx.cfg.web.password:
        raise RuntimeError("web.password muss gesetzt sein (Basic-Auth für die Oberfläche)")
    app = FastAPI(title="doku-agent", docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.globals.update(jobs=JOBS, status_labels=STATUS_LABELS, categories=CATEGORY_LABELS)
    security = HTTPBasic(realm="doku-agent")
    ctx.store.reset_open_questions()  # nach einem Neustart hängengebliebene Fragen

    def auth(creds: HTTPBasicCredentials = Depends(security)) -> str:
        ok_user = secrets.compare_digest(creds.username.encode(), ctx.cfg.web.username.encode())
        ok_pass = secrets.compare_digest(creds.password.encode(), ctx.cfg.web.password.encode())
        if not (ok_user and ok_pass):
            raise HTTPException(401, "Anmeldung erforderlich", headers={"WWW-Authenticate": 'Basic realm="doku-agent"'})
        return creds.username

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        token = request.cookies.get(CSRF_COOKIE) or secrets.token_urlsafe(32)
        request.state.csrf = token
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        response.headers["Referrer-Policy"] = "same-origin"
        if request.cookies.get(CSRF_COOKIE) != token:
            response.set_cookie(CSRF_COOKIE, token, httponly=True, samesite="strict")
        return response

    def check_csrf(request: Request, csrf: str = Form("")) -> None:
        origin = request.headers.get("origin")
        if origin and urlsplit(origin).netloc != request.headers.get("host"):
            raise HTTPException(403, "Ungültiger Ursprung (Origin)")
        cookie = request.cookies.get(CSRF_COOKIE, "")
        if not cookie or not secrets.compare_digest(cookie, csrf):
            raise HTTPException(403, "Ungültiges oder fehlendes CSRF-Token – Seite neu laden")

    def render(request: Request, name: str, **data) -> HTMLResponse:
        data.update(csrf=request.state.csrf, pending=ctx.store.count_pending(),
                    msg=request.query_params.get("msg"), err=request.query_params.get("err"))
        return templates.TemplateResponse(request, name, data)

    @app.get("/healthz", response_class=PlainTextResponse)
    def healthz():
        return "ok"

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request, user: str = Depends(auth)):
        return render(request, "index.html", proposals=ctx.store.list_proposals("pending", 10),
                      recent_jobs=ctx.store.list_jobs(8), startable=STARTABLE, schedule=ctx.cfg.schedule)

    # --- Vorschläge -------------------------------------------------------

    @app.get("/vorschlaege", response_class=HTMLResponse)
    def proposals(request: Request, status: str = "pending", user: str = Depends(auth)):
        return render(request, "proposals.html", proposals=ctx.store.list_proposals(status or None), status=status)

    @app.get("/vorschlaege/{pid}", response_class=HTMLResponse)
    def proposal(request: Request, pid: int, user: str = Depends(auth)):
        prop = ctx.store.get_proposal(pid)
        if prop is None:
            raise HTTPException(404, "Vorschlag nicht gefunden")
        steps_json = json.dumps(prop.payload.get("steps", []), indent=2, ensure_ascii=False)
        return render(request, "proposal.html", p=prop, diff=diff_lines(prop.diff), steps_json=steps_json)

    @app.post("/vorschlaege/{pid}/freigeben")
    def approve(pid: int, _: None = Depends(check_csrf), user: str = Depends(auth),
                title: str = Form(None), path: str = Form(None), tags: str = Form(None),
                content: str = Form(None), steps: str = Form(None), change: list[str] | None = Form(None),
                version: str = Form(None)):
        prop = ctx.store.get_proposal(pid)
        if prop is None:
            raise HTTPException(404, "Vorschlag nicht gefunden")
        if version and version != prop.updated_at:
            # Ein Lauf hat den Vorschlag neu berechnet, während die Seite offen war.
            return _redirect(f"/vorschlaege/{pid}", "Der Vorschlag wurde inzwischen aktualisiert – bitte erneut "
                             "prüfen und dann übernehmen.", error=True)
        payload = dict(prop.payload)
        try:
            if payload.get("changes"):
                # Auswahl vor dem Schreiben prüfen; ein Auswahlfehler lässt den Vorschlag offen.
                validate_selection(payload["changes"], set(change or []))
                payload["selected"] = list(change or [])
                ctx.store.update_proposal(pid, payload=payload)
            elif prop.kind == "netbox_plan" and steps is not None:
                new_steps = json.loads(steps)
                validate_plan(new_steps)
                if new_steps != payload["steps"]:
                    payload["steps"] = new_steps
                    ctx.store.update_proposal(pid, payload=payload)
            elif prop.kind == "wiki_page":
                _apply_wiki_edits(ctx, pid, payload, title, path, tags, content)
            result = apply_proposal(ctx, pid)
        except (json.JSONDecodeError, PlanError) as exc:
            return _redirect(f"/vorschlaege/{pid}", f"Plan ungültig: {exc}", error=True)
        except ApplyError as exc:
            if ctx.store.get_proposal(pid).status == "pending":
                return _redirect(f"/vorschlaege/{pid}", str(exc), error=True)
            return _redirect(f"/vorschlaege/{pid}", f"Fehler beim Übernehmen: {exc}", error=True)
        except Exception as exc:
            return _redirect(f"/vorschlaege/{pid}", f"Fehler beim Übernehmen: {exc}", error=True)
        if result != "applied":
            return _redirect(f"/vorschlaege/{pid}", result, error=True)
        return _redirect("/vorschlaege", f"Vorschlag #{pid} übernommen.")

    @app.post("/vorschlaege/{pid}/ablehnen")
    def reject(pid: int, _: None = Depends(check_csrf), user: str = Depends(auth), ignore: str = Form("")):
        reject_proposal(ctx, pid, ignore=bool(ignore))
        return _redirect("/vorschlaege", f"Vorschlag #{pid} abgelehnt" + (" und ignoriert." if ignore else "."))

    @app.post("/vorschlaege/{pid}/wieder-oeffnen")
    def reopen(pid: int, _: None = Depends(check_csrf), user: str = Depends(auth)):
        prop = ctx.store.get_proposal(pid)
        if prop is None or prop.status not in ("failed", "rejected"):
            return _redirect(f"/vorschlaege/{pid}", "Nur abgelehnte oder fehlgeschlagene Vorschläge.", error=True)
        ctx.store.update_proposal(pid, status="pending", result="Wieder geöffnet")
        return _redirect(f"/vorschlaege/{pid}", "Vorschlag wieder geöffnet.")

    # --- Jobs & Aufträge --------------------------------------------------

    @app.get("/jobs", response_class=HTMLResponse)
    def jobs(request: Request, user: str = Depends(auth)):
        return render(request, "jobs.html", job_list=ctx.store.list_jobs(100), startable=STARTABLE)

    @app.get("/jobs/{jid}", response_class=HTMLResponse)
    def job(request: Request, jid: int, user: str = Depends(auth)):
        j = ctx.store.get_job(jid)
        if j is None:
            raise HTTPException(404, "Job nicht gefunden")
        return render(request, "job.html", j=j)

    @app.post("/jobs")
    def start_job(_: None = Depends(check_csrf), user: str = Depends(auth), name: str = Form(...)):
        if name not in STARTABLE:
            return _redirect("/jobs", f"Job {name} kann nicht direkt gestartet werden.", error=True)
        jid = ctx.store.enqueue(name, {})
        return _redirect(f"/jobs/{jid}", "Job eingeplant – er startet, sobald der vorherige fertig ist.")

    @app.get("/auftrag", response_class=HTMLResponse)
    def task_form(request: Request, user: str = Depends(auth)):
        return render(request, "task.html")

    @app.post("/auftrag")
    async def task_submit(request: Request, user: str = Depends(auth), csrf: str = Form(""),
                          instruction: str = Form(""), target_path: str = Form(""),
                          files: list[UploadFile] = File(default=[])):
        check_csrf(request, csrf)
        if not instruction.strip():
            return _redirect("/auftrag", "Bitte beschreibe, was dokumentiert werden soll.", error=True)
        upload_dir = ctx.cfg.upload_dir / uuid.uuid4().hex
        saved = []
        for upload in files or []:
            if not upload.filename:
                continue
            upload_dir.mkdir(parents=True, exist_ok=True)
            target = upload_dir / (Path(upload.filename).name or "datei")
            data = await upload.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                return _redirect("/auftrag", f"{upload.filename} ist größer als 20 MB.", error=True)
            target.write_bytes(data)
            saved.append(str(target))
        jid = ctx.store.enqueue("freeform", {"instruction": instruction.strip(), "target_path": target_path.strip(),
                                             "files": saved, "upload_dir": str(upload_dir)})
        return _redirect(f"/jobs/{jid}", "Auftrag eingeplant. Das Ergebnis erscheint als Vorschlag.")

    # --- Fragen ans Wiki ---------------------------------------------------

    @app.get("/fragen", response_class=HTMLResponse)
    def questions(request: Request, user: str = Depends(auth)):
        from doku_agent import semantic
        try:
            ready = semantic.is_ready(ctx)
        except Exception:
            ready = False
        return render(request, "questions.html", questions=ctx.store.list_questions(), ready=ready)

    @app.post("/fragen")
    def ask(_: None = Depends(check_csrf), user: str = Depends(auth), question: str = Form("")):
        from doku_agent import semantic
        if not ctx.cfg.embeddings.enabled:
            return _redirect("/fragen", "Embeddings sind in der Konfiguration deaktiviert.", error=True)
        text = question.strip()[:1000]
        if not text:
            return _redirect("/fragen", "Bitte eine Frage eingeben.", error=True)
        qid = ctx.store.add_question(text)
        threading.Thread(target=semantic.run_question, args=(ctx, qid), name=f"frage-{qid}", daemon=True).start()
        return _redirect(f"/fragen/{qid}")

    @app.get("/fragen/{qid}", response_class=HTMLResponse)
    def question(request: Request, qid: int, user: str = Depends(auth)):
        q = ctx.store.get_question(qid)
        if q is None:
            raise HTTPException(404, "Frage nicht gefunden")
        return render(request, "question.html", q=q)

    # --- Wiki-Lint ----------------------------------------------------------

    @app.get("/wiki-lint", response_class=HTMLResponse)
    def wiki_lint(request: Request, user: str = Depends(auth)):
        from doku_agent.lint import REPORT_KEY
        return render(request, "lint.html", report=ctx.store.kv_get(REPORT_KEY),
                      page_url=ctx.wiki.page_url)

    # --- Konventionen & Status --------------------------------------------

    @app.get("/konventionen", response_class=HTMLResponse)
    def conventions(request: Request, bereich: str = "", user: str = Depends(auth)):
        from doku_agent.conventions import Conventions

        conv = Conventions(ctx.wiki, ctx.cfg.wiki.convention_sample_pages)
        try:
            areas = conv.areas(depth=3)
            profile = conv.profile(bereich.strip("/")) if bereich else None
            error = ""
        except Exception as exc:
            areas, profile, error = [], None, str(exc)
        return render(request, "conventions.html", areas=areas, profile=profile, bereich=bereich, error=error,
                      paths=ctx.cfg.wiki.paths)

    @app.get("/status", response_class=HTMLResponse)
    def status(request: Request, user: str = Depends(auth)):
        return render(request, "status.html", checks=run_checks(ctx), hosts=sorted(allowed_hosts(ctx.cfg)),
                      ignores=ctx.store.list_ignores())

    @app.post("/ignorierliste/entfernen")
    def unignore(_: None = Depends(check_csrf), user: str = Depends(auth), key: str = Form(...)):
        ctx.store.unignore(key)
        return _redirect("/status", f"{key} wird wieder vorgeschlagen.")

    return app


def run_checks(ctx: Context) -> list[tuple[str, bool, str]]:
    """Verbindungstest aller Dienste (auch für 'doku-agent check')."""
    checks = []

    def check(name, fn):
        try:
            checks.append((name, True, fn()))
        except Exception as exc:
            checks.append((name, False, str(exc)[:300]))

    def llm():
        models = ctx.llm.models()
        if ctx.cfg.llm.model not in models and f"{ctx.cfg.llm.model}:latest" not in models:
            raise RuntimeError(f"Modell {ctx.cfg.llm.model} fehlt (vorhanden: {', '.join(models) or 'keine'})")
        return f"Modell {ctx.cfg.llm.model} vorhanden"

    def netbox():
        major, minor = ctx.netbox.version()
        return f"Version {major}.{minor}"

    def netbox_fields():
        from doku_agent import netbox_fields as nf
        fs = nf.status(ctx.netbox, ctx.cfg.netbox.custom_fields)
        if fs.steps:
            raise RuntimeError("fehlen oder sind nicht für Geräte und VMs freigeschaltet – die Discovery schlägt "
                               "das Anlegen vor")
        if fs.hints:
            raise RuntimeError(" ".join(fs.hints))
        return "vorhanden: " + ", ".join(sorted(nf.field_names(ctx.cfg.netbox.custom_fields).values()))

    def fortigate(dev):
        info = ctx.fortigate(dev.name).system()
        return f"{info['hostname']}, FortiOS {info['version']}"

    def intune_permissions():
        areas = list(ctx.cfg.intune.include)
        if ctx.cfg.intune.resolve_group_names and "groups" not in areas:
            areas.append("groups")
        missing = ctx.intune.missing_permissions(areas)
        if missing:
            raise RuntimeError("fehlende Anwendungsberechtigungen (Administratorzustimmung nötig): " + "; ".join(
                f"{perm} für {', '.join(found)}" for perm, found in missing.items()))
        return "Berechtigungen für " + ", ".join(areas) + " vorhanden"

    def entra_permissions():
        from doku_agent.generators.entra_docs import NEEDS, PROBE_AREAS
        cfg = ctx.cfg.entra
        groups = set().union(*(NEEDS[a] for a in cfg.include)) if cfg.include else set()
        areas = [PROBE_AREAS[g] for g in sorted(groups)]  # dieselben Daten, die der Job lädt
        areas += ["groups"] if groups & {"ca", "methods"} else []  # Gruppen in Zuweisungen und Zielen
        areas += ["users"] if cfg.user_names != "count" or cfg.breakglass else []
        areas += ["apps"] if "ca" in groups else []
        missing = ctx.entra.missing_permissions(areas)
        optional = missing.pop("Application.Read.All", None)
        if missing:
            raise RuntimeError("fehlende Anwendungsberechtigungen (Administratorzustimmung nötig): " + "; ".join(
                f"{perm} für {', '.join(found)}" for perm, found in missing.items()))
        return "Berechtigungen vorhanden" + (
            "; optional fehlt Application.Read.All (App-Namen erscheinen als ID)" if optional else "")

    def embeddings():
        models = ctx.llm.models()
        model = ctx.cfg.embeddings.model
        if model not in models and f"{model}:latest" not in models:
            raise RuntimeError(f"Modell {model} fehlt (docker compose --profile setup run --rm ollama-pull)")
        return f"Modell {model} vorhanden"

    check("Sprachmodell (Ollama)", llm)
    if ctx.cfg.embeddings.enabled:
        check("Embedding-Modell (Ollama)", embeddings)
    check("Wiki.js", lambda: f"{len(ctx.wiki.list_pages())} Seiten lesbar")
    if ctx.cfg.netbox.enabled:
        check("Netbox", netbox)
        if ctx.cfg.netbox.custom_fields.enabled:
            check("Netbox Custom Fields", netbox_fields)
    if ctx.cfg.wazuh.enabled:
        check("Wazuh", lambda: f"{len(ctx.wazuh.agents())} Agents")
    if ctx.cfg.intune.enabled:
        check("Intune (Graph)", lambda: f"{len(ctx.intune.managed_devices())} verwaltete Geräte")
        check("Intune-Berechtigungen", intune_permissions)
    if ctx.cfg.entra.enabled:
        check("Entra ID (Graph)", lambda: f"{len(ctx.entra.ca_policies())} Conditional-Access-Richtlinien" + (
            " (über Graph beta – v1.0 liefert einen Serverfehler bei Microsoft)" if ctx.entra.ca_via_beta else ""))
        check("Entra-Berechtigungen", entra_permissions)
    if ctx.cfg.fortigate.enabled:
        for dev in ctx.cfg.fortigate.devices:
            check(f"FortiGate {dev.name}", lambda dev=dev: fortigate(dev))
    return checks
