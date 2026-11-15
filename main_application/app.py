"""
M4 — Dashboard, Integration & Final Reporting
================================================
Flask app that orchestrates the existing M1 (Syft), M2 (Snyk), and
M3 (Gemini enrichment) pieces behind one upload -> scan -> results ->
report workflow.

Run:
    python app.py
Then open http://localhost:5000
"""

import json
import os
import shutil
import threading
import traceback
import uuid
import zipfile
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

from modules import m1_sbom, m2_scan, m3_enrich, report

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
OUTPUT_DIR = BASE_DIR / "outputs"
UPLOAD_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

MAX_UPLOAD_MB = 50
ALLOWED_EXTENSIONS = {".zip"}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

# In-memory job registry. Fine for a local single-user demo; each job
# also persists its status to outputs/<job_id>/status.json so state
# survives a process restart.
JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()


# ------------------------------------------------------------------
# Job helpers
# ------------------------------------------------------------------

def job_paths(job_id: str) -> dict:
    out = OUTPUT_DIR / job_id
    return {
        "upload_dir": UPLOAD_DIR / job_id,
        "extract_dir": UPLOAD_DIR / job_id / "extracted",
        "out_dir": out,
        "sbom": out / "sbom.json",
        "snyk_raw": out / "snyk_raw.json",
        "clean_findings": out / "clean_findings.json",
        "ai_results": out / "ai_results.json",
        "status": out / "status.json",
        "report": out / "report.pdf",
        "report_xlsx": out / "report.xlsx",
    }


def set_status(job_id: str, **fields):
    with JOBS_LOCK:
        JOBS.setdefault(job_id, {})
        JOBS[job_id].update(fields)
        snapshot = dict(JOBS[job_id])
    paths = job_paths(job_id)
    paths["out_dir"].mkdir(parents=True, exist_ok=True)
    with open(paths["status"], "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2)


def get_status(job_id: str) -> dict | None:
    with JOBS_LOCK:
        if job_id in JOBS:
            return dict(JOBS[job_id])
    paths = job_paths(job_id)
    if paths["status"].exists():
        with open(paths["status"], "r", encoding="utf-8") as f:
            return json.load(f)
    return None


def safe_extract_zip(zip_path: Path, dest_dir: Path):
    """Extract a zip while guarding against zip-slip path traversal."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.infolist():
            member_path = (dest_dir / member.filename).resolve()
            if not str(member_path).startswith(str(dest_dir.resolve())):
                raise ValueError(f"Unsafe path in zip: {member.filename}")
        zf.extractall(dest_dir)

    # Uploaded zips often wrap everything in one top-level folder
    # (e.g. intern/). If so, treat that as the real project root.
    entries = [p for p in dest_dir.iterdir() if p.name != "__MACOSX"]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest_dir


def find_package_json(root: Path) -> str | None:
    for p in root.rglob("package.json"):
        if "node_modules" not in p.parts:
            return str(p)
    return None


# ------------------------------------------------------------------
# Pipeline (runs in a background thread)
# ------------------------------------------------------------------

def run_pipeline(job_id: str, project_root: Path, project_name: str):
    paths = job_paths(job_id)
    try:
        set_status(job_id, stage="generating_sbom", message="Running Syft to generate the SBOM…", error=None)
        sbom = m1_sbom.generate_sbom(str(project_root), str(paths["sbom"]))
        sbom_summary = m1_sbom.summarize_sbom(sbom)
        pkg_json = find_package_json(project_root)
        sbom_summary["dependencies"] = m1_sbom.mark_direct_dependencies(
            sbom_summary["dependencies"], pkg_json
        )

        _skip_pip = os.environ.get("CODEGUARD_SKIP_PIP_INSTALL", "").lower() in ("1", "true", "yes")
        _scan_msg = (
            "Running Snyk against the project…" if _skip_pip
            else "Running Snyk against the project (installing Python deps first, if any)…"
        )
        set_status(job_id, stage="scanning_vulnerabilities", message=_scan_msg)
        raw = m2_scan.run_snyk_scan(str(project_root), str(paths["snyk_raw"]))
        findings = m2_scan.clean_findings(raw)
        with open(paths["clean_findings"], "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)
        severity_counts = m2_scan.severity_summary(findings)

        set_status(
            job_id, stage="enriching_ai", message="Enriching findings with AI analysis…",
            ai_progress={"done": 0, "total": len(findings)},
        )

        def on_progress(i, total, cve, ok):
            set_status(
                job_id, stage="enriching_ai",
                message=f"Analyzing finding {i} of {total} ({cve})…",
                ai_progress={"done": i, "total": total},
            )

        ai_results = m3_enrich.enrich_findings(
            findings, output_path=str(paths["ai_results"]), on_progress=on_progress
        )
        merged = m3_enrich.merge_enrichment(findings, ai_results)

        with open(paths["out_dir"] / "merged_results.json", "w", encoding="utf-8") as f:
            json.dump({
                "project_name": project_name,
                "sbom_summary": sbom_summary,
                "severity_counts": severity_counts,
                "findings": merged,
            }, f, indent=2)

        failed = sum(1 for f in merged if f.get("ai") is None)
        if failed:
            # Don't report a clean "Scan complete" if AI enrichment silently
            # failed for some/all findings — that's how you end up with a
            # dashboard full of unexplained "Pending" rows and no clue why.
            if m3_enrich.quota_exhausted_last_run():
                reason = (
                    "the Gemini free-tier daily quota (500 requests/day) is exhausted — "
                    "wait for it to reset, enable billing on the Google AI Studio project, "
                    "or re-run later (already-enriched findings are cached, so a re-run "
                    "won't re-spend quota on them)."
                )
            else:
                reason = (
                    "check the server terminal for the reason "
                    "(commonly an invalid/rotated GEMINI_API_KEY)."
                )
            set_status(
                job_id, stage="completed",
                message=(
                    f"Scan complete, but AI enrichment failed for {failed}/{len(merged)} "
                    f"findings — {reason}"
                ),
                error=None,
            )
        else:
            set_status(job_id, stage="completed", message="Scan complete.", error=None)

    except (m1_sbom.SBOMGenerationError, m2_scan.VulnerabilityScanError, m3_enrich.AIEnrichmentError) as exc:
        set_status(job_id, stage="error", message=str(exc), error=str(exc))
    except Exception as exc:  # noqa: BLE001 — surface unexpected errors to the UI, don't crash the thread silently
        traceback.print_exc()
        set_status(job_id, stage="error", message=f"Unexpected error: {exc}", error=str(exc))


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/upload", methods=["POST"])
def upload():
    if "project" not in request.files:
        return jsonify({"error": "No file field named 'project' in the request."}), 400

    file = request.files["project"]
    if file.filename == "":
        return jsonify({"error": "No file selected."}), 400

    filename = secure_filename(file.filename)
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({"error": "Only .zip uploads are supported."}), 400

    job_id = uuid.uuid4().hex[:12]
    paths = job_paths(job_id)
    paths["upload_dir"].mkdir(parents=True, exist_ok=True)
    zip_path = paths["upload_dir"] / filename
    file.save(zip_path)

    try:
        project_root = safe_extract_zip(zip_path, paths["extract_dir"])
    except (zipfile.BadZipFile, ValueError) as exc:
        set_status(job_id, stage="error", message=f"Invalid zip file: {exc}", error=str(exc))
        return jsonify({"error": f"Invalid zip file: {exc}"}), 400

    project_name = os.path.splitext(filename)[0]
    set_status(
        job_id, stage="uploaded", message="Project uploaded.", error=None,
        project_name=project_name, created_at=datetime.now().isoformat(),
    )

    with JOBS_LOCK:
        JOBS[job_id]["_project_root"] = str(project_root)

    return jsonify({"job_id": job_id, "project_name": project_name})


@app.route("/api/scan/<job_id>", methods=["POST"])
def start_scan(job_id):
    status = get_status(job_id)
    if not status:
        return jsonify({"error": "Unknown job_id. Upload a project first."}), 404
    if status.get("stage") in ("generating_sbom", "scanning_vulnerabilities", "enriching_ai"):
        return jsonify({"error": "A scan is already running for this job."}), 409

    with JOBS_LOCK:
        project_root = JOBS.get(job_id, {}).get("_project_root")
    if not project_root:
        return jsonify({"error": "Project files not found for this job. Re-upload."}), 400

    project_name = status.get("project_name", "uploaded-project")
    thread = threading.Thread(
        target=run_pipeline, args=(job_id, Path(project_root), project_name), daemon=True
    )
    thread.start()
    set_status(job_id, stage="queued", message="Scan starting…")
    return jsonify({"ok": True})


@app.route("/api/jobs")
def list_jobs():
    """
    List every past scan saved on disk (outputs/<job_id>/status.json),
    newest first, so the UI can offer a 'previous scans' picker instead
    of only ever showing the most recent job.
    """
    jobs = []
    if OUTPUT_DIR.exists():
        for d in OUTPUT_DIR.iterdir():
            if not d.is_dir():
                continue
            status_path = d / "status.json"
            if not status_path.exists():
                continue
            try:
                with open(status_path, "r", encoding="utf-8") as f:
                    s = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue
            jobs.append({
                "job_id": d.name,
                "project_name": s.get("project_name", d.name),
                "stage": s.get("stage"),
                "message": s.get("message"),
                "created_at": s.get("created_at") or datetime.fromtimestamp(d.stat().st_mtime).isoformat(),
                "has_results": (d / "merged_results.json").exists(),
            })

    def sort_key(j):
        return j.get("created_at") or ""

    jobs.sort(key=sort_key, reverse=True)
    return jsonify({"jobs": jobs})


@app.route("/api/status/<job_id>")
def status(job_id):
    s = get_status(job_id)
    if not s:
        return jsonify({"error": "Unknown job_id."}), 404
    return jsonify({k: v for k, v in s.items() if not k.startswith("_")})


@app.route("/api/results/<job_id>")
def results(job_id):
    paths = job_paths(job_id)
    merged_path = paths["out_dir"] / "merged_results.json"
    if not merged_path.exists():
        return jsonify({"error": "Results not ready yet."}), 404
    with open(merged_path, "r", encoding="utf-8") as f:
        return jsonify(json.load(f))


@app.route("/api/report/<job_id>", methods=["POST"])
def generate_report(job_id):
    paths = job_paths(job_id)
    merged_path = paths["out_dir"] / "merged_results.json"
    if not merged_path.exists():
        return jsonify({"error": "Run a scan before generating a report."}), 400

    with open(merged_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    html = report.generate_report_html(
        project_name=data["project_name"],
        sbom_summary=data["sbom_summary"],
        severity_counts=data["severity_counts"],
        merged_findings=data["findings"],
    )
    pdf_bytes = report.generate_report_pdf(html)
    with open(paths["report"], "wb") as f:
        f.write(pdf_bytes)

    xlsx_bytes = report.generate_report_xlsx(
        project_name=data["project_name"],
        sbom_summary=data["sbom_summary"],
        severity_counts=data["severity_counts"],
        merged_findings=data["findings"],
    )
    with open(paths["report_xlsx"], "wb") as f:
        f.write(xlsx_bytes)

    return jsonify({
        "ok": True,
        "download_url": f"/api/report/{job_id}/download",
        "download_url_xlsx": f"/api/report/{job_id}/download.xlsx",
    })


@app.route("/api/report/<job_id>/download")
def download_report(job_id):
    paths = job_paths(job_id)
    if not paths["report"].exists():
        return jsonify({"error": "Report not generated yet."}), 404
    return send_file(
        paths["report"],
        as_attachment=True,
        download_name=f"security-report-{job_id}.pdf",
        mimetype="application/pdf",
    )


@app.route("/api/report/<job_id>/download.xlsx")
def download_report_xlsx(job_id):
    paths = job_paths(job_id)
    if not paths["report_xlsx"].exists():
        return jsonify({"error": "Report not generated yet."}), 404
    return send_file(
        paths["report_xlsx"],
        as_attachment=True,
        download_name=f"security-report-{job_id}.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)
