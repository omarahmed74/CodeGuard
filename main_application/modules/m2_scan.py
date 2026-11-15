"""
M2 — Vulnerability Scanning
============================
Runs Snyk (proprietary vulnerability intelligence, not an open-source
feed like Grype/NVD/GHSA) against the extracted project directory, then
normalizes Snyk's raw JSON into the exact flat schema found in the
uploaded clean_findings.json:

    {package, version, cve, cvss, severity, description, fix_version[]}

Snyk is used here as `snyk test --all-projects --json` against the
extracted source tree (manifest-based scanning), rather than
`snyk sbom test` against the Syft-generated SBOM — the SBOM-testing
endpoint requires a Snyk Enterprise plan, while `snyk test` works on
Free/Team plans and covers the same dependency set for this project's
supported ecosystems (npm, pip, etc). The Syft-generated SBOM is still
used elsewhere (M1) purely for the dependency inventory shown in the
dashboard; it is no longer the input to this scan.

Python/pip caveat handled here: unlike npm/yarn (where Snyk can read a
lockfile statically), Snyk's pip support inspects what's *actually
installed* in a Python environment rather than just the versions
pinned in requirements.txt. An uploaded project has never been
`pip install`ed anywhere, so without help Snyk silently resolves zero
dependencies for it (under --all-projects this fails silently rather
than raising an error — you just get an empty result). To fix that,
_prepare_python_venv() below creates a disposable virtualenv, installs
the project's requirements.txt into it, and points Snyk at that venv's
Python interpreter via --command.
"""

import json
import os
import platform
import shutil
import subprocess
import tempfile
import time
import venv as venv_module


class VulnerabilityScanError(Exception):
    """Raised when Snyk is missing, fails, or produces unreadable output."""


def check_snyk_available() -> bool:
    return shutil.which("snyk") is not None


def _find_requirements_file(project_root: str):
    """Look for a requirements.txt in the usual places. Returns the full
    path if found, else None. (Poetry/Pipfile projects aren't handled
    here yet — Snyk resolves those differently and this project's
    sample apps only ever use requirements.txt.)"""
    for name in ("requirements.txt", os.path.join("requirements", "base.txt"),
                 os.path.join("requirements", "prod.txt")):
        candidate = os.path.join(project_root, name)
        if os.path.isfile(candidate):
            return candidate
    return None


def _install_requirements(venv_python: str, requirements_path: str,
                           per_package_timeout: int = 30,
                           overall_timeout: int = 150):
    """
    Install requirements.txt into the venv, fast path first: try one
    batch `pip install -r requirements.txt` (a single subprocess call —
    quick when every package installs cleanly, which is the common
    case). Only if that fails does it fall back to installing each line
    individually, since pip's default behavior is to abort the ENTIRE
    batch if even one package fails (e.g. an old pinned version with no
    prebuilt wheel for the current Python, needing a C build toolchain
    pip doesn't have) — which would otherwise leave the venv completely
    empty even though every other package would have installed fine.
    """
    try:
        batch = subprocess.run(
            [venv_python, "-m", "pip", "install", "--prefer-binary",
             "--disable-pip-version-check", "-r", requirements_path],
            capture_output=True, text=True, timeout=overall_timeout,
            encoding="utf-8", errors="replace",
        )
        if batch.returncode == 0:
            return  # fast path succeeded, nothing more to do
    except (subprocess.TimeoutExpired, OSError):
        pass  # fall through to the slower per-package retry below

    # Slow path: one pip install per line, so a single bad package only
    # costs that one package instead of blocking everything else.
    try:
        with open(requirements_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return

    start = time.monotonic()
    for raw_line in lines:
        # Strip inline comments; blank/comment-only/pip-option lines
        # (-r other.txt, -e ., --index-url ...) aren't a single
        # installable package spec, so they're skipped.
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        if time.monotonic() - start > overall_timeout:
            break
        try:
            subprocess.run(
                [venv_python, "-m", "pip", "install", "--prefer-binary",
                 "--disable-pip-version-check", line],
                capture_output=True, text=True, timeout=per_package_timeout,
                encoding="utf-8", errors="replace",
            )
        except (subprocess.TimeoutExpired, OSError):
            pass  # this one package didn't make it — move on to the next


def _prepare_python_venv(requirements_path: str, timeout: int):
    """
    Create a disposable virtualenv and install requirements.txt into it
    (see _install_requirements — fast batch attempt first, falling back
    to one-by-one only if needed), so Snyk
    can inspect what's actually installed. Best-effort: if venv creation
    fails outright, returns (None, None) and the scan proceeds exactly as
    it did before this feature existed (Snyk will just resolve whatever
    it can, which may be nothing for a pip project — same as before).

    Returns (venv_dir, venv_python_path). Caller is responsible for
    deleting venv_dir once the scan using it is finished.
    """
    venv_dir = tempfile.mkdtemp(prefix="codeguard_snyk_venv_")
    try:
        venv_module.create(venv_dir, with_pip=True)
    except Exception:
        shutil.rmtree(venv_dir, ignore_errors=True)
        return None, None

    if platform.system() == "Windows":
        venv_python = os.path.join(venv_dir, "Scripts", "python.exe")
    else:
        venv_python = os.path.join(venv_dir, "bin", "python")

    if not os.path.exists(venv_python):
        shutil.rmtree(venv_dir, ignore_errors=True)
        return None, None

    _install_requirements(venv_python, requirements_path, overall_timeout=timeout)

    return venv_dir, venv_python


def run_snyk_scan(project_root: str, output_path: str, timeout: int = 300,
                   pip_install_timeout: int = 150) -> list:
    """
    Run Snyk against the extracted project directory and write the raw
    JSON to `output_path`. Returns the parsed raw JSON, always as a
    list of per-manifest result objects (Snyk emits a single JSON object
    when only one manifest is found, and a JSON array when
    `--all-projects` finds more than one — this normalizes both cases).

        snyk test --all-projects --json --json-file-output=<output_path>
        [--command=<venv_python>]   # added automatically for pip projects

    Requires `snyk auth` (or a SNYK_TOKEN environment variable) to have
    already been run once on this machine — see README for setup.
    """
    if not check_snyk_available():
        raise VulnerabilityScanError(
            "Snyk CLI is not installed or not on PATH. Install it with "
            "'npm install -g snyk' and authenticate with 'snyk auth' (or set "
            "SNYK_TOKEN) before running a scan. See "
            "https://docs.snyk.io/snyk-cli/install-or-update-the-snyk-cli"
        )

    # Snyk runs with project_root as its working directory, so keep the
    # report location stable when callers pass a relative application path.
    output_path = os.path.abspath(output_path)

    # --- Python/pip: install requirements into a throwaway venv first ---
    # (skippable via CODEGUARD_SKIP_PIP_INSTALL=1 — Snyk will then just
    # resolve pip deps statically from requirements.txt, which may yield
    # fewer/zero findings for that ecosystem, but nothing gets installed.)
    venv_dir = None
    venv_python = None
    skip_pip_install = os.environ.get("CODEGUARD_SKIP_PIP_INSTALL", "").lower() in ("1", "true", "yes")
    if not skip_pip_install:
        requirements_path = _find_requirements_file(project_root)
        if requirements_path:
            venv_dir, venv_python = _prepare_python_venv(requirements_path, pip_install_timeout)

    try:
        # On Windows, `npm install -g snyk` creates a `snyk.cmd` shim rather
        # than a `snyk.exe`. subprocess.run(["snyk", ...]) with a plain arg
        # list won't reliably resolve/execute that shim (CreateProcess
        # doesn't run .cmd/.bat files directly the way it runs real
        # executables), even though shutil.which("snyk") finds it fine as a
        # *path*. Routing through `cmd.exe /c` makes Windows interpret the
        # shim correctly; on macOS/Linux, snyk is a real executable so no
        # shell wrapping is needed.
        snyk_path = shutil.which("snyk")

        snyk_args = ["test", "--all-projects", "--json", f"--json-file-output={output_path}"]
        if venv_python:
            snyk_args.append(f"--command={venv_python}")

        if platform.system() == "Windows":
            cmd = ["cmd", "/c", snyk_path] + snyk_args
        else:
            cmd = [snyk_path] + snyk_args

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, cwd=project_root,
                encoding="utf-8", errors="replace",
            )
        except subprocess.TimeoutExpired as exc:
            raise VulnerabilityScanError(
                f"Snyk timed out after {timeout}s scanning the project."
            ) from exc

        # Snyk's exit codes are NOT the usual 0-is-success convention:
        #   0 = scan completed, no vulnerabilities found
        #   1 = scan completed, vulnerabilities WERE found (this is normal,
        #       not a failure — the whole point of running the scan)
        #   2 = the scan itself failed (bad/missing auth, network error,
        #       unparsable manifest, etc.)
        if result.returncode not in (0, 1):
            # Snyk usually writes error detail as a JSON object to stdout
            # (since --json was requested) rather than stderr, so stderr
            # alone is often empty — surface whichever actually has
            # content, and try to pull out Snyk's own "error"/"message"
            # field for a cleaner message first.
            detail = None
            stdout_text = (result.stdout or "").strip()
            if stdout_text:
                try:
                    parsed = json.loads(stdout_text)
                    if isinstance(parsed, dict):
                        detail = parsed.get("error") or parsed.get("message")
                except json.JSONDecodeError:
                    pass
            if not detail:
                detail = (result.stderr or "").strip() or stdout_text or "(no output captured)"

            raise VulnerabilityScanError(
                f"Snyk exited with code {result.returncode}: {detail[:2000]}\n"
                "Common causes: not authenticated (run 'snyk auth' or set "
                "SNYK_TOKEN), the free/team plan's test limit was reached, "
                "or a flag/argument Snyk's CLI version doesn't support."
            )

        try:
            with open(output_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            raise VulnerabilityScanError(
                f"Snyk ran but produced unreadable JSON output: {exc}"
            ) from exc

        return raw if isinstance(raw, list) else [raw]
    finally:
        if venv_dir:
            shutil.rmtree(venv_dir, ignore_errors=True)


def clean_findings(raw_snyk_results: list) -> list:
    """
    Flatten Snyk's raw per-manifest result objects into the clean_findings.json
    schema.

    Snyk vulnerability shape (per `snyk test --json`):
        vulnerability.id / .title / .severity / .cvssScore / .fixedIn[]
        vulnerability.identifiers.CVE[] / .packageName / .version

    Missing CVSS score -> None. Missing fix info -> empty list, never a
    fabricated version.

    Snyk's own advisory id (e.g. SNYK-JS-LODASH-567746) is always
    assigned, whether or not a CVE Numbering Authority has also issued a
    CVE for the same issue. Where a CVE exists, it's used as `cve`
    (matching what the rest of the pipeline / report expects) with the
    Snyk id preserved in `advisory_id` for traceability; where no CVE
    exists yet, the Snyk id is used as `cve` directly.
    """
    findings = []
    for project_result in raw_snyk_results:
        if not isinstance(project_result, dict):
            continue
        for vuln in project_result.get("vulnerabilities", []):
            snyk_id = vuln.get("id", "Unknown")
            cves = (vuln.get("identifiers") or {}).get("CVE") or []
            cve_id = cves[0] if cves else snyk_id
            advisory_id = snyk_id if cves else None

            findings.append({
                "package": vuln.get("packageName"),
                "version": vuln.get("version"),
                "cve": cve_id,
                "advisory_id": advisory_id,
                "cvss": vuln.get("cvssScore"),
                "severity": (vuln.get("severity") or "unknown").capitalize(),
                "description": vuln.get("title") or "",
                "fix_version": vuln.get("fixedIn") or [],
            })

    return findings


def severity_summary(findings: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for f in findings:
        key = (f.get("severity") or "unknown").lower()
        if key not in counts:
            key = "unknown"
        counts[key] += 1
    counts["total"] = len(findings)
    return counts
