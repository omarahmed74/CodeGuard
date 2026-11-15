"""
M1 — SBOM Generation
=====================
Thin wrapper around the *existing* M1 tool: Syft, run as a CLI subprocess,
producing a CycloneDX JSON SBOM — exactly the format already found in
the uploaded intern/sbom.json (bomFormat: CycloneDX, specVersion 1.7).

No SBOM-generation logic is reimplemented here. This module's only job
is to invoke the real `syft` binary the same way M1 already does, and
hand back the parsed JSON + a small summary for the dashboard.
"""

import json
import shutil
import subprocess


class SBOMGenerationError(Exception):
    """Raised when Syft is missing, fails, or produces unreadable output."""


def check_syft_available() -> bool:
    return shutil.which("syft") is not None


def generate_sbom(source_dir: str, output_path: str, timeout: int = 300) -> dict:
    """
    Run Syft against `source_dir` and write a CycloneDX JSON SBOM to
    `output_path`. Returns the parsed SBOM dict.

    Mirrors the command used to produce the sample sbom.json:
        syft <source_dir> -o cyclonedx-json=<output_path>
    """
    if not check_syft_available():
        raise SBOMGenerationError(
            "Syft is not installed or not on PATH. Install it from "
            "https://github.com/anchore/syft before running a scan."
        )

    cmd = ["syft", source_dir, "-o", f"cyclonedx-json={output_path}"]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        raise SBOMGenerationError(
            f"Syft timed out after {timeout}s scanning the uploaded project."
        ) from exc

    if result.returncode != 0:
        raise SBOMGenerationError(
            f"Syft exited with code {result.returncode}.\n"
            f"stderr: {result.stderr.strip()[:2000]}"
        )

    try:
        with open(output_path, "r", encoding="utf-8") as f:
            sbom = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise SBOMGenerationError(
            f"Syft ran but produced unreadable SBOM output: {exc}"
        ) from exc

    return sbom


def summarize_sbom(sbom: dict) -> dict:
    """Extract dashboard-friendly dependency info from a CycloneDX SBOM."""
    components = sbom.get("components", [])

    deps = []
    for c in components:
        purl = c.get("purl", "")
        ecosystem = purl.split(":")[1].split("/")[0] if purl.startswith("pkg:") else "unknown"
        licenses = c.get("licenses", [])
        license_id = None
        if licenses:
            lic = licenses[0].get("license", {})
            license_id = lic.get("id") or lic.get("name")
        deps.append({
            "name": c.get("name"),
            "version": c.get("version"),
            "ecosystem": ecosystem,
            "license": license_id or "—",
            "type": c.get("type", "library"),
        })

    return {
        "total_dependencies": len(components),
        "tool": sbom.get("metadata", {}).get("tools", {}).get("components", [{}])[0].get("name", "syft"),
        "dependencies": deps,
    }


def mark_direct_dependencies(deps: list, package_json_path: str | None) -> list:
    """
    Best-effort direct-vs-transitive tagging by cross-referencing the
    uploaded project's package.json "dependencies" keys. If no
    package.json is found (non-Node project), everything is tagged
    "unknown" rather than guessed.
    """
    direct_names = set()
    if package_json_path:
        try:
            with open(package_json_path, "r", encoding="utf-8") as f:
                pkg = json.load(f)
            direct_names = set(pkg.get("dependencies", {}).keys()) | set(
                pkg.get("devDependencies", {}).keys()
            )
        except (OSError, json.JSONDecodeError):
            pass

    for d in deps:
        if not direct_names:
            d["dep_type"] = "unknown"
        else:
            d["dep_type"] = "direct" if d["name"] in direct_names else "transitive"
    return deps
