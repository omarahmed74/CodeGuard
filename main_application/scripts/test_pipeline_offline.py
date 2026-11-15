"""
Offline pipeline test — proves the M1 summarization, M2 severity
counting, and the merge + report generation logic all work correctly,
using the REAL sample data already produced by the team (no Syft/Snyk
binaries or live API calls required).

Run from the project root:
    python scripts/test_pipeline_offline.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules import m1_sbom, m2_scan, m3_enrich, report

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"

def main():
    sbom = json.loads((SAMPLES / "sbom.sample.json").read_text())
    clean = json.loads((SAMPLES / "clean_findings.sample.json").read_text())
    ai_results = json.loads((SAMPLES / "ai_results.sample.json").read_text())

    sbom_summary = m1_sbom.summarize_sbom(sbom)
    print(f"[M1] total dependencies: {sbom_summary['total_dependencies']}")
    assert sbom_summary["total_dependencies"] == len(sbom["components"])

    severity_counts = m2_scan.severity_summary(clean)
    print(f"[M2] severity summary: {severity_counts}")
    assert severity_counts["total"] == len(clean)

    merged = m3_enrich.merge_enrichment(clean, ai_results)
    matched = sum(1 for m in merged if m["ai"] is not None)
    print(f"[M3] merged {matched}/{len(merged)} findings with AI enrichment")
    assert matched == len(ai_results), "Every AI result should match a clean finding by cve id"

    html = report.generate_report_html(
        project_name="sample-vulnerable-app",
        sbom_summary=sbom_summary,
        severity_counts=severity_counts,
        merged_findings=merged,
    )
    out_path = ROOT / "outputs" / "offline_test_report.html"
    out_path.parent.mkdir(exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    print(f"[Report] wrote {out_path} ({len(html)} bytes)")

    print("\nAll offline pipeline checks passed.")

if __name__ == "__main__":
    main()
