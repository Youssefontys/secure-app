"""Counts what one measurement yielded and writes measurement.json.
Usage: count.py <out folder> <variant> <db_ms> <db_exit> <gen_ms> <gen_exit> <scan_ms> <scan_exit>"""
import collections
import json
import os
import pathlib
import sys

out, variant = pathlib.Path(sys.argv[1]), sys.argv[2]
db_ms, db_exit, gen_ms, gen_exit, scan_ms, scan_exit = map(int, sys.argv[3:9])
# The copies pip carries in pip/_vendor, with their own known vulnerabilities.
VENDORED = ("urllib3", "msgpack", "setuptools")


# CycloneDX can put components in components; Trivy does that for the Python packages.
def walk(components):
    for c in components or []:
        yield c
        yield from walk(c.get("components"))


sbom = json.loads((out / "sbom.json").read_text(encoding="utf-8"))
# Syft also puts every file in the SBoM; only the packages are counted, as with Trivy.
components = [c for c in walk(sbom.get("components")) if c.get("type") != "file"]
kinds = collections.Counter(c["purl"].split("/")[0].removeprefix("pkg:") if c.get("purl", "").startswith("pkg:") else c.get("type", "?")
                            for c in components)
pypi = {c["name"].lower() for c in components if c.get("purl", "").startswith("pkg:pypi/")}

scan = json.loads((out / "scan.json").read_text(encoding="utf-8"))
if variant == "trivy":
    findings = {(v["VulnerabilityID"], v["PkgName"]) for r in scan.get("Results") or [] for v in r.get("Vulnerabilities") or []}
else:
    findings = {(m["vulnerability"]["id"], m["artifact"]["name"]) for m in scan.get("matches", [])
                if m["vulnerability"]["severity"].upper() in ("HIGH", "CRITICAL")}

result = {
    "variant": variant, "image": os.environ["IMAGE"], "repetition": int(os.environ["REPETITION"]),
    "ms_database": db_ms, "ms_generate": gen_ms, "ms_scan": scan_ms,
    "exit_database": db_exit, "exit_generate": gen_exit, "exit_scan": scan_exit,
    "cyclonedx": sbom.get("specVersion"), "components": len(components), "kinds": dict(kinds),
    "copies_in_pip": sum(name in pypi for name in VENDORED), "high_critical_with_fix": len(findings),
    "findings": sorted(f"{i} ({p})" for i, p in findings),
}
(out / "measurement.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
print(json.dumps(result))
