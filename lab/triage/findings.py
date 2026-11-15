"""Subquestion 2: puts every finding of Trivy together with EPSS (FIRST), KEV (CISA) and whether the app loads the package.
Usage: findings.py <out folder with scan.json, loaded-files.txt and loaded-packages.txt>.
Writes markdown to stdout and findings.csv in the out folder."""
import collections
import csv
import json
import pathlib
import sys
import urllib.request

out = pathlib.Path(sys.argv[1])
ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def get_json(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "secure-app-lab"}), timeout=60) as r:
        return json.load(r)


scan = json.loads((out / "scan.json").read_text(encoding="utf-8"))
rows = []
for result in scan.get("Results") or []:
    for v in result.get("Vulnerabilities") or []:
        rows.append({"id": v["VulnerabilityID"], "package": v["PkgName"], "installed": v.get("InstalledVersion", ""),
                     "fixed": v.get("FixedVersion", ""), "severity": v.get("Severity", "UNKNOWN"), "type": result.get("Type", "")})

cves = sorted({r["id"] for r in rows if r["id"].startswith("CVE-")})
epss = {}
for i in range(0, len(cves), 80):
    data = get_json("https://api.first.org/data/v1/epss?cve=" + ",".join(cves[i:i + 80]))
    epss.update({d["cve"]: float(d["epss"]) for d in data.get("data", [])})
kev = {v["cveID"] for v in get_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")["vulnerabilities"]}

loaded_packages = set((out / "loaded-packages.txt").read_text(encoding="utf-8").split())
loaded_files = (out / "loaded-files.txt").read_text(encoding="utf-8")
for r in rows:
    r["epss"] = epss.get(r["id"])
    r["kev"] = r["id"] in kev
    # A Debian package counts as loaded if one of its files is mapped; a Python package if a file under its folder is.
    r["loaded"] = r["package"] in loaded_packages or f"/site-packages/{r['package'].replace('-', '_')}" in loaded_files

with open(out / "findings.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["id", "package", "installed", "fixed", "severity", "type", "epss", "kev", "loaded"])
    w.writeheader()
    w.writerows(sorted(rows, key=lambda r: (ORDER.index(r["severity"]) if r["severity"] in ORDER else 9, r["package"], r["id"])))

count = collections.Counter(r["severity"] for r in rows)
print(f"## Subquestion 2: {len(rows)} findings on the image, without a filter\n")
print("| Severity | Findings | With a fix | EPSS >= 1% | In KEV | Package loaded |")
print("|---|---|---|---|---|---|")
for s in ORDER:
    group = [r for r in rows if r["severity"] == s]
    if group:
        print(f"| {s} | {len(group)} | {sum(bool(r['fixed']) for r in group)} | {sum((r['epss'] or 0) >= 0.01 for r in group)} | "
              f"{sum(r['kev'] for r in group)} | {sum(r['loaded'] for r in group)} |")
print(f"\nLoaded: {len(loaded_packages)} Debian packages, {loaded_files.count(chr(10))} files.\n")
print("### HIGH and CRITICAL, one by one\n")
print("| Finding | Package | Installed | Fixed | Severity | EPSS | KEV | Loaded |")
print("|---|---|---|---|---|---|---|---|")
for r in rows:
    if r["severity"] in ("CRITICAL", "HIGH"):
        e = "-" if r["epss"] is None else f"{r['epss'] * 100:.2f}%"
        print(f"| {r['id']} | {r['package']} | {r['installed']} | {r['fixed'] or '-'} | {r['severity']} | {e} | "
              f"{'yes' if r['kev'] else 'no'} | {'yes' if r['loaded'] else 'no'} |")
