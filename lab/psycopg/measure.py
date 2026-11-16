"""Proof after subquestion 3: measures one variant of the app while the local stack runs (scripts/deployment.py local):
the security test, what the app loads, the SBoM and the brake as in the pipeline (with the VEX of main), and the speed
to the database. Runs on a runner through .github/workflows/sq3-psycopg.yml, not locally.
Usage: python lab/psycopg/measure.py <binary|libpq> <empty out folder>
       python lab/psycopg/measure.py compare <folder with binary/ and libpq/>"""
import collections
import json
import pathlib
import re
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]


def run(cmd, **kw):
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO, **kw)
    if p.returncode != 0:
        sys.exit(f"failed ({p.returncode}): {' '.join(cmd[:6])} ...\n{p.stderr[-800:]}")
    return p


def trivy_image():
    text = (REPO / ".github/workflows/CI-image.yml").read_text(encoding="utf-8")
    return re.search(r"^\s*TRIVY: (aquasec/trivy:[0-9.]+@sha256:[0-9a-f]{64})$", text, re.M).group(1)


def in_app(script):
    # Copy the script into the container of the app and run it, with the environment of the app (DATABASE_URL of notes_app).
    run(["docker", "compose", "cp", str(HERE.parent / script), f"app:/tmp/{pathlib.Path(script).name}"])
    return json.loads(run(["docker", "compose", "exec", "-T", "app", "python", "-I", f"/tmp/{pathlib.Path(script).name}"]).stdout)


def measure(variant, out):
    res = {"variant": variant}
    # The security test first, on a fresh stack; its last line says how it went, also when a check fails.
    start = time.monotonic()
    p = subprocess.run([sys.executable, "-u", "tests/securitytest.py", "--wipe"], capture_output=True, text=True, cwd=REPO)
    (out / "securitytest.txt").write_text(p.stdout + p.stderr, encoding="utf-8")
    lines = [line for line in p.stdout.splitlines() if line.strip()]
    res["securitytest"] = {"outcome": lines[-1] if lines else p.stderr[-300:], "seconds": round(time.monotonic() - start),
                           "checks": sum(line.startswith("ok") for line in lines)}
    truth = in_app("sq3/inside.py")
    (out / "inside.json").write_text(json.dumps(truth, indent=1), encoding="utf-8")
    origin = collections.Counter()
    for g in truth["loaded"]:
        src = g["from"]
        origin["bundled by psycopg-binary" if "psycopg_binary.libs/" in g["file"] else
               "deb" if src.startswith("deb:") else src] += 1
    res["loaded"] = {"files": len(truth["loaded"]), "per_origin": dict(origin),
                     "debian_packages": sorted({g["from"][4:] for g in truth["loaded"] if g["from"].startswith("deb:")}),
                     "openssl": sorted({v for g in truth["loaded"] for v in g["versions"].get("openssl", [])}),
                     "libpq": truth["libpq_in_psycopg"], "debian_total": len(truth["dpkg"])}
    res["speed"] = in_app("psycopg/bench.py")
    # The image of the stack, as a tar, with the SBoM and the scan as in CI-image.yml.
    image = run(["docker", "inspect", "--format", "{{.Image}}", run(["docker", "compose", "ps", "-q", "app"]).stdout.strip()]).stdout.strip()
    res["image_mb"] = round(int(run(["docker", "image", "inspect", "--format", "{{.Size}}", image]).stdout) / 1e6, 1)
    run(["docker", "save", image, "-o", str(out / "img.tar")])
    trivy = trivy_image()
    w = ["--mount", f"type=bind,source={out},target=/w", "--mount", "type=volume,source=trivycache,target=/root/.cache"]
    run(["docker", "run", "--rm", *w, trivy, "image", "--input", "/w/img.tar", "--format", "cyclonedx",
         "--output", "/w/sbom.json", "--quiet"])
    (out / "img.tar").unlink()
    sbom = json.loads((out / "sbom.json").read_text(encoding="utf-8"))
    res["sbom_components"] = sum(1 for c in sbom.get("components", []) if c.get("type") != "file")
    vex = ["--mount", f"type=bind,source={REPO / 'vex'},target=/vex,readonly"]
    run(["docker", "run", "--rm", *w, trivy, "sbom", "/w/sbom.json", "--format", "json", "--output", "/w/scan-all.json", "--quiet"])
    # The brake of the pipeline: HIGH and CRITICAL, with the VEX of main; exit 1 is an outcome here, not an error.
    gate = subprocess.run(["docker", "run", "--rm", *w, *vex, trivy, "sbom", "/w/sbom.json", "--severity", "HIGH,CRITICAL",
                           "--vex", "/vex/openvex.json", "--exit-code", "1", "--format", "json", "--output", "/w/scan-brake.json",
                           "--quiet"], capture_output=True, text=True)
    allv = [v for r in json.loads((out / "scan-all.json").read_text(encoding="utf-8")).get("Results") or []
            for v in r.get("Vulnerabilities") or []]
    left = [v for r in json.loads((out / "scan-brake.json").read_text(encoding="utf-8")).get("Results") or []
            for v in r.get("Vulnerabilities") or []]
    res["scan"] = {"findings": len(allv), "vulnerabilities": len({v["VulnerabilityID"] for v in allv}),
                   "per_severity": dict(collections.Counter(v["Severity"] for v in allv)),
                   "brake_exit": gate.returncode,
                   "left_after_vex": sorted({f"{v['VulnerabilityID']} {v['PkgName']} {v['Severity']} {v.get('Status')}" for v in left})}
    (out / "result.json").write_text(json.dumps(res, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(res, indent=1, ensure_ascii=False))


def compare(base):
    a, b = (json.loads((base / v / "result.json").read_text(encoding="utf-8")) for v in ("binary", "libpq"))
    rows = [("Security test", a["securitytest"]["outcome"], b["securitytest"]["outcome"]),
            ("Checks", a["securitytest"]["checks"], b["securitytest"]["checks"]),
            ("Files loaded", a["loaded"]["files"], b["loaded"]["files"]),
            ("Per origin", a["loaded"]["per_origin"], b["loaded"]["per_origin"]),
            ("Debian packages loaded", len(a["loaded"]["debian_packages"]), len(b["loaded"]["debian_packages"])),
            ("Debian packages in the image", a["loaded"]["debian_total"], b["loaded"]["debian_total"]),
            ("OpenSSL in the process", a["loaded"]["openssl"], b["loaded"]["openssl"]),
            ("libpq", a["loaded"]["libpq"], b["loaded"]["libpq"]),
            ("psycopg", a["speed"]["implementation"], b["speed"]["implementation"]),
            ("Image (MB)", a["image_mb"], b["image_mb"]),
            ("SBoM components", a["sbom_components"], b["sbom_components"]),
            ("Findings / vulnerabilities", f"{a['scan']['findings']} / {a['scan']['vulnerabilities']}",
             f"{b['scan']['findings']} / {b['scan']['vulnerabilities']}"),
            ("Per severity", a["scan"]["per_severity"], b["scan"]["per_severity"]),
            ("Brake with the VEX of main (exit)", a["scan"]["brake_exit"], b["scan"]["brake_exit"]),
            ("Left after the VEX", a["scan"]["left_after_vex"], b["scan"]["left_after_vex"])]
    rows += [(f"{k} (median, ms)", a["speed"][k]["median"], b["speed"][k]["median"])
             for k in ("connect_50", "select_1_5000", "rows_1000_200")]
    new = sorted(set(b["loaded"]["debian_packages"]) - set(a["loaded"]["debian_packages"]))
    print("| What | psycopg-binary (main) | psycopg + libpq5 of Debian |\n|---|---|---|")
    for name, x, y in rows:
        print(f"| {name} | {x} | {y} |")
    print(f"\nNewly loaded Debian packages: {', '.join(new)}")


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("binary", "libpq", "compare"):
        sys.exit(__doc__)
    out = pathlib.Path(sys.argv[2]).resolve()
    if sys.argv[1] == "compare":
        compare(out)
        return
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        sys.exit("The out folder must be empty.")
    measure(sys.argv[1], out)


main()
