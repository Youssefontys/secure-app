"""Lab measurement for subquestion 3: what do SBoMs of the same image miss, and how much do they differ per generator and
scanner? SBoMs of Trivy, Syft, Syft with the sbom cataloger, cdxgen (of the image) and cyclonedx-py (of requirements.txt),
each scanned with Trivy and with Grype and checked with cyclonedx-cli, next to what is really in the running image
(inside.py). cdxgen, cyclonedx-py and cyclonedx-cli only take part if they are on the PATH, as on the runner.
Runs on a runner through .github/workflows/sq3-limitations.yml; works on Windows too.
Usage: python lab/sq3/measure.py <image> <empty out folder>"""
import collections
import json
import pathlib
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
from urllib.parse import unquote

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
# The same versions as the benchmark of subquestion 1; Trivy from CI-image.yml.
SYFT = "anchore/syft:v1.54.1@sha256:3eb5379ba7b409c3f4069b686110527af0c47df993fa5c10d13e7cf34f49b1aa"
GRYPE = "anchore/grype:v0.120.1@sha256:e4a44ef45d285b829ce6efe2642980329661bd2d18eab5fc539138d4adaebbbe"
SBOMS = ["trivy", "syft", "syft-sbom"]
SCANNERS = ("trivy", "grype")
PORT = 5056


def trivy_image():
    text = (REPO / ".github/workflows/CI-image.yml").read_text(encoding="utf-8")
    m = re.search(r"^\s*TRIVY: (aquasec/trivy:[0-9.]+@sha256:[0-9a-f]{64})$", text, re.M)
    if not m:
        sys.exit("TRIVY not found in CI-image.yml")
    return m.group(1)


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"failed ({p.returncode}): {' '.join(cmd[:6])} ...\n{p.stderr[-800:]}")
    return p


def mount(src, dst, ro=False):
    return ["--mount", f"type=bind,source={src},target={dst}" + (",readonly" if ro else "")]


def generate(out, trivy):
    w = mount(out, "/w")
    run(["docker", "run", "--rm", *w, "--mount", "type=volume,source=trivycache,target=/root/.cache", trivy,
         "image", "--input", "/w/img.tar", "--format", "cyclonedx", "--output", "/w/sbom-trivy.json", "--quiet"])
    run(["docker", "run", "--rm", *w, SYFT, "docker-archive:/w/img.tar", "-o", "cyclonedx-json=/w/sbom-syft.json", "-q"])
    run(["docker", "run", "--rm", *w, SYFT, "docker-archive:/w/img.tar", "--select-catalogers", "+sbom-cataloger",
         "-o", "cyclonedx-json=/w/sbom-syft-sbom.json", "-q"])
    # The other CycloneDX tools: cdxgen reads the same tar, cyclonedx-py only requirements.txt (the source, not the image).
    # A tool that fails is an outcome; the error goes to make-<name>.error.txt.
    errors = {}
    extra = []
    if shutil.which("cdxgen"):
        extra.append(("cdxgen", [shutil.which("cdxgen"), str(out / "img.tar"), "-t", "docker", "-o", str(out / "sbom-cdxgen.json")]))
    if shutil.which("cyclonedx-py"):
        extra.append(("cyclonedx-py", [shutil.which("cyclonedx-py"), "requirements", str(REPO / "app/requirements.txt"),
                                       "--of", "JSON", "-o", str(out / "sbom-cyclonedx-py.json")]))
    for name, cmd in extra:
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode == 0 and (out / f"sbom-{name}.json").exists():
            SBOMS.append(name)
        else:
            (out / f"make-{name}.error.txt").write_text(p.stdout[-4000:] + p.stderr[-4000:], encoding="utf-8")
            errors[f"make {name}"] = (p.stderr.strip().splitlines() or [str(p.returncode)])[-1][-300:]
    return errors


def validate(out):
    # Every SBoM against the schema of CycloneDX, with cyclonedx-cli: valid and still not interchangeable, or not valid?
    cli = shutil.which("cyclonedx")
    if not cli:
        return {}
    result = {}
    for s in SBOMS:
        p = subprocess.run([cli, "validate", "--input-file", str(out / f"sbom-{s}.json"), "--input-format", "json",
                            "--fail-on-errors"], capture_output=True, text=True)
        result[s] = {"valid": p.returncode == 0, "output": (p.stdout + p.stderr).strip()[-400:]}
    return result


def scan(out, trivy):
    w = mount(out, "/w")
    tcache = ["--mount", "type=volume,source=trivycache,target=/root/.cache"]
    gcache = ["--mount", "type=volume,source=grypecache,target=/cache", "-e", "GRYPE_DB_CACHE_DIR=/cache"]
    # First update the databases; after that everything scans on the same database.
    run(["docker", "run", "--rm", *tcache, trivy, "image", "--download-db-only", "--quiet"])
    run(["docker", "run", "--rm", *gcache, GRYPE, "db", "update", "-q"])
    # A scan that fails is an outcome too: the error goes to scan-<scanner>-<sbom>.error.txt, and the measurement goes on.
    meta = {"errors": {}}
    for s in SBOMS:
        for sc, cmd in (("trivy", [*w, *tcache, trivy, "sbom", f"/w/sbom-{s}.json", "--skip-db-update", "--format", "json",
                                   "--output", f"/w/scan-trivy-{s}.json", "--quiet"]),
                        ("grype", [*w, *gcache, "-e", "GRYPE_DB_AUTO_UPDATE=false", GRYPE, f"sbom:/w/sbom-{s}.json",
                                   "-o", "json", "--file", f"/w/scan-grype-{s}.json", "-q"])):
            p = subprocess.run(["docker", "run", "--rm", *cmd], capture_output=True, text=True)
            if p.returncode != 0:
                (out / f"scan-{sc}-{s}.error.txt").write_text(p.stderr, encoding="utf-8")
                meta["errors"][f"{sc} on {s}"] = p.stderr.strip().splitlines()[-1][-300:] if p.stderr.strip() else str(p.returncode)
    meta["trivy"] = json.loads((out / "scan-trivy-trivy.json").read_text(encoding="utf-8")).get("CreatedAt")
    p = subprocess.run(["docker", "run", "--rm", *gcache, GRYPE, "db", "status", "-o", "json"], capture_output=True, text=True)
    meta["grype_db"] = p.stdout.strip()[:400]
    return meta


def inside(out, image):
    # Start the app with throwaway keys and without a database, then inside.py in it.
    name = "sq3-measurement"
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    run(["docker", "run", "-d", "--name", name, "-p", f"127.0.0.1:{PORT}:5000", *mount(HERE, "/lab", ro=True),
         "-e", f"FLASK_SECRET_KEY={secrets.token_urlsafe(32)}", "-e", f"DATA_ENCRYPTION_KEY={secrets.token_hex(32)}",
         "-e", "HTTPS_ONLY=0", "-e", "DATABASE_URL=postgresql://x:y@127.0.0.1:1/x", image])
    try:
        for _ in range(30):
            try:
                if urllib.request.urlopen(f"http://127.0.0.1:{PORT}/login", timeout=2).status == 200:
                    break
            except OSError:
                time.sleep(1)
        else:
            sys.exit("the app did not come up")
        p = run(["docker", "exec", name, "python", "-I", "/lab/inside.py"])
        (out / "inside.json").write_text(p.stdout, encoding="utf-8")
        return json.loads(p.stdout)
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def walk(components):
    for c in components or []:
        yield c
        yield from walk(c.get("components"))


def norm_name(kind, name):
    return re.sub(r"[-_.]+", "-", name.lower()) if kind == "pypi" else name


def parse_purl(purl):
    # The namespace only before the @, otherwise a / in a qualifier (download_url=https://...) counts too.
    m = re.match(r"pkg:([^/]+)/(?:[^@?#]*/)?([^/@?#]+)(?:@([^?#]+))?", purl or "")
    if not m:
        return None
    kind, name, version = m.group(1), unquote(m.group(2)), unquote(m.group(3) or "")
    return kind, norm_name(kind, name), re.sub(r"^\d+:", "", version)


def sbom_components(path):
    doc = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for c in walk(doc.get("components")):
        if c.get("type") == "file":
            continue
        p = parse_purl(c.get("purl"))
        out.append(p if p else (c.get("type", "?"), c.get("name", "?"), c.get("version", "")))
    return out


def findings(path, scanner):
    doc = json.loads(path.read_text(encoding="utf-8"))
    out = set()
    if scanner == "trivy":
        for r in doc.get("Results") or []:
            for v in r.get("Vulnerabilities") or []:
                out.add((v["VulnerabilityID"], v["PkgName"], v.get("Severity", "?").upper()))
    else:
        for m in doc.get("matches", []):
            v = m["vulnerability"]
            cves = [r["id"] for r in m.get("relatedVulnerabilities", []) if r.get("id", "").startswith("CVE-")]
            vid = v["id"] if v["id"].startswith("CVE-") or not cves else cves[0]
            out.add((vid, m["artifact"]["name"], v.get("severity", "?").upper()))
    return out


def analyse(out, truth, meta):
    deb = {(row[0], re.sub(r"^\d+:", "", row[1])) for row in truth["dpkg"]}
    deb_names = {n for n, _ in deb}
    pypi = {(norm_name("pypi", n), v) for n, v in truth["dists"]}
    res = {"meta": meta, "truth": {
        "deb": len(deb), "pypi": len(pypi), "python": truth["python"], "ssl_of_python": truth["ssl_of_python"],
        "openssl_in_cryptography": truth["openssl_in_cryptography"], "libpq_in_psycopg": truth["libpq_in_psycopg"],
        "wheel_sboms": {k: len(v) for k, v in truth["wheel_sboms"].items()}}, "sboms": {}, "scans": {}}
    hidden_words = ("python", "openssl", "libssl", "libcrypto", "libpq", "postgres", "krb5", "pcre", "sasl", "ldap",
                    "selinux", "keyutils", "com_err", "libcrypt", "xcrypt")
    for s in SBOMS:
        comps = sbom_components(out / f"sbom-{s}.json")
        kinds = collections.Counter(k for k, _, _ in comps)
        got_deb = {(n, v) for k, n, v in comps if k == "deb"}
        got_pypi = {(n, v) for k, n, v in comps if k == "pypi"}
        extra = sorted({f"{k}:{n}@{v}" for k, n, v in comps if k not in ("deb", "pypi")
                        and any(w in n.lower() for w in hidden_words)})
        res["sboms"][s] = {
            "components": len(comps), "kinds": dict(kinds),
            "deb_found": len(got_deb & deb), "deb_missed": sorted(f"{n}@{v}" for n, v in deb - got_deb),
            "deb_extra": sorted(f"{n}@{v}" for n, v in got_deb - deb),
            "pypi_found": len(got_pypi & pypi), "pypi_missed": sorted(f"{n}@{v}" for n, v in pypi - got_pypi),
            "pypi_extra": sorted(f"{n}@{v}" for n, v in got_pypi - pypi),
            "hidden_seen": extra}
    for s in SBOMS:
        for sc in SCANNERS:
            if not (out / f"scan-{sc}-{s}.json").exists():
                res["scans"][f"{sc} on {s}"] = {"error": meta["errors"].get(f"{sc} on {s}", "no output")}
                continue
            f = findings(out / f"scan-{sc}-{s}.json", sc)
            res["scans"][f"{sc} on {s}"] = {
                "findings": len(f), "vulnerabilities": len({i for i, _, _ in f}),
                "per_severity": dict(collections.Counter(sev for _, _, sev in f)),
                "on_hidden": sorted({f"{i} {p} {sev}" for i, p, sev in f if p not in deb_names
                                     and norm_name("pypi", p) not in {n for n, _ in pypi}})[:60]}
    ids = {k: {i for i, _, _ in findings(out / f"scan-{k.split(' on ')[0]}-{k.split(' on ')[1]}.json", k.split(' on ')[0])}
           for k in res["scans"] if "error" not in res["scans"][k]}
    keys = list(ids)
    res["overlap"] = {f"{a} | {b}": [len(ids[a] & ids[b]), len(ids[a] | ids[b])] for i, a in enumerate(keys) for b in keys[i + 1:]}
    loaded = collections.Counter()
    for g in truth["loaded"]:
        src = g["from"]
        if "psycopg_binary.libs/" in g["file"]:
            src = "pypi:psycopg-binary (bundled library)"
        loaded[src.split(":")[0] if src.startswith("deb:") else src] += 1
    res["loaded"] = {"files": len(truth["loaded"]), "per_origin": dict(loaded),
                     "with_version": [f"{g['file'].split('/')[-1]} {g['versions']}" for g in truth["loaded"] if g["versions"]]}
    (out / "results.json").write_text(json.dumps(res, indent=1, ensure_ascii=False), encoding="utf-8")
    return res


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    image, out = sys.argv[1], pathlib.Path(sys.argv[2]).resolve()
    if not re.fullmatch(r"ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+:[0-9a-f]{40}", image):
        sys.exit("Only an image of ghcr.io with a commit as tag.")
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        sys.exit("The out folder must be empty.")
    trivy = trivy_image()
    run(["docker", "pull", "-q", image])
    digest = run(["docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", image]).stdout.strip()
    run(["docker", "save", image, "-o", str(out / "img.tar")])
    made = generate(out, trivy)
    # The scans only read the SBoMs; the tar does not belong in the artifact.
    (out / "img.tar").unlink()
    meta = scan(out, trivy)
    meta["errors"].update(made)
    meta.update(image=image, digest=digest, trivy=trivy, syft=SYFT, grype=GRYPE, scan_trivy_db=meta.pop("trivy"),
                valid=validate(out), tools={t: shutil.which(t) is not None for t in ("cdxgen", "cyclonedx-py", "cyclonedx")})
    truth = inside(out, image)
    res = analyse(out, truth, meta)
    print(json.dumps({k: res[k] for k in ("truth", "loaded")}, indent=1, ensure_ascii=False))
    for s, v in res["sboms"].items():
        print(f"SBoM {s:12} {v['components']:4} components {v['kinds']}; deb {v['deb_found']}/{res['truth']['deb']}, "
              f"pypi {v['pypi_found']}/{res['truth']['pypi']}; hidden seen: {v['hidden_seen']}")
    for k, v in res["scans"].items():
        if "error" in v:
            print(f"{k:28} ERROR: {v['error']}")
        else:
            print(f"{k:28} {v['findings']:4} findings, {v['vulnerabilities']:4} vulnerabilities {v['per_severity']}")
    for s, v in meta["valid"].items():
        print(f"schema {s:14} {'valid' if v['valid'] else 'NOT valid: ' + v['output'][-160:]}")
    for k, v in meta["errors"].items():
        if k.startswith("make"):
            print(f"{k}: ERROR: {v}")


main()
