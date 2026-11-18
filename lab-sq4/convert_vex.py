# -*- coding: utf-8 -*-
"""sq4: convert vex/openvex.json into a standalone CycloneDX VEX document (vulnerabilities
only, no components), referencing this specific SBOM via a BOM-Link (serialNumber + version)."""
import json
import os

# Expects sbom.json (a CycloneDX SBoM of the image, made the same way as CI-image.yml) and
# vex/openvex.json (run from the repo root) in the current directory.
WORK = os.getcwd()

JMAP = {
    "component_not_present": "code_not_present",
    "vulnerable_code_not_present": "code_not_present",
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "vulnerable_code_cannot_be_controlled_by_adversary": "protected_by_mitigating_control",
    "inline_mitigations_already_exist": "protected_by_mitigating_control",
}

sbom = json.load(open(f"{WORK}/sbom.json", encoding="utf-8"))
vex = json.load(open(f"{WORK}/vex/openvex.json", encoding="utf-8"))

serial = sbom["serialNumber"].removeprefix("urn:uuid:")
bom_version = sbom.get("version", 1)
bom_link = f"{serial}/{bom_version}"

# purl prefix (before the first '?') -> full bom-ref in this SBOM
by_prefix = {}
for c in sbom.get("components", []):
    ref = c.get("bom-ref")
    if ref and "pkg:" in ref:
        by_prefix.setdefault(ref.split("?")[0], []).append(ref)

# OpenVEX allows one CVE to be split over several statements, each with its own products and
# justification (CVE-2025-69720 is one: vulnerable_code_not_present for three packages,
# vulnerable_code_not_in_execute_path for a fourth). CycloneDX's vulnerabilities[] is keyed by
# id, with one analysis block per entry: no room for a second justification under the same id.
# Merged here, keeping the first statement's justification for the combined entry; the split
# itself does not survive the conversion, and that loss is a finding of this comparison.
by_cve = {}
unmatched = []
merged_cves = []
for s in vex["statements"]:
    cve = s["vulnerability"]["name"]
    refs = []
    for p in s["products"]:
        prefix = p["@id"]
        found = by_prefix.get(prefix)
        if not found:
            unmatched.append((cve, prefix))
            continue
        refs.extend(found)
    if cve in by_cve:
        merged_cves.append(cve)
        by_cve[cve]["affects"].extend(f"urn:cdx:{bom_link}#{r}" for r in refs)
    else:
        by_cve[cve] = {
            "id": cve,
            "analysis": {
                "state": s["status"],
                "justification": JMAP[s["justification"]],
                "detail": s.get("impact_statement", ""),
            },
            "affects": [f"urn:cdx:{bom_link}#{r}" for r in refs],
        }

vulns = []
for v in by_cve.values():
    v["affects"] = [{"ref": r} for r in v["affects"]]
    vulns.append(v)

doc = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "vulnerabilities": vulns,
}

with open(f"{WORK}/cyclonedx-vex-manual.json", "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)

print(f"wrote {len(vulns)} vulnerabilities, {sum(len(v['affects']) for v in vulns)} affects total")
print(f"unmatched products: {len(unmatched)}")
for u in unmatched[:20]:
    print("  ", u)
print(f"CVEs with more than one OpenVEX statement, merged into one entry: {merged_cves}")
