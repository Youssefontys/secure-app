"""Puts all measurements together: per variant and image the median, minimum and maximum of the times, and what was
found. Usage: summary.py <folder with the artifacts>. Writes markdown to stdout and measurements.csv."""
import csv
import json
import pathlib
import statistics
import sys

root = pathlib.Path(sys.argv[1])
rows = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(root.glob("*/measurement.json"))]
fields = ["variant", "image", "repetition", "ms_database", "ms_generate", "ms_scan", "exit_scan",
          "cyclonedx", "components", "copies_in_pip", "high_critical_with_fix"]
with open(root / "measurements.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    w.writerows(sorted(rows, key=lambda r: (r["variant"], r["image"], r["repetition"])))


def spread(values):
    return f"{statistics.median(values) / 1000:.1f} s ({min(values) / 1000:.1f} to {max(values) / 1000:.1f})"


print(f"## SBoM benchmark: {len(rows)} measurements, each on a runner of its own\n")
print("Median, with the minimum and maximum between brackets.\n")
print("| Variant | Image | n | Database | Generate | Scan | Exit scan | Components | Copies in pip | HIGH/CRITICAL with fix |")
print("|---|---|---|---|---|---|---|---|---|---|")
for key in sorted({(r["variant"], r["image"]) for r in rows}):
    group = [r for r in rows if (r["variant"], r["image"]) == key]
    exits = sorted({r["exit_scan"] for r in group})
    comps = sorted({r["components"] for r in group})
    vend = sorted({r["copies_in_pip"] for r in group})
    found = sorted({r["high_critical_with_fix"] for r in group})
    print(f"| {key[0]} | {key[1]} | {len(group)} | {spread([r['ms_database'] for r in group])} | "
          f"{spread([r['ms_generate'] for r in group])} | {spread([r['ms_scan'] for r in group])} | "
          f"{', '.join(map(str, exits))} | {', '.join(map(str, comps))} | {', '.join(map(str, vend))} | {', '.join(map(str, found))} |")
