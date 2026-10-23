#!/usr/bin/env bash
# One measurement for subquestion 1: one generator with its scanner, on one image, with empty caches.
# Usage: measure.sh <trivy|syft|syft-sbom> <folder with img.tar> <out folder>
# Writes sbom.json, scan.json and measurement.json in the out folder. The tool images are already local, so pulling does not count.
set -u
VARIANT=$1 IN=$2 OUT=$3
mkdir -p "$OUT"

# Milliseconds; GitHub shows the duration of a step only per second.
ms() { date +%s%3N; }

case "$VARIANT" in
  trivy)
    # The database separately, because it depends on the network; after that Trivy scans without updating.
    s=$(ms); docker run --rm -v trivycache:/root/.cache "$TRIVY" image --download-db-only --quiet; db_exit=$?; db_ms=$(( $(ms) - s ))
    s=$(ms); docker run --rm -v "$IN:/in:ro" -v "$OUT:/out" -v trivycache:/root/.cache "$TRIVY" image --input /in/img.tar \
      --format cyclonedx --output /out/sbom.json --quiet; gen_exit=$?; gen_ms=$(( $(ms) - s ))
    s=$(ms); docker run --rm -v "$OUT:/out" -v trivycache:/root/.cache "$TRIVY" sbom /out/sbom.json --skip-db-update \
      --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --format json --output /out/scan.json --quiet; scan_exit=$?
    scan_ms=$(( $(ms) - s ))
    ;;
  syft | syft-sbom)
    # The sbom cataloger reads SBoMs that are already in the image; for an image it is off by default.
    extra=(); [ "$VARIANT" = syft-sbom ] && extra=(--select-catalogers +sbom-cataloger)
    s=$(ms); docker run --rm -v "$IN:/in:ro" -v "$OUT:/out" "$SYFT" docker-archive:/in/img.tar "${extra[@]}" \
      -o cyclonedx-json=/out/sbom.json -q; gen_exit=$?; gen_ms=$(( $(ms) - s ))
    s=$(ms); docker run --rm -v grypecache:/cache -e GRYPE_DB_CACHE_DIR=/cache "$GRYPE" db update -q; db_exit=$?; db_ms=$(( $(ms) - s ))
    s=$(ms); docker run --rm -v "$OUT:/out" -v grypecache:/cache -e GRYPE_DB_CACHE_DIR=/cache -e GRYPE_DB_AUTO_UPDATE=false \
      "$GRYPE" sbom:/out/sbom.json --only-fixed --fail-on high -o json --file /out/scan.json -q; scan_exit=$?
    scan_ms=$(( $(ms) - s ))
    ;;
  *) echo "unknown variant: $VARIANT" >&2; exit 2 ;;
esac

python3 "$(dirname "$0")/count.py" "$OUT" "$VARIANT" "$db_ms" "$db_exit" "$gen_ms" "$gen_exit" "$scan_ms" "$scan_exit"
