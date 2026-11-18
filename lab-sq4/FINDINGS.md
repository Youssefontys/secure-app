# sq4: OpenVEX versus CycloneDX VEX

Gemeten op 18 november 2026, tegen de SBoM van het lokaal gebouwde image van `main`
(serialNumber `urn:uuid:491a2c7d-7027-49ef-bc0d-217c9abf70ea`, 112 componenten, Trivy 0.76.0).
De 26 verklaringen uit `vex/openvex.json` zijn met een script omgezet naar een losstaand
CycloneDX-VEX-document (alleen `vulnerabilities`, geen `components`), en beide tegen dezelfde
SBoM gescand: `trivy sbom sbom.json --severity HIGH,CRITICAL --vex <bestand> --show-suppressed
--exit-code 1`.

## Uitkomst

| | OpenVEX (`vex/openvex.json`) | CycloneDX VEX (omgezet) |
|---|---|---|
| Resultaat | `Total: 0`, exit 0 | `Total: 0`, exit 0 (na twee fixes) |
| Onderdrukt | 103 | 103 |

Functioneel identiek: beide formaten geven dezelfde uitkomst voor dezelfde SBoM.

## Twee dingen die niet uit de documentatie kwamen, maar uit het draaien zelf

1. **De BOM-Link mag het serialNumber niet dubbel voorvoegen.** `urn:cdx:urn:uuid:491a2c7d-.../1#...`
   gaf op elke regel `WARN [vex] Unable to parse BOM-Link`, en dus 0 onderdrukkingen (`Total: 103`).
   Juist: `urn:cdx:491a2c7d-.../1#...` — het `urn:uuid:`-voorvoegsel van het serialNumber eraf.
2. **Eén CVE over meerdere OpenVEX-verklaringen past niet een-op-een.** `CVE-2025-69720` staat in
   `vex/openvex.json` als twee verklaringen (drie pakketten met `vulnerable_code_not_present`, een
   vierde met `vulnerable_code_not_in_execute_path`). CycloneDX's `vulnerabilities[]` heeft één
   `analysis`-blok per id; samengevoegd tot één verklaring (met de eerste justification), de drie
   pakketten bleven zonder dat anders onderdrukt (`Total: 3` tot de samenvoeging). Trivy's eigen
   filter kijkt toch alleen naar `state`, niet naar `justification` (al eerder vastgesteld in 6.2,
   "VEX in Trivy"), dus functioneel ging er niets verloren voor de scan zelf — wel de precisie van
   de reden, voor wie het document leest.

## Wat dit niet oplost

Het BOM-Link-probleem waarom OpenVEX eerst gekozen werd, blijft bestaan voor een **los, handmatig
bijgehouden** CycloneDX-VEX-bestand: het serialNumber verandert bij elke nieuwe build, dus zo'n
bestand zou na elke build opnieuw moeten. Dat is precies waarom de overstap in 6.2 aan
Dependency-Track is gekoppeld, niet aan het formaat alleen: Dependency-Track genereert het
CycloneDX-VEX-document opnieuw per scan, uit analyses die het zelf per PURL onthoudt, in plaats
van een bestand dat iemand met de hand bijhoudt. Dat deel van sq4 (uploaden, analyses zetten,
exporteren) is nog niet gemeten: de sleutel die daarvoor bestaat mag alleen een SBoM uploaden,
niet lezen (`GET /api/v1/project/lookup` gaf 403) — een bredere sleutel is nog nodig.

## Bestanden

- `convert_vex.py`: de omzetting, met de twee fixes erin.
- `cyclonedx-vex-manual.json`: het resultaat, 25 vulnerabilities (CVE-2025-69720 samengevoegd).
