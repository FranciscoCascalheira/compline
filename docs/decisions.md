# Decisions

Numbered and dated. Code cites them as D<n>. A decision that changes gets a new number that says which one it replaces.

## D1, 26/10/2026. The product proof runs on Zigbee2MQTT, not on OWASP NodeGoat

The buyer is a manufacturer of hardware with software, so the proof has to run on the software of a product with a radio, not on a training web app. Three open-source candidates, each with a lockfile Syft reads, scanned on 26/10/2026 with Syft 1.55.0 and Grype 0.121.0 (database built 25/10/2026). Components exclude the file entries Syft adds for lockfiles and workflows:

| Candidate | What it is | Components | Grype matches | Scan time | Public docs for the interview | Releases to diff |
| --- | --- | --- | --- | --- | --- | --- |
| Zigbee2MQTT 2.14.2 | Zigbee to MQTT gateway software; talks to a Zigbee radio adapter | 278 (pnpm-lock.yaml) | 18 | 6.0 s | Architecture in the README, securing guide, update guide, GitHub security page | Monthly (2.13.0, 2.14.x) |
| ChirpStack Concentratord 4.7.1 | LoRa gateway daemon that drives the SX1301/SX1302 radio concentrator | 211 (Cargo.lock) | 1 | 5.2 s | Configuration docs; no security policy file | Regular (4.6.0, 4.7.x) |
| Valetudo 2026.10.0 | Cloud-free control software that runs on robot vacuums (Wi-Fi) | 475 (package-lock.json) | 133 | 6.6 s | Extensive docs; its SECURITY.md says the software "should not under any circumstance be used" | Monthly |

Chosen: Zigbee2MQTT. It has a radio, a realistic number of findings, monthly releases for a meaningful diff, and enough public documentation to answer half the interview from URLs, while leaving real gaps (no security policy, no support period) that the file must show as gaps. Concentratord is closer to the radio but its one finding makes a thin demo, and the vendored Semtech C code is invisible to Syft. Valetudo is a hobby project whose own security file disowns production use, so it cannot stand in for a manufacturer.

Zigbee2MQTT stands in for the software of a manufacturer's Zigbee hub. The demo answers come from its public documentation, not from an interview with its maintainers.

## D2, 26/10/2026. One command line in Python: `compline scan | annex | interview | diff`

Python because the Annex VII generator and its tests already were, and one language keeps the CLI testable end to end with stand-in tools. `scan.mjs` stays as the script that produced the NodeGoat report of 24/10/2026; it is not part of the CLI.

## D3, 26/10/2026. Evidence is a bundle of hashed artefacts, and a changed artefact is refused

`compline scan` writes `evidence/<name>/`: the CycloneDX SBOM, the Grype JSON, the CISA KEV catalogue it checked against, and the repository signals, each gzipped, plus `manifest.json` with the SHA-256 of each uncompressed artefact, the target commit and the timings. Every claim in the technical file cites the artefacts it comes from by hash, and the scanned product's commit, not the commit of Compline. `compline annex` and `compline diff` refuse a bundle whose artefact no longer matches its manifest hash (fail closed). Bundles are small enough to commit (about 250 KB each, most of it the KEV catalogue); raw tool outputs elsewhere stay git-ignored.

## D4, 26/10/2026. EPSS from Grype's database, KEV from the CISA catalogue snapshot

Grype 0.121.0 already attaches dated EPSS scores to each match, so the scan makes no call to the FIRST API. KEV membership is checked against the full CISA catalogue, stored in the bundle with its version number, so an auditor can see what "not in KEV" was checked against.

## D5, 26/10/2026. PyYAML is the only third-party dependency

The question bank and the answers are YAML because people edit them by hand. The standard library has no YAML parser. Pinned in `requirements.txt`; CI installs it.

## D6, 26/10/2026. An interview answer without a source is refused; an unanswered question stays PENDING

Each answer cites a URL with its retrieval date, or a person with a date. `compline interview` and `compline annex` refuse answers without one, answers to unknown questions and duplicate answers. A question nobody answered becomes a PENDING line in the file with the question itself, so the next interview starts from it. Nothing is invented to fill a gap.

## D7, 26/10/2026. Annex VII is a fixed list of 13 points, and a parity test refuses any empty point

Points 1(a) to 1(d), 2(a) to 2(c), and 3 to 8, in the regulation's order. `compline annex` will not write a file in which a point is missing, empty, or carries an evidenced or answered claim without a source. The test suite checks this on the demo bundle with and without answers, and checks that the checker itself fails on broken input.

## D8, 26/10/2026. `compline scan` will not overwrite an existing bundle without `--force`

Evidence is meant to be kept. Replacing a bundle is a deliberate act.

## D9, 26/10/2026. The repository is evidence too

The scan records process facts that a repository shows and a firmware binary does not: a security policy file, dependency update automation, CI workflows, test code. Each is hashed in `repo.json`. Absences are recorded as findings ("no security policy file"), not skipped.

## D10, 26/10/2026. Claims say what the artefact proves and no more

"In the CISA KEV catalogue", not "actively exploited": KEV is a public signal, and the Article 14 clock starts when the manufacturer becomes aware of an actively exploited vulnerability. The old draft overstated this (errata R06 and A03).

## D11, 26/10/2026. Runtime and development packages are separated from the lockfile

Syft lists every package in the lockfile, build tools included, and does not mark which ones ship. For pnpm (lockfile 9) Compline walks the dependency closure from the importers' runtime dependencies; for npm it reads the `dev` flag in `package-lock.json`. On Zigbee2MQTT 2.14.2 that gives 111 of 278 components shipped, and 10 of the 18 matches in shipped packages. Other ecosystems are reported as "not known from the repository" until supported.

## D12, 26/10/2026. No language-model drafting yet

The deterministic path is the floor: every sentence in the file comes from an artefact or a sourced answer. A model would add value turning a recorded interview into answers, which needs real interviews to test against. Until then the CLI has no network dependency beyond the scan, and the demo runs offline.

## D13, 26/10/2026. The NodeGoat path is kept and corrected, not deleted

`annex7.py` still drafts from `relatorio.md`, because the submitted pitch deck points at `annex-vii-draft.md`. Fixed on 26/10/2026: it read the EPSS table as if it were the critical and high table (56 identifiers instead of 54), it counted fixes over 72 rows while naming the 105 findings, it said "actively exploited" for "not in KEV", it paraphrased point 1(c), and it left out point 2(c).
