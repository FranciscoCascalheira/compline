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

## D14, 26/10/2026. Firmware manifests (ESP-IDF, Zephyr west) go into the SBOM before matching

Syft does not read the manifests that embedded C firmware uses to declare its SDK and components. Measured on 26/10/2026: on ESPresense (ESP-IDF, `main/idf_component.yml`) and on `zephyrproject-rtos/example-application` (`west.yml`), the SBOM held only the GitHub Actions of the CI and, for the first, one web UI package; none of the firmware's components.

`compline scan` now reads `dependencies.lock` (or, without it, every `idf_component.yml`) and `west.yml`, outside `build/`, `managed_components/`, test and example folders, and adds each declared component to the CycloneDX SBOM before Grype runs, marked with the file it came from. A version counts as pinned only when a lock file or a release tag says so; a constraint (`^3.0.3`, `>=5.4`) or a branch (`main`) is kept as written and never turned into a version. Pinned ESP-IDF and Zephyr get their NVD CPE (`espressif:esp-idf`, `zephyrproject:zephyr`) so Grype can match them; the components get type `library`, because Grype 0.121.0 matched CPEs on that type and not on `operating-system` (tested on 26/10/2026). The file gains one claim, `repo.firmware`, only when such manifests exist, so bundles scanned before D14 are unchanged.

Measured on 26/10/2026 with real Syft and Grype: ESPresense, 10 components declared and none pinned (no lock file in the repository); the Zephyr example, 4 declared, none pinned (revision `main`); `jmharvey1/ESP32BtCWKeyBrd`, ESP-IDF 4.4.4 pinned by its lock file, 15 vulnerability matches where the SBOM before D14 had no firmware component at all.

Not covered yet: git submodules, code copied into the repository without a manifest, PlatformIO `platformio.ini`, Yocto and Buildroot. Those still come from the interview.

## D15, 26/10/2026. More of the firmware: the SDK version the build uses, git submodules, PlatformIO, and NVD names for common C libraries

Extends D14 on the same rule: only an exact release (lock file, release tag, or `name@1.2.3`) is a version; ranges, branches and commits are kept as written.

- **ESP-IDF without a lock file.** The SDK version is taken from the build configuration when it names exactly one release tag: the `esp_idf_version` input of `espressif/esp-idf-ci-action` (including `${{ env.NAME }}`), an `espressif/idf:` container or image, or a Dockerfile `FROM`. Two different tags (a build matrix) prove neither; a branch such as `release-v5.4` is not a version. The claim names the file and the manifest's own constraint. On ESPresense this gives ESP-IDF 5.4.4 from `.github/workflows/build.yml` and 8 vulnerability matches in the SDK (26/10/2026).
- **Git submodules.** `.gitmodules` plus the commit the parent repository pins; a version only when that commit carries a release tag in a checked-out submodule.
- **PlatformIO.** `platform`, `platform_packages` and `lib_deps` of every `[env]`, after `${section.key}`, `extends`, the `[env]` defaults and `extra_configs`, as the build reads them; libraries listed but used by no environment are left out. GitHub archive and release URLs give a version when the ref is a release tag and a commit otherwise. On OpenMQTTGateway: 47 components, 23 pinned (26/10/2026).
- **NVD names.** Besides ESP-IDF and Zephyr, CPEs for Mbed TLS, wolfSSL, OpenSSL, libcurl, Apache NimBLE, FreeRTOS, arduino-esp32, zlib, lwIP and cJSON. Each was kept only after Grype 0.121.0, with its database of 25/10/2026, matched an old release of it; `lwip:lwip` and littlefs matched nothing and were left out. Libraries without an NVD name (most Arduino libraries) are listed in the SBOM and matched by nobody, which the file does not hide.

Still not read: code copied into the repository without any manifest, Yocto, Buildroot.

## D16, 26/10/2026. `annex --red` lists the EN 18031 requirements and says where each answer comes from

The sale today is the Radio Equipment Directive, whose presumption of conformity comes from EN 18031-1, -2 and -3 (Implementing Decision (EU) 2025/138). `interview/en18031.yaml` holds the 42 requirement identifiers and titles, read on 26/10/2026 in the official index previews (normy.normoff.gov.sk, items 139451 to 139453), the parts each belongs to, and where its answer has to come from. With `--red`, the file gains a table, one row per requirement, that cites the claims of the same file bearing on it.

Only GEC-1 ("Up-to-date software and hardware with no publicly known exploitable vulnerabilities") is supported in substance by the scan (SBOM, matches, fixes, KEV, firmware manifests, dependency updates). SCM-2, SCM-3, CRY-1 and SUM-1 get a signal (the SBOM names the TLS or crypto library, or an update component) that proves nothing on its own. Everything else comes from the interview, a test report, or both. No row ever says a requirement is met: that is the manufacturer's decision-tree answer, with its justification. A row cites only claims present in the file, so a bundle scanned before D14 does not cite `repo.firmware`. Without `--red` the file is unchanged.
