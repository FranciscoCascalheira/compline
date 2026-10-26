# Compline

**Compline drafts and keeps current the Cyber Resilience Act technical file of a product, from its repository.**

[![ci](https://github.com/FranciscoCascalheira/compline/actions/workflows/ci.yml/badge.svg)](https://github.com/FranciscoCascalheira/compline/actions/workflows/ci.yml)
&nbsp;MIT licensed &nbsp;·&nbsp; early stage &nbsp;·&nbsp; not legal advice

Radio equipment that connects to the internet has had cybersecurity requirements under the Radio Equipment Directive since August 2025 (Delegated Regulation (EU) 2022/30). From 11 December 2027 the Cyber Resilience Act (Regulation (EU) 2024/2847) takes over and covers every product with digital elements placed on the EU market, except medical devices, vehicles, certified aviation products and marine equipment. Its Annex VII lists what the technical file must contain, and Article 31 says the file must be kept up to date during the support period. Reporting duties under Article 14 already apply since 11 September 2026.

Compline builds that file from what the repository can prove, asks the team for the rest, and redoes it on every release:

1. **Scan**: CycloneDX SBOM (Syft), known vulnerabilities (Grype), the CISA KEV catalogue, and process facts from the repository (security policy, dependency updates, CI, tests), hashed into an evidence bundle.
2. **Interview**: a question for every Annex VII point the scan cannot prove. An answer needs a source, a URL or a person with a date.
3. **Annex**: all 13 points of Annex VII, each claim tied to the artefact hash or the source it came from. Anything unanswered stays PENDING, as a question.
4. **Diff**: on the next release, what changed in components, vulnerabilities and claims. Kept with both files, that is the audit trail.

An engineer reviews and signs. Compline never decides whether a product conforms.

## Try it (offline, about a second)

```bash
git clone https://github.com/FranciscoCascalheira/compline.git && cd compline
pip install -r requirements.txt        # PyYAML
bash demo.sh                           # writes demo/: the technical file and the 2.13.0 to 2.14.2 diff
```

The demo rebuilds everything from the evidence bundles in `evidence/`, so it needs neither the scanners nor the network. The last step changes one artefact and shows that Compline refuses the bundle. Output of a run: [`demo/run.txt`](demo/run.txt), [`demo/annex-vii-zigbee2mqtt-2.14.2.md`](demo/annex-vii-zigbee2mqtt-2.14.2.md), [`demo/diff-zigbee2mqtt-2.13.0-2.14.2.md`](demo/diff-zigbee2mqtt-2.13.0-2.14.2.md).

## The proof: Zigbee2MQTT, a Zigbee gateway

[Zigbee2MQTT](https://github.com/Koenkk/zigbee2mqtt) bridges Zigbee radio devices to MQTT. It stands in for the software of a manufacturer's Zigbee hub (why this target: [D1](docs/decisions.md)). Scanned on 26 October 2026, version 2.14.2:

- **278** components in the SBOM; **111** of them ship with the product according to `pnpm-lock.yaml`, the rest are build and test tools.
- **18** known vulnerabilities, all with a fixed version upstream; **10** are in shipped packages (fast-uri, ip-address).
- **0** of the 18 CVEs in the CISA KEV catalogue, version 2026.10.23.
- No security policy file in the repository; Dependabot is configured; 9 CI workflows; 26 test files.
- **7** of the 14 interview questions answered from the public documentation, each with its URL; **7** still PENDING (supported versions, production process, risk assessment, support period, standards, security tests, declaration of conformity).
- From 2.13.0 to 2.14.2: 13 components added, 69 removed, 103 changed version; 3 vulnerabilities new, 44 resolved, 15 still present; 11 claims in the file changed.
- Scan time: SBOM 2.4 s, vulnerability matching 3.7 s, recorded in the bundle's `manifest.json`.

These numbers describe an open-source project read from its public documentation, not a customer's product, and not an interview with its maintainers.

## Use it on your repository

You need Python 3.12 or later with PyYAML, and [Syft](https://github.com/anchore/syft) and [Grype](https://github.com/anchore/grype) on your `PATH` (or `SYFT_BIN` and `GRYPE_BIN`).

```bash
./compline.py scan path/to/repo --out evidence/my-product-1.0 --version 1.0   # downloads the CISA KEV catalogue, or pass --kev FILE
./compline.py interview --answers my-answers.yaml                               # checks sources, lists what is still to ask
./compline.py annex evidence/my-product-1.0 --answers my-answers.yaml --out annex-vii.md
./compline.py diff evidence/my-product-0.9 evidence/my-product-1.0 --answers my-answers.yaml
npm test                                                                         # 23 tests, offline
```

Questions live in [`interview/questions.yaml`](interview/questions.yaml); [`interview/answers-zigbee2mqtt.yaml`](interview/answers-zigbee2mqtt.yaml) shows the answer format.

## Files

| File | What it is |
| --- | --- |
| `compline.py` | The command line: `scan`, `annex`, `interview`, `diff`. |
| `evidence/` | Evidence bundles for Zigbee2MQTT 2.13.0 and 2.14.2: gzipped artefacts plus `manifest.json` with their SHA-256. |
| `interview/` | The question bank and the demo answers. |
| `demo.sh`, `demo/` | The offline demo and the output of a run. |
| `test_compline.py` | One test per command, parity over every Annex VII point, and tests that the checks themselves fail on broken input. |
| `docs/decisions.md` | Numbered decisions; the code cites them as D1 to D13. |
| `scan.mjs`, `relatorio.md`, `annex7.py`, `annex-vii-draft.md`, `test_annex7.py` | The first proof, on OWASP NodeGoat, 24 and 25 October 2026 (corrected on 26 October, see D13). |

## Limitations

- A draft for an engineer to review and sign. Not legal advice, not a conformity assessment.
- The runtime and development split reads npm and pnpm lockfiles only; other ecosystems count every package ([D11](docs/decisions.md)).
- Embedded C firmware: the SDK and components declared in ESP-IDF (`dependencies.lock`, `idf_component.yml`) and Zephyr (`west.yml`) manifests are added to the SBOM, and pinned ESP-IDF and Zephyr versions are matched against known vulnerabilities ([D14](docs/decisions.md)). Code copied into the repository without a manifest, git submodules, PlatformIO, Yocto and Buildroot are not read yet; those need the interview.
- KEV membership is a public signal of exploitation, not the Article 14 test ([D10](docs/decisions.md)).
- No language model writes any part of the file yet ([D12](docs/decisions.md)).

## Team

- **Francisco Cascalheira**, founder and engineer. FEUP, Informatics and Computing Engineering. Head of Product at Unilinkr.
- **Rian Vilares**, co-founder, industry. FEUP, Mechanical Engineering.

## License

MIT, see [`LICENSE`](./LICENSE).
