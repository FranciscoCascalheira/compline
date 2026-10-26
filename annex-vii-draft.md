# Technical documentation, Cyber Resilience Act, Annex VII
# Product: exemplo-NodeGoat (clone público do OWASP NodeGoat)

Draft generated 2026-10-26 by Compline from the scan of 2026-10-24. Scan-derived sections are filled and
carry evidence tags. Interview-derived sections are marked PENDING. This is a draft for engineer review
and signature, not legal advice, and not yet a conformity assessment.

## 1. General description of the product with digital elements
- 1(a) Intended purpose: **PENDING, team interview.**
- 1(b) Software versions affecting conformity: **PENDING, team interview.**
- 1(c) Where the product is hardware, photographs or illustrations of external features, marking and internal layout: **PENDING, team interview.**
- 1(d) Information and instructions to the user (Annex II): **PENDING, team interview.**

## 2. Design, development, production and vulnerability handling processes
- 2(a) System architecture and interaction of components: **PENDING, team interview.**
- 2(b) Vulnerability handling, Annex I Part II:
  - Software bill of materials: CycloneDX SBOM with **422 components**, generated with Syft. [evidence: relatorio.md sha256:ead3b33d4563 @ bf77836]
  - Known vulnerabilities at scan time: **105** reported by Grype (14 critical, 58 high, 23 medium, 10 low). [evidence: relatorio.md sha256:ead3b33d4563 @ bf77836]
  - Unique CVE/GHSA identifiers in the critical and high table: **54**. [evidence: relatorio.md sha256:ead3b33d4563 @ bf77836]
  - Identifiers in the CISA KEV catalogue at scan time: **0**. KEV is a public signal of exploitation, not the Article 14 test. [evidence: relatorio.md sha256:ead3b33d4563 @ bf77836]
  - Critical findings with a fix available: **14 of 14**. [evidence: relatorio.md sha256:ead3b33d4563 @ bf77836]
  - Coordinated vulnerability disclosure policy and contact: **PENDING, team interview.**
  - Secure update distribution and separation of security from functional updates: **PENDING, team interview.**
- 2(c) Production and monitoring processes and their validation: **PENDING, team interview.**

## 3. Cybersecurity risk assessment (Article 13(2))
- Risk assessment covering planning, design, development, production, delivery and maintenance: **PENDING, team interview.**
- Inputs available from the scan: the 54 identifiers above, ranked by EPSS exploit probability in the report. [evidence: relatorio.md sha256:ead3b33d4563 @ bf77836]

## 4. Support period and its justification (Article 13(8))
- Support period: **PENDING, team interview.**

## 5. Harmonised standards, common specifications or other technical solutions applied
- **PENDING, team interview.**

## 6. Reports of tests carried out to verify conformity (Annex I and vulnerability handling)
- Dependency scan of 2026-10-24 with Syft and Grype: 105 findings; 70 of the 72 critical and high findings have a fix available. [evidence: relatorio.md sha256:ead3b33d4563 @ bf77836]
- Further tests (fuzzing, penetration, update mechanism): **PENDING, team interview.**

## 7. Copy of the EU declaration of conformity
- **PENDING, team interview.** (template Annex V)

## 8. Software bill of materials (on reasoned request of a market surveillance authority)
- Available in CycloneDX JSON, 422 components, regenerated on every release. [evidence: relatorio.md sha256:ead3b33d4563 @ bf77836]

## Appendix A. Critical findings at scan time (from the report)
| Component | Version | Identifier | Fix available | In CISA KEV |
| --- | --- | --- | --- | --- |
| minimist | 0.0.10 | CVE-2021-44906 | Sim (0.2.4) | Não |
| minimist | 0.0.8 | CVE-2021-44906 | Sim (0.2.4) | Não |
| minimist | 0.0.8 | CVE-2021-44906 | Sim (0.2.4) | Não |
| minimist | 1.2.0 | CVE-2021-44906 | Sim (1.2.6) | Não |
| minimist | 1.2.5 | CVE-2021-44906 | Sim (1.2.6) | Não |
| underscore | 1.9.1 | CVE-2021-23358 | Sim (1.12.1) | Não |
| mixin-deep | 1.3.1 | CVE-2019-10746 | Sim (1.3.2) | Não |
| set-value | 0.4.3 | CVE-2019-10747 | Sim (2.0.1) | Não |
| set-value | 2.0.0 | CVE-2019-10747 | Sim (2.0.1) | Não |
| bson | 1.0.9 | CVE-2020-7610 | Sim (1.1.4) | Não |
| fsevents | 1.2.9 | CVE-2023-45311 | Sim (1.2.11) | Não |
| tar | 4.4.8 | CVE-2026-59873 | Sim (7.5.19) | Não |
| proxy-addr | 2.0.4 | CVE-2026-90711 | Sim (2.0.8) | Não |
| fsevents | 1.2.9 | GHSA-xv2f-5jw4-v95m | Sim (1.2.11) | Não |

## Appendix B. Evidence index
- [evidence: relatorio.md sha256:ead3b33d4563 @ bf77836]
- Next release: regenerate this file, diff against this version, keep both for the auditor.
