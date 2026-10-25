#!/usr/bin/env python3
"""Draft a CRA Annex VII technical file from the real scan report (relatorio.md).

Sections that depend on the scan are filled from the report; sections that depend on the
team interview are left as PENDING. Every scan-derived claim carries an evidence tag that
points at the report file, its SHA-256 and the commit it was read from.

Usage: python3 annex7.py [relatorio.md] [annex-vii-draft.md]
"""
import hashlib, re, subprocess, sys, datetime, os

src = sys.argv[1] if len(sys.argv) > 1 else 'relatorio.md'
dst = sys.argv[2] if len(sys.argv) > 2 else 'annex-vii-draft.md'
text = open(src, encoding='utf8').read()
sha = hashlib.sha256(text.encode('utf8')).hexdigest()[:12]
try:
    commit = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'], text=True).strip()
except Exception:
    commit = 'uncommitted'
E = f'[evidence: {src} sha256:{sha} @ {commit}]'

def grab(pattern, default='?'):
    m = re.search(pattern, text)
    return m.group(1) if m else default

components = grab(r'componentes identificados no SBOM:\s*(\d+)')
vulns = grab(r'vulnerabilidades reportadas pelo Grype:\s*(\d+)')
sev = {k: grab(rf'- {k}:\s*(\d+)', '0') for k in ('Critical', 'High', 'Medium', 'Low')}
target = grab(r'Alvo analisado:\s*(.+)')
date = grab(r'Data de geração:\s*(\S+)')
tools = grab(r'Ferramentas:\s*(.+)')

rows = []
for line in text.splitlines():
    if line.startswith('|') and 'CVE-' in line or line.startswith('|') and 'GHSA-' in line:
        cells = [c.strip() for c in line.strip('|').split('|')]
        if len(cells) >= 6:
            rows.append(cells)
cves = sorted({r[2] for r in rows})
kev = [r for r in rows if r[5].lower().startswith('sim')]
fixable = [r for r in rows if r[4].lower().startswith('sim')]
crit = [r for r in rows if r[3] == 'Critical']

today = datetime.date.today().isoformat()
P = '**PENDING, team interview.**'

out = f"""# Technical documentation, Cyber Resilience Act, Annex VII
# Product: {target}

Draft generated {today} by Compline from the scan of {date}. Scan-derived sections are filled and
carry evidence tags. Interview-derived sections are marked PENDING. This is a draft for engineer review
and signature, not legal advice, and not yet a conformity assessment.

## 1. General description of the product with digital elements
- 1(a) Intended purpose: {P}
- 1(b) Software versions affecting conformity: {P}
- 1(c) Hardware product and external interfaces: {P}
- 1(d) Information and instructions to the user (Annex II): {P}

## 2. Design, development, production and vulnerability handling processes
- 2(a) System architecture and interaction of components: {P}
- 2(b) Vulnerability handling, Annex I Part II:
  - Software bill of materials: CycloneDX SBOM with **{components} components**, generated with Syft. {E}
  - Known vulnerabilities at scan time: **{vulns}** reported by Grype ({sev['Critical']} critical, {sev['High']} high, {sev['Medium']} medium, {sev['Low']} low). {E}
  - Unique CVE/GHSA identifiers in the critical and high table: **{len(cves)}**. {E}
  - Actively exploited (CISA KEV) at scan time: **{len(kev)}**, therefore no Article 14 early-warning clock was running at scan time. {E}
  - Critical findings with a fix available: **{len([r for r in crit if r[4].lower().startswith('sim')])} of {len(crit)}**. {E}
  - Coordinated vulnerability disclosure policy and contact: {P}
  - Secure update distribution and separation of security from functional updates: {P}

## 3. Cybersecurity risk assessment (Article 13(2))
- Risk assessment covering planning, design, development, production, delivery and maintenance: {P}
- Inputs available from the scan: the {len(cves)} identifiers above, ranked by EPSS exploit probability in the report. {E}

## 4. Support period and its justification (Article 13(8))
- Support period: {P}

## 5. Harmonised standards, common specifications or other technical solutions applied
- {P}

## 6. Reports of tests carried out to verify conformity (Annex I and vulnerability handling)
- Dependency scan of {date} with Syft and Grype: {vulns} findings, {len(fixable)} with a fix available. {E}
- Further tests (fuzzing, penetration, update mechanism): {P}

## 7. Copy of the EU declaration of conformity
- {P} (template Annex V)

## 8. Software bill of materials (on reasoned request of a market surveillance authority)
- Available in CycloneDX JSON, {components} components, regenerated on every release. {E}

## Appendix A. Critical findings at scan time (from the report)
| Component | Version | Identifier | Fix available | In CISA KEV |
| --- | --- | --- | --- | --- |
""" + "\n".join(f"| {r[0]} | {r[1]} | {r[2]} | {r[4]} | {r[5]} |" for r in crit) + f"""

## Appendix B. Evidence index
- {E}
- Next release: regenerate this file, diff against this version, keep both for the auditor.
"""
open(dst, 'w', encoding='utf8').write(out)
filled = out.count('[evidence:')
pending = out.count('PENDING')
print(f'wrote {dst}: {filled} evidence-tagged claims, {pending} pending interview items, {len(cves)} identifiers, {len(crit)} critical rows')
