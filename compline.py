#!/usr/bin/env python3
"""Compline: drafts the CRA Annex VII technical file from a product repository and keeps it current.

    compline scan TARGET --out evidence/NAME [--kev FILE] [--name N] [--version V] [--force]
    compline annex EVIDENCE [--answers FILE] [--out FILE.md]
    compline interview [--answers FILE]
    compline diff OLD_EVIDENCE NEW_EVIDENCE [--answers FILE] [--out FILE.md]

D<n> refers to docs/decisions.md. This is a draft generator for engineer review, not legal advice.
"""
import argparse
import datetime
import gzip
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from collections import Counter
from pathlib import Path

import yaml  # D5: the only third-party dependency

ROOT = Path(__file__).resolve().parent
QUESTIONS = ROOT / 'interview' / 'questions.yaml'
KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
SEVERITIES = ('Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown')

# Annex VII of Regulation (EU) 2024/2847, every point, in the regulation's order (D7).
ANNEX_VII = [
    ('1a', 'Intended purpose'),
    ('1b', 'Versions of software affecting compliance with the essential cybersecurity requirements'),
    ('1c', 'Hardware: photographs or illustrations showing external features, marking and internal layout'),
    ('1d', 'User information and instructions (Annex II)'),
    ('2a', 'Design and development, including the system architecture'),
    ('2b', 'Vulnerability handling: SBOM, coordinated vulnerability disclosure policy, reporting contact, secure distribution of updates'),
    ('2c', 'Production and monitoring processes and their validation'),
    ('3', 'Cybersecurity risk assessment (Article 13), including how Annex I Part I applies'),
    ('4', 'Information taken into account to determine the support period (Article 13(8))'),
    ('5', 'Harmonised standards, common specifications or certification schemes applied, or the solutions adopted'),
    ('6', 'Reports of tests verifying conformity with Annex I Parts I and II'),
    ('7', 'Copy of the EU declaration of conformity'),
    ('8', 'Software bill of materials, on reasoned request of a market surveillance authority'),
]
SECTIONS = {
    '1': 'General description of the product with digital elements',
    '2': 'Design, development and production, and vulnerability handling processes',
    '3': 'Cybersecurity risk assessment',
    '4': 'Support period',
    '5': 'Standards and specifications applied',
    '6': 'Test reports',
    '7': 'EU declaration of conformity',
    '8': 'Software bill of materials',
}
ARTEFACTS = {'sbom': 'sbom.cdx.json', 'grype': 'grype.json', 'kev': 'kev.json', 'repo': 'repo.json'}
# Process facts a repository shows and a binary does not (D9).
SIGNALS = {
    'security-policy': ['SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md'],
    'dependency-updates': ['.github/dependabot.yml', '.github/dependabot.yaml', 'renovate.json', '.github/renovate.json', '.renovaterc', '.renovaterc.json'],
    'ci': ['.github/workflows/*.yml', '.github/workflows/*.yaml', '.gitlab-ci.yml', 'Jenkinsfile'],
    'tests': ['test/**/*', 'tests/**/*', '__tests__/**/*'],
    'changelog': ['CHANGELOG.md'],
    'lockfile': ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'Cargo.lock', 'go.sum', 'poetry.lock', 'requirements*.txt'],
}


def die(msg):
    sys.exit(f'compline: {msg}')


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git(target, *args):
    try:
        return subprocess.run(['git', '-C', str(target), *args], check=True, capture_output=True, text=True).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


# ---------------------------------------------------------------- scan

def repo_signals(target):
    target = Path(target)
    files = []
    for signal, patterns in SIGNALS.items():
        for pattern in patterns:
            for p in sorted(target.glob(pattern)):
                if p.is_file():
                    files.append({'signal': signal, 'path': p.relative_to(target).as_posix(), 'sha256': sha256(p.read_bytes())})
    found = {f['signal'] for f in files}
    return {'files': files, 'missing': [s for s in SIGNALS if s not in found], 'looked_for': SIGNALS, 'runtime': runtime_packages(target)}


def runtime_packages(target):
    """name@version of the packages that ship, read from the lockfile; None when the lockfile cannot tell (D11)."""
    pnpm, npm = Path(target) / 'pnpm-lock.yaml', Path(target) / 'package-lock.json'
    if pnpm.exists():
        lock = yaml.safe_load(pnpm.read_text(encoding='utf8')) or {}
        if not str(lock.get('lockfileVersion', '')).startswith('9'):
            return None
        snapshots, todo, seen = lock.get('snapshots', {}), [], set()
        for importer in lock.get('importers', {}).values():
            for section in ('dependencies', 'optionalDependencies'):
                todo += [f"{n}@{d['version']}" for n, d in (importer.get(section) or {}).items() if not str(d['version']).startswith('link:')]
        while todo:
            key = todo.pop()
            if key not in seen:
                seen.add(key)
                for section in ('dependencies', 'optionalDependencies'):
                    todo += [f'{n}@{v}' for n, v in ((snapshots.get(key) or {}).get(section) or {}).items()]
        return {'lockfile': 'pnpm-lock.yaml', 'packages': sorted({k.split('(')[0] for k in seen})}
    if npm.exists():
        packages = json.loads(npm.read_text(encoding='utf8')).get('packages', {})
        return {'lockfile': 'package-lock.json', 'packages': sorted({f"{path.rsplit('node_modules/', 1)[-1]}@{p['version']}" for path, p in packages.items() if path and 'version' in p and not p.get('dev')})}
    return None


# Firmware manifests that Syft does not read, and the NVD names Grype matches them by (D14).
FIRMWARE_CPES = {
    'esp-idf': 'cpe:2.3:a:espressif:esp-idf:{}:*:*:*:*:*:*:*',
    'zephyr': 'cpe:2.3:o:zephyrproject:zephyr:{}:*:*:*:*:*:*:*',
}
SKIP_DIRS = {'.git', 'build', 'managed_components', 'node_modules', 'test', 'tests', 'examples'}  # what does not ship


def firmware_components(target):
    """Components declared in ESP-IDF and Zephyr manifests, each with the file it came from (D14).

    A version is 'resolved' only when a lock file or a release tag pins it; a constraint such as ^3.0.3 is kept
    as written and never turned into a version.
    """
    target = Path(target)
    found = lambda name: sorted(p for p in target.rglob(name) if p.is_file() and not SKIP_DIRS & set(p.relative_to(target).parts))
    comps = []

    def add(name, version, resolved, source, ecosystem):
        comps.append({'name': 'esp-idf' if name == 'idf' else name, 'version': str(version), 'resolved': resolved,
                      'source': source.relative_to(target).as_posix(), 'ecosystem': ecosystem})

    locks = found('dependencies.lock')
    for lock in locks:
        for name, d in ((yaml.safe_load(lock.read_text(encoding='utf8')) or {}).get('dependencies') or {}).items():
            add(name, d.get('version', 'unknown'), 'version' in d, lock, 'esp-idf')
    if not locks:  # no lock file: only constraints are known
        for manifest in found('idf_component.yml'):
            for name, spec in ((yaml.safe_load(manifest.read_text(encoding='utf8')) or {}).get('dependencies') or {}).items():
                add(name, spec.get('version', '*') if isinstance(spec, dict) else spec, False, manifest, 'esp-idf')
    for west in found('west.yml'):
        manifest = (yaml.safe_load(west.read_text(encoding='utf8')) or {}).get('manifest') or {}
        default = (manifest.get('defaults') or {}).get('revision', 'master')
        for project in manifest.get('projects') or []:
            revision = str(project.get('revision', default))
            tag = re.fullmatch(r'v?(\d+\.\d+(?:\.\d+)?)', revision)
            add(project['name'], tag.group(1) if tag else revision, bool(tag), west, 'zephyr-west')
            allow = (project.get('import') or {}).get('name-allowlist') if isinstance(project.get('import'), dict) else None
            for module in allow or []:
                add(module, f"from {project['name']} {revision}", False, west, 'zephyr-west')
    return comps


def cyclonedx(firmware):
    """Firmware components as CycloneDX entries; type library, because Grype matches CPEs on that type and not on operating-system (D14)."""
    out = []
    for i, c in enumerate(firmware):
        entry = {'type': 'library', 'bom-ref': f"compline-firmware-{i}", 'name': c['name'], 'version': c['version'],
                 'properties': [{'name': 'compline:source', 'value': c['source']}, {'name': 'compline:ecosystem', 'value': c['ecosystem']},
                                {'name': 'compline:resolved', 'value': str(c['resolved']).lower()}]}
        if c['resolved'] and c['name'] in FIRMWARE_CPES:
            entry['cpe'] = FIRMWARE_CPES[c['name']].format(c['version'])
        out.append(entry)
    return out


def cmd_scan(a):
    out = Path(a.out)
    if out.exists() and any(out.iterdir()) and not a.force:
        die(f'{out} already holds evidence; refusing to overwrite it (pass --force to replace it). See D8.')
    env = {**os.environ, 'SYFT_CHECK_FOR_APP_UPDATE': 'false', 'GRYPE_CHECK_FOR_APP_UPDATE': 'false', 'GRYPE_DB_AUTO_UPDATE': 'false'}
    syft, grype = os.environ.get('SYFT_BIN', 'syft'), os.environ.get('GRYPE_BIN', 'grype')

    def run(cmd):
        return subprocess.run(cmd, check=True, capture_output=True, env=env).stdout

    t0 = time.monotonic()
    sbom = run([syft, 'scan', f'dir:{a.target}', '-o', 'cyclonedx-json', '-q'])
    firmware = firmware_components(a.target)
    if firmware:  # D14: before matching, so Grype sees the SDK and RTOS too
        doc = json.loads(sbom)
        doc['components'] = doc.get('components', []) + cyclonedx(firmware)
        sbom = json.dumps(doc, indent=1).encode()
    t1 = time.monotonic()
    with tempfile.NamedTemporaryFile(suffix='.cdx.json') as f:
        f.write(sbom)
        f.flush()
        vulns = run([grype, f'sbom:{f.name}', '-o', 'json', '-q'])
    t2 = time.monotonic()
    kev = Path(a.kev).read_bytes() if a.kev else urllib.request.urlopen(KEV_URL, timeout=60).read()
    raw = {'sbom': sbom, 'grype': vulns, 'kev': kev, 'repo': json.dumps({**repo_signals(a.target), 'firmware': firmware}, indent=1).encode()}
    for name, data in raw.items():
        try:
            json.loads(data)
        except ValueError:
            die(f'{name} output is not JSON; nothing written.')
    manifest = {
        'target': {
            'name': a.name or Path(a.target).resolve().name,
            'version': a.version or git(a.target, 'describe', '--tags', '--always') or 'unknown',
            'commit': git(a.target, 'rev-parse', 'HEAD') or 'unknown',
        },
        'scanned_at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
        'seconds': {'sbom': round(t1 - t0, 2), 'vulnerabilities': round(t2 - t1, 2)},
        'kev_source': a.kev and Path(a.kev).name or KEV_URL,
        'artefacts': {k: {'file': ARTEFACTS[k], 'sha256': sha256(v)} for k, v in raw.items()},
    }
    out.mkdir(parents=True, exist_ok=True)
    for k, data in raw.items():  # D3: gzip on disk, hash of the uncompressed bytes in the manifest
        (out / f'{ARTEFACTS[k]}.gz').write_bytes(gzip.compress(data, mtime=0))
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f"scanned {manifest['target']['name']} {manifest['target']['version']} into {out}: "
          f"SBOM {manifest['seconds']['sbom']} s, vulnerabilities {manifest['seconds']['vulnerabilities']} s")


# ---------------------------------------------------------------- evidence

def load(evidence):
    """Reads an evidence bundle and refuses it if any artefact no longer matches its manifest hash (D3)."""
    d = Path(evidence)
    manifest_bytes = (d / 'manifest.json').read_bytes()
    m = json.loads(manifest_bytes)
    m['sha256'] = sha256(manifest_bytes)
    data = {}
    for k, meta in m['artefacts'].items():
        raw = gzip.decompress((d / f"{meta['file']}.gz").read_bytes())
        if sha256(raw) != meta['sha256']:
            die(f"{d / meta['file']}.gz does not match its manifest hash; the evidence changed after the scan.")
        data[k] = json.loads(raw)
    return m, data


def vuln_id(match):
    """The CVE alias when there is one, so KEV (keyed by CVE) can be checked."""
    v = match['vulnerability']
    if v['id'].startswith('CVE-'):
        return v['id']
    return next((r['id'] for r in match.get('relatedVulnerabilities', []) if r['id'].startswith('CVE-')), v['id'])


def components(sbom):
    return [c for c in sbom.get('components', []) if c.get('type') != 'file']


def ecosystem(c):
    prop = next((p['value'] for p in c.get('properties', []) if p.get('name') == 'compline:ecosystem'), None)
    if prop:
        return prop
    return c['purl'].split(':', 1)[1].split('/', 1)[0] if c.get('purl') else c.get('type', 'other')


def facts(d):
    comps = components(d['sbom'])
    matches = d['grype'].get('matches', [])
    ids = sorted({vuln_id(x) for x in matches})
    kev_ids = {v['cveID'] for v in d['kev'].get('vulnerabilities', [])}
    tools = d['sbom'].get('metadata', {}).get('tools', {}).get('components', [])
    runtime = d['repo'].get('runtime')
    shipped = set(runtime['packages']) if runtime else None
    ships = lambda x: shipped is None or f"{x['artifact']['name']}@{x['artifact']['version']}" in shipped
    epss = sorted(((e['epss'], e['cve'], x['artifact']['name']) for x in matches if ships(x) for e in x['vulnerability'].get('epss', [])), reverse=True)
    return {
        'runtime_lockfile': runtime and runtime['lockfile'],
        'runtime_components': shipped is not None and sum(1 for c in comps if f"{c.get('name')}@{c.get('version')}" in shipped),
        'runtime_matches': shipped is not None and sorted({(x['artifact']['name'], x['artifact']['version']) for x in matches if f"{x['artifact']['name']}@{x['artifact']['version']}" in shipped}),
        'runtime_match_count': shipped is not None and sum(1 for x in matches if f"{x['artifact']['name']}@{x['artifact']['version']}" in shipped),
        'components': len(comps),
        'ecosystems': Counter(ecosystem(c) for c in comps),
        'matches': len(matches),
        'severity': Counter(x['vulnerability'].get('severity', 'Unknown') for x in matches),
        'ids': ids,
        'cves': [i for i in ids if i.startswith('CVE-')],
        'in_kev': [i for i in ids if i in kev_ids],
        'kev_version': d['kev'].get('catalogVersion', 'unknown'),
        'fixed': sum(1 for x in matches if x['vulnerability'].get('fix', {}).get('state') == 'fixed'),
        'epss_top': list(dict.fromkeys(epss))[:3],
        'syft': next((f"{t['name']} {t['version']}" for t in tools if t.get('name') == 'syft'), 'syft'),
        'grype': f"grype {d['grype'].get('descriptor', {}).get('version', '?')}",
        'db_built': d['grype'].get('descriptor', {}).get('db', {}).get('status', {}).get('built', 'unknown'),
        'repo': d['repo'],
    }


def ev(m, *keys):
    return [{'artefact': m['artefacts'][k]['file'], 'sha256': m['artefacts'][k]['sha256']} for k in keys]


def scan_claims(m, d):
    """Claims the evidence bundle proves on its own. Wording says what the artefact shows and no more (D10)."""
    f = facts(d)
    t = m['target']
    day = m['scanned_at'][:10]
    signal = lambda s: [x['path'] for x in f['repo']['files'] if x['signal'] == s]
    listed = lambda paths, n=4: ', '.join(paths[:n]) + (f' and {len(paths) - n} more' if len(paths) > n else '')
    eco = ', '.join(f'{n} {k}' for k, n in f['ecosystems'].most_common())
    sev = ', '.join(f"{f['severity'][s]} {s.lower()}" for s in SEVERITIES if f['severity'][s])
    manifest = [{'artefact': 'manifest.json', 'sha256': m['sha256']}]
    kev = (f"{len(f['in_kev'])} of the {len(f['cves'])} CVE identifiers are in the CISA Known Exploited Vulnerabilities "
           f"catalogue (version {f['kev_version']})" + (f": {', '.join(f['in_kev'])}" if f['in_kev'] else '') +
           '. The catalogue is a public signal of exploitation, not the Article 14 test, which starts when the manufacturer becomes aware.')
    top = '; '.join(f'{cve} in {pkg}, {p:.3f}' for p, cve, pkg in f['epss_top']) or 'none scored'
    scope = 'in runtime dependencies' if f['runtime_lockfile'] else 'across all components'
    deps, policy, ci = signal('dependency-updates'), signal('security-policy'), signal('ci')
    test_code = [p for p in signal('tests') if re.search(r'(test|spec)', Path(p).name, re.I)]
    if f['runtime_lockfile']:
        runtime_text = (f"{f['runtime_components']} of the {f['components']} SBOM components are runtime dependencies according to "
                        f"{f['runtime_lockfile']}; the rest are development and build tools that do not ship with the product.")
        pkgs = ', '.join(f'{n} {v}' for n, v in f['runtime_matches'])
        runtime_vulns_text = (f"{f['runtime_match_count']} of the {f['matches']} matches are in runtime dependencies" +
                              (f" ({pkgs})" if pkgs else '') + '; the others are in development and build tools.')
    else:
        runtime_text = 'The lockfile does not say which components ship with the product; the SBOM counts every package found.'
        runtime_vulns_text = 'Which matches affect shipped components is not known from the repository; see the interview.'
    claims = [
        ('1b', 'scan.version', f"Version assessed: {t['name']} {t['version']}, commit {t['commit'][:12]}.", manifest),
        ('2b', 'scan.sbom', f"Software bill of materials: CycloneDX JSON, {f['components']} components ({eco}), generated by {f['syft']} on {day}.", ev(m, 'sbom')),
        ('2b', 'repo.runtime', runtime_text, ev(m, 'sbom', 'repo')),
        ('2b', 'scan.vulnerabilities', f"Known vulnerabilities at scan time: {f['matches']} matches ({sev or 'none'}), {len(f['ids'])} distinct identifiers, found by {f['grype']} with the vulnerability database built {f['db_built'][:10]}.", ev(m, 'sbom', 'grype')),
        ('2b', 'scan.runtime-vulnerabilities', runtime_vulns_text, ev(m, 'grype', 'repo')),
        ('2b', 'scan.fixes', f"{f['fixed']} of the {f['matches']} matches have a fixed version available upstream.", ev(m, 'grype')),
        ('2b', 'scan.kev', kev, ev(m, 'grype', 'kev')),
        ('2b', 'repo.dependency-updates', f'Automated dependency updates are configured in the repository: {listed(deps)}.' if deps else 'No automated dependency update configuration in the repository (looked for Dependabot and Renovate files).', ev(m, 'repo')),
        ('2b', 'repo.security-policy', f'Security policy file in the repository: {listed(policy)}.' if policy else 'No security policy file in the repository (looked for SECURITY.md, .github/SECURITY.md and docs/SECURITY.md).', ev(m, 'repo')),
        ('2c', 'repo.ci', f'Build and release automation is defined in the repository: {len(ci)} CI workflow files ({listed(ci)}).' if ci else 'No CI workflow definition in the repository.', ev(m, 'repo')),
        ('3', 'scan.epss', f'Input for the risk assessment, highest EPSS exploit probabilities {scope}: {top}.', ev(m, 'grype', 'repo')),
        ('6', 'scan.test', f"Dependency scan on {day}: {f['matches']} vulnerability matches across {f['components']} components; SBOM in {m['seconds']['sbom']} s and matching in {m['seconds']['vulnerabilities']} s.", ev(m, 'sbom', 'grype') + manifest),
        ('6', 'repo.tests', f"Automated test code in the repository: {len(test_code)} files (for example {listed(test_code, 2)})." if test_code else 'No automated test code in the repository (looked in test/, tests/ and __tests__/).', ev(m, 'repo')),
        ('8', 'scan.sbom-on-request', f"The SBOM is available in CycloneDX JSON ({f['components']} components) and `compline scan` regenerates it for every release.", ev(m, 'sbom')),
    ]
    firmware = d['repo'].get('firmware')  # absent in bundles scanned before D14
    if firmware:
        pinned = [c for c in firmware if c['resolved']]
        loose = [c for c in firmware if not c['resolved']]
        named = lambda cs: listed([f"{c['name']} {c['version']}" for c in cs])
        keys = {(c['name'], c['version']) for c in firmware}
        hits = sum(1 for x in d['grype'].get('matches', []) if (x['artifact']['name'], x['artifact']['version']) in keys)
        text = (f"{len(firmware)} firmware components are declared in manifests the SBOM tool does not read "
                f"({listed(sorted({c['source'] for c in firmware}))}) and were added to the SBOM, each marked with its source file: "
                f"{len(pinned)} with a pinned version" + (f" ({named(pinned)})" if pinned else '') +
                f", {len(loose)} with only a version constraint or a branch" + (f" ({named(loose)})" if loose else '') +
                f". {hits} of the vulnerability matches are in these components." +
                (' Without a lock file or a release tag, the exact versions of the others are not known from the repository; see the interview.' if loose else ''))
        claims.append(('2b', 'repo.firmware', text, ev(m, 'sbom', 'grype', 'repo')))
    return [{'item': i, 'key': k, 'status': 'evidence', 'text': text, 'sources': src} for i, k, text, src in claims]


# ---------------------------------------------------------------- interview

def read_yaml(path):
    with open(path, encoding='utf8') as fh:
        return yaml.safe_load(fh) or {}


def answer_errors(questions, answers):
    """An answer without a source is refused: a URL with its retrieval date, or a person with a date (D6)."""
    known = {q['id'] for q in questions['questions']}
    errors, seen = [], set()
    for i, a in enumerate(answers.get('answers', []), 1):
        qid = a.get('question')
        where = f'answer {i} ({qid})'
        if qid not in known:
            errors.append(f'{where}: no such question in the bank')
        if qid in seen:
            errors.append(f'{where}: question answered twice')
        seen.add(qid)
        if not str(a.get('answer', '')).strip():
            errors.append(f'{where}: empty answer')
        s = a.get('source') or {}
        if not ((s.get('url') and s.get('retrieved')) or (s.get('person') and s.get('date'))):
            errors.append(f'{where}: source must be a URL with its retrieval date, or a person with a date')
    return errors


def interview_claims(questions, answers):
    given = {a['question']: a for a in answers.get('answers', [])}
    claims = []
    for q in questions['questions']:
        a = given.get(q['id'])
        if a:
            claims.append({'item': str(q['item']), 'key': q['id'], 'status': 'answered', 'text': f"{q['label']}: {' '.join(str(a['answer']).split())}", 'sources': [a['source']]})
        else:
            claims.append({'item': str(q['item']), 'key': q['id'], 'status': 'pending', 'text': f"PENDING ({q['id']}): {' '.join(q['ask'].split())}", 'sources': []})
    return claims


def cmd_interview(a):
    questions = read_yaml(QUESTIONS)
    answers = read_yaml(a.answers) if a.answers else {}
    errors = answer_errors(questions, answers)
    if errors:
        die('answers refused:\n  ' + '\n  '.join(errors))
    claims = interview_claims(questions, answers)
    pending = [c for c in claims if c['status'] == 'pending']
    print(f'{len(claims) - len(pending)} of {len(claims)} questions answered with a source; {len(pending)} still to ask:\n')
    for c in pending:
        q = next(q for q in questions['questions'] if q['id'] == c['key'])
        print(f"- [{q['item']}] {q['id']}: {' '.join(q['ask'].split())}")


# ---------------------------------------------------------------- annex

def build_annex(evidence, answers_path=None):
    m, d = load(evidence)
    questions = read_yaml(QUESTIONS)
    answers = read_yaml(answers_path) if answers_path else {}
    errors = answer_errors(questions, answers)
    if errors:
        die('answers refused:\n  ' + '\n  '.join(errors))
    claims = scan_claims(m, d) + interview_claims(questions, answers)
    items = [{'id': i, 'title': title, 'claims': [c for c in claims if c['item'] == i]} for i, title in ANNEX_VII]
    return {
        'target': m['target'],
        'scanned_at': m['scanned_at'],
        'manifest_sha256': m['sha256'],
        'artefacts': m['artefacts'],
        'answers': answers.get('product'),
        'items': items,
    }


def parity_problems(annex):
    """Every Annex VII point is present, in order, and every claim is evidenced, answered with a source, or PENDING (D7)."""
    problems = []
    ids = [it['id'] for it in annex['items']]
    if ids != [i for i, _ in ANNEX_VII]:
        problems.append(f'Annex VII points missing or out of order: {ids}')
    for it in annex['items']:
        if not it['claims']:
            problems.append(f"{it['id']}: empty")
        for c in it['claims']:
            if not c['text'].strip():
                problems.append(f"{it['id']} {c['key']}: empty text")
            elif c['status'] in ('evidence', 'answered') and not c['sources']:
                problems.append(f"{it['id']} {c['key']}: {c['status']} without a source")
            elif c['status'] == 'pending' and not c['text'].startswith('PENDING'):
                problems.append(f"{it['id']} {c['key']}: pending but not marked PENDING")
            elif c['status'] not in ('evidence', 'answered', 'pending'):
                problems.append(f"{it['id']} {c['key']}: unknown status {c['status']}")
    return problems


def tag(s):
    if 'artefact' in s:
        return f"[evidence: {s['artefact']} sha256:{s['sha256'][:12]}]"
    if 'url' in s:
        return f"[source: {s['url']}, retrieved {s['retrieved']}]"
    return f"[source: {s['person']}, {s['date']}]"


def counts(annex):
    return Counter(c['status'] for it in annex['items'] for c in it['claims'])


def render(annex):
    t, n = annex['target'], counts(annex)
    lines = [
        '# Technical documentation, Cyber Resilience Act (Regulation (EU) 2024/2847), Annex VII',
        '',
        f"Product: {t['name']} {t['version']} (commit {t['commit'][:12]}). Scanned {annex['scanned_at']}.",
        f"Interview answers: {annex['answers'] or 'none yet'}.",
        '',
        f"Draft generated by Compline for engineer review and signature. Not legal advice and not a conformity assessment. "
        f"{n['evidence']} claims come from scan evidence, {n['answered']} from interview answers with their source, "
        f"{n['pending']} are PENDING and listed as questions, never invented.",
    ]
    section = None
    for it in annex['items']:
        if it['id'][0] != section:
            section = it['id'][0]
            lines += ['', f'## {section}. {SECTIONS[section]}']
        label = f"{it['id'][0]}({it['id'][1]})" if len(it['id']) == 2 else it['id']
        lines += ['', f"### {label} {it['title']}", '']
        lines += [f"- {c['text']} {' '.join(tag(s) for s in c['sources'])}".rstrip() for c in it['claims']]
    lines += ['', '## Evidence index', '', '| Artefact | SHA-256 |', '| --- | --- |']
    lines += [f"| {a['file']} | `{a['sha256']}` |" for a in annex['artefacts'].values()]
    lines += [f"| manifest.json | `{annex['manifest_sha256']}` |", '',
              'Check an artefact: `gunzip -c evidence/<bundle>/<file>.gz | sha256sum`.', '']
    return '\n'.join(lines)


def cmd_annex(a):
    annex = build_annex(a.evidence, a.answers)
    problems = parity_problems(annex)
    if problems:
        die('annex refused, parity check failed:\n  ' + '\n  '.join(problems))
    out = Path(a.out)
    out.write_text(render(annex), encoding='utf8')
    out.with_suffix('.json').write_text(json.dumps(annex, indent=1) + '\n', encoding='utf8')
    n = counts(annex)
    print(f"wrote {out} and {out.with_suffix('.json').name}: {n['evidence']} evidence claims, {n['answered']} answered, {n['pending']} pending, {len(annex['items'])}/{len(ANNEX_VII)} Annex VII points")


# ---------------------------------------------------------------- diff

def component_versions(sbom):
    versions = {}
    for c in components(sbom):
        key = c['purl'].split('@')[0] if c.get('purl') else c.get('name')
        versions.setdefault(key, set()).add(c.get('version', ''))
    return versions


def vuln_keys(grype):
    """(identifier, package) -> versions: a fix is a vulnerability that left the package, not a package that changed version."""
    keys = {}
    for x in grype.get('matches', []):
        keys.setdefault((vuln_id(x), x['artifact']['name']), set()).add(f"{x['artifact']['version']} {x['vulnerability'].get('severity', 'Unknown').lower()}")
    return keys


def diff_report(old, new, answers_path=None):
    (mo, do), (mn, dn) = load(old), load(new)
    co, cn = component_versions(do['sbom']), component_versions(dn['sbom'])
    added = sorted(k for k in cn if k not in co)
    removed = sorted(k for k in co if k not in cn)
    changed = sorted(k for k in cn if k in co and cn[k] != co[k])
    vo, vn = vuln_keys(do['grype']), vuln_keys(dn['grype'])
    ao, an = build_annex(old, answers_path), build_annex(new, answers_path)
    texts = lambda annex: {c['key']: (it['id'], c['text']) for it in annex['items'] for c in it['claims']}
    to, tn = texts(ao), texts(an)
    claims = [(tn[k][0], k, to[k][1], tn[k][1]) for k in tn if k in to and to[k][1] != tn[k][1]]
    v = lambda m: f"{m['target']['name']} {m['target']['version']} ({m['target']['commit'][:12]})"
    out = [f'# What changed between {v(mo)} and {v(mn)}', '',
           f"Old evidence manifest sha256:{mo['sha256'][:12]}, new evidence manifest sha256:{mn['sha256'][:12]}. "
           'Keep both annexes and this diff: together they are the audit trail.', '',
           f'## Components: {len(added)} added, {len(removed)} removed, {len(changed)} changed version', '']
    out += [f"- added {k} {', '.join(sorted(cn[k]))}" for k in added]
    out += [f"- removed {k} {', '.join(sorted(co[k]))}" for k in removed]
    out += [f"- changed {k}: {', '.join(sorted(co[k]))} -> {', '.join(sorted(cn[k]))}" for k in changed]
    new_v, gone_v, kept_v = sorted(vn.keys() - vo.keys()), sorted(vo.keys() - vn.keys()), sorted(vn.keys() & vo.keys())
    out += ['', f'## Vulnerabilities: {len(new_v)} new, {len(gone_v)} resolved, {len(kept_v)} still present', '']
    out += [f"- new {i} in {p} {', '.join(sorted(vn[(i, p)]))}" for i, p in new_v]
    out += [f"- resolved {i} in {p} {', '.join(sorted(vo[(i, p)]))}" for i, p in gone_v]
    out += [f"- still present {i} in {p}: {', '.join(sorted(vo[(i, p)]))} -> {', '.join(sorted(vn[(i, p)]))}" for i, p in kept_v]
    out += ['', f'## Technical file claims: {len(claims)} changed', '']
    for item, key, before, after in sorted(claims):
        out += [f'- {item} {key}', f'  - before: {before}', f'  - after: {after}']
    return '\n'.join(out) + '\n'


def cmd_diff(a):
    report = diff_report(a.old, a.new, a.answers)
    if a.out:
        Path(a.out).write_text(report, encoding='utf8')
        print(f'wrote {a.out}')
    else:
        print(report, end='')


def main(argv=None):
    p = argparse.ArgumentParser(prog='compline', description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='command', required=True)
    s = sub.add_parser('scan', help='SBOM, vulnerabilities, CISA KEV and repository signals into an evidence bundle')
    s.add_argument('target')
    s.add_argument('--out', required=True)
    s.add_argument('--kev', help='local copy of the CISA KEV catalogue (offline); default: download it')
    s.add_argument('--name')
    s.add_argument('--version')
    s.add_argument('--force', action='store_true', help='replace an existing evidence bundle')
    s.set_defaults(func=cmd_scan)
    s = sub.add_parser('annex', help='draft the Annex VII technical file from an evidence bundle and interview answers')
    s.add_argument('evidence')
    s.add_argument('--answers')
    s.add_argument('--out', default='annex-vii.md')
    s.set_defaults(func=cmd_annex)
    s = sub.add_parser('interview', help='check interview answers and list the questions still to ask')
    s.add_argument('--answers')
    s.set_defaults(func=cmd_interview)
    s = sub.add_parser('diff', help='what changed between two releases: components, vulnerabilities, claims')
    s.add_argument('old')
    s.add_argument('new')
    s.add_argument('--answers')
    s.add_argument('--out')
    s.set_defaults(func=cmd_diff)
    a = p.parse_args(argv)
    a.func(a)


if __name__ == '__main__':
    main()
