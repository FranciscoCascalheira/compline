"""Tests for compline.py: one per command, the Annex VII parity promise, and the checks themselves.

Run: python3 -m unittest -v  (offline: uses the evidence bundles committed under evidence/)
"""
import copy
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import compline  # noqa: E402

OLD, NEW = HERE / 'evidence' / 'zigbee2mqtt-2.13.0', HERE / 'evidence' / 'zigbee2mqtt-2.14.2'
ANSWERS = HERE / 'interview' / 'answers-zigbee2mqtt.yaml'


def cli(*args, **kw):
    return subprocess.run([sys.executable, str(HERE / 'compline.py'), *map(str, args)], capture_output=True, text=True, **kw)


def raw(bundle, name):
    return gzip.decompress((Path(bundle) / f'{name}.gz').read_bytes())


class Scan(unittest.TestCase):
    def test_writes_a_bundle_whose_hashes_match_and_refuses_to_overwrite_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            for name in ('sbom.cdx.json', 'grype.json', 'kev.json'):
                (tmp / name).write_bytes(raw(NEW, name))
            for tool, output in (('syft', 'sbom.cdx.json'), ('grype', 'grype.json')):  # stand-ins that replay the real 2.14.2 scan
                stub = tmp / f'fake-{tool}'
                stub.write_text(f'#!/bin/sh\ncat "{tmp / output}"\n')
                stub.chmod(0o755)
            target = tmp / 'target'
            (target / '.github' / 'workflows').mkdir(parents=True)
            (target / '.github' / 'workflows' / 'ci.yml').write_text('on: push\n')
            (target / 'test').mkdir()
            (target / 'test' / 'device.test.js').write_text('// test\n')
            env = {**os.environ, 'SYFT_BIN': str(tmp / 'fake-syft'), 'GRYPE_BIN': str(tmp / 'fake-grype')}
            args = ('scan', target, '--out', tmp / 'ev', '--kev', tmp / 'kev.json', '--name', 'demo', '--version', '1.0')

            r = cli(*args, env=env)
            self.assertEqual(r.returncode, 0, r.stderr)
            m = json.loads((tmp / 'ev' / 'manifest.json').read_text())
            self.assertEqual(m['target']['version'], '1.0')
            for meta in m['artefacts'].values():
                self.assertEqual(hashlib.sha256(raw(tmp / 'ev', meta['file'])).hexdigest(), meta['sha256'], meta['file'])
            repo = json.loads(raw(tmp / 'ev', 'repo.json'))
            self.assertEqual({f['signal'] for f in repo['files']}, {'ci', 'tests'})
            self.assertIn('security-policy', repo['missing'])

            again = cli(*args, env=env)
            self.assertNotEqual(again.returncode, 0)
            self.assertIn('refusing to overwrite', again.stderr)


class RuntimePackages(unittest.TestCase):
    def test_pnpm_lock_keeps_the_runtime_closure_and_drops_dev_tools(self):
        lock = """lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a: {specifier: ^1.0.0, version: 1.0.0}
      local: {specifier: 'workspace:*', version: 'link:packages/local'}
    devDependencies:
      d: {specifier: ^1.0.0, version: 1.0.0}
snapshots:
  a@1.0.0:
    dependencies:
      b: 2.0.0(c@3.0.0)
  b@2.0.0(c@3.0.0): {}
  d@1.0.0:
    dependencies:
      e: 1.0.0
  e@1.0.0: {}
"""
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'pnpm-lock.yaml').write_text(lock)
            self.assertEqual(compline.runtime_packages(tmp), {'lockfile': 'pnpm-lock.yaml', 'packages': ['a@1.0.0', 'b@2.0.0']})

    def test_npm_lock_drops_packages_flagged_dev(self):
        lock = {'lockfileVersion': 3, 'packages': {'': {'name': 'x'}, 'node_modules/a': {'version': '1.0.0'},
                                                   'node_modules/a/node_modules/b': {'version': '2.0.0'},
                                                   'node_modules/d': {'version': '1.0.0', 'dev': True}}}
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'package-lock.json').write_text(json.dumps(lock))
            self.assertEqual(compline.runtime_packages(tmp)['packages'], ['a@1.0.0', 'b@2.0.0'])


class Firmware(unittest.TestCase):
    """D14: ESP-IDF and Zephyr manifests, which Syft does not read."""

    def tree(self, files):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        for path, text in files.items():
            (tmp / path).parent.mkdir(parents=True, exist_ok=True)
            (tmp / path).write_text(text)
        return tmp

    def test_esp_idf_lock_pins_versions_and_names_the_sdk(self):
        t = self.tree({
            'dependencies.lock': 'dependencies:\n  idf:\n    source: {type: idf}\n    version: 5.4.1\n'
                                 '  espressif/led_strip:\n    version: 3.0.3\nversion: 2.0.0\n',
            'main/idf_component.yml': 'dependencies:\n  idf: ">=5.4"\n',
            'managed_components/espressif__led_strip/idf_component.yml': 'dependencies:\n  idf: ">=4.4"\n',
        })
        comps = compline.firmware_components(t)
        self.assertEqual([(c['name'], c['version'], c['resolved'], c['source']) for c in comps],
                         [('esp-idf', '5.4.1', True, 'dependencies.lock'), ('espressif/led_strip', '3.0.3', True, 'dependencies.lock')])
        cdx = compline.cyclonedx(comps)
        self.assertEqual(cdx[0]['cpe'], 'cpe:2.3:a:espressif:esp-idf:5.4.1:*:*:*:*:*:*:*')
        self.assertNotIn('cpe', cdx[1])  # no NVD name known for registry components
        self.assertEqual([compline.nvd_name(n) for n in ('ARMmbed/mbedtls', 'curl', 'mynewt-nimble', 'littlefs')], ['mbedtls', 'libcurl', 'nimble', None])
        self.assertTrue(all(c['type'] == 'library' for c in cdx))

    def test_manifest_without_lock_keeps_constraints_and_claims_no_version(self):
        t = self.tree({'main/idf_component.yml': 'dependencies:\n  idf: ">=5.4"\n  espressif/ds18b20: "^0.4.0"\n'
                                                  '  local/x:\n    version: "~1.2"\n',
                       'test/deps/main/idf_component.yml': 'dependencies:\n  unity: "*"\n'})
        comps = compline.firmware_components(t)
        self.assertEqual([(c['name'], c['version'], c['resolved']) for c in comps],
                         [('esp-idf', '>=5.4', False), ('espressif/ds18b20', '^0.4.0', False), ('local/x', '~1.2', False)])
        self.assertFalse(any('cpe' in c for c in compline.cyclonedx(comps)))

    def test_without_a_lock_the_sdk_version_comes_from_one_exact_tag_in_the_build(self):
        manifest = {'main/idf_component.yml': 'dependencies:\n  idf: ">=5.4"\n'}
        ci = ('env:\n  IDF_VERSION: v5.4.4\njobs:\n  build:\n    steps:\n'
              '      - uses: espressif/esp-idf-ci-action@v1\n        with:\n          esp_idf_version: ${{ env.IDF_VERSION }}\n')
        sdk = lambda files: [c for c in compline.firmware_components(self.tree({**manifest, **files})) if c['name'] == 'esp-idf'][0]

        c = sdk({'.github/workflows/build.yml': ci})
        self.assertEqual((c['version'], c['resolved'], c['source'], c['constraint']), ('5.4.4', True, '.github/workflows/build.yml', '>=5.4'))
        self.assertEqual(sdk({'Dockerfile': 'FROM espressif/idf:v5.3.2\n'})['version'], '5.3.2')
        self.assertFalse(sdk({'Dockerfile': 'FROM espressif/idf:release-v5.4\n'})['resolved'])  # a branch is not a version
        matrix = {'.github/workflows/a.yml': ci, 'Dockerfile': 'FROM espressif/idf:v5.3.2\n'}
        self.assertFalse(sdk(matrix)['resolved'])  # two versions in the build prove neither
        locked = sdk({'.github/workflows/build.yml': ci, 'dependencies.lock': 'dependencies:\n  idf:\n    version: 5.4.1\n'})
        self.assertEqual((locked['version'], locked['source']), ('5.4.1', 'dependencies.lock'))

    def test_platformio_exact_versions_are_pinned_and_ranges_are_not(self):
        ini = ('[env]\nplatform = espressif32@6.5.0\nlib_deps =\n    bblanchon/ArduinoJson@^6.21.6\n    knolleary/PubSubClient@2.8\n'
               '[env:s3]\nplatform = espressif32@6.5.0\n')
        comps = compline.firmware_components(self.tree({'platformio.ini': ini}))
        self.assertEqual([(c['name'], c['version'], c['resolved']) for c in comps],
                         [('espressif32', '6.5.0', True), ('bblanchon/ArduinoJson', '^6.21.6', False), ('knolleary/PubSubClient', '2.8', True)])

    def test_platformio_resolves_references_extends_and_extra_configs_like_the_build(self):
        ini = ('[platformio]\nextra_configs = envs.ini\n'
               '[libraries]\njson = ArduinoJson@6.18.5\nunused = Never@1.0.0\n'
               'ble = https://github.com/h2zero/NimBLE-Arduino/archive/2.5.0.zip\nlog = https://github.com/x/Arduino-Log/archive/6d1f14a.zip\n'
               '[com]\nesp32 = https://github.com/pioarduino/platform-espressif32/releases/download/55.03.39/platform-espressif32.zip\n'
               '[env]\nlib_deps =\n  ${libraries.json} ; comment\n  ${libraries.log}\n'
               '[base]\nplatform = ${com.esp32}\nlib_deps =\n  ${env.lib_deps}\n  ${libraries.ble}\n')
        t = self.tree({'platformio.ini': ini, 'envs.ini': '[env:board]\nextends = base\n'})
        self.assertEqual(sorted(compline.platformio_components(t / 'platformio.ini')),
                         [('Arduino-Log', 'commit 6d1f14a', False), ('ArduinoJson', '6.18.5', True), ('NimBLE-Arduino', '2.5.0', True),
                          ('platform-espressif32', '55.03.39', True)])

    def test_submodule_is_a_version_only_when_its_commit_carries_a_release_tag(self):
        git = lambda cwd, *a: subprocess.run(['git', '-c', 'user.name=t', '-c', 'user.email=t@t', '-c', 'protocol.file.allow=always', *a],
                                             cwd=cwd, check=True, capture_output=True)
        root = self.tree({'lib/README': 'x\n', 'fw/main.c': 'int main(void) { return 0; }\n'})
        lib, fw = root / 'lib', root / 'fw'
        for repo in (lib, fw):
            git(repo, 'init', '-q')
        git(lib, 'add', '.'); git(lib, 'commit', '-qm', 'lib'); git(lib, 'tag', 'v2.28.1')
        git(fw, 'submodule', 'add', '-q', str(lib), 'third_party/mbedtls'); git(fw, 'add', '.'); git(fw, 'commit', '-qm', 'fw')
        [c] = compline.firmware_components(fw)
        self.assertEqual((c['name'], c['version'], c['resolved'], c['ecosystem']), ('lib', '2.28.1', True, 'git-submodule'))
        git(lib, 'commit', '-q', '--allow-empty', '-m', 'untagged'); git(fw / 'third_party' / 'mbedtls', 'pull', '-q', 'origin', 'HEAD')
        git(fw, 'commit', '-qam', 'bump')
        [c] = compline.firmware_components(fw)
        self.assertFalse(c['resolved'])
        self.assertTrue(c['version'].startswith('commit '))

    def test_west_tag_is_a_version_and_a_branch_is_not(self):
        t = self.tree({'west.yml': 'manifest:\n  projects:\n'
                                   '    - name: zephyr\n      revision: v3.7.0\n      import:\n        name-allowlist: [hal_nordic]\n'
                                   '    - name: mylib\n      revision: main\n',
                       'build/west.yml': 'manifest: {projects: [{name: ignored}]}\n'})
        comps = compline.firmware_components(t)
        self.assertEqual([(c['name'], c['version'], c['resolved']) for c in comps],
                         [('zephyr', '3.7.0', True), ('hal_nordic', 'from zephyr v3.7.0', False), ('mylib', 'main', False)])
        self.assertEqual(compline.cyclonedx(comps)[0]['cpe'], 'cpe:2.3:o:zephyrproject:zephyr:3.7.0:*:*:*:*:*:*:*')

    def test_scan_adds_them_to_the_sbom_before_matching_and_the_file_says_where_they_came_from(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / 'kev.json').write_bytes(raw(NEW, 'kev.json'))
            (tmp / 'syft.json').write_text(json.dumps({'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'components': []}))
            (tmp / 'fake-syft').write_text(f'#!/bin/sh\ncat "{tmp / "syft.json"}"\n')
            # The stand-in Grype records the SBOM it was given, to prove the firmware was in it before matching.
            (tmp / 'fake-grype').write_text(f'#!/bin/sh\ncat "${{1#sbom:}}" > "{tmp / "seen.json"}"\necho \'{{"matches": []}}\'\n')
            for s in ('fake-syft', 'fake-grype'):
                (tmp / s).chmod(0o755)
            target = tmp / 'fw'
            (target / 'main').mkdir(parents=True)
            (target / 'main' / 'idf_component.yml').write_text('dependencies:\n  idf: ">=5.4"\n')
            env = {**os.environ, 'SYFT_BIN': str(tmp / 'fake-syft'), 'GRYPE_BIN': str(tmp / 'fake-grype')}
            r = cli('scan', target, '--out', tmp / 'ev', '--kev', tmp / 'kev.json', '--version', '1.0', env=env)
            self.assertEqual(r.returncode, 0, r.stderr)

            seen = json.loads((tmp / 'seen.json').read_text())
            self.assertEqual([c['name'] for c in seen['components']], ['esp-idf'])
            self.assertEqual(json.loads(raw(tmp / 'ev', 'repo.json'))['firmware'][0]['source'], 'main/idf_component.yml')
            claims = {c['key']: c['text'] for item in compline.build_annex(tmp / 'ev')['items'] for c in item['claims'] if c['status'] == 'evidence'}
            self.assertIn('1 firmware component is declared', claims['repo.firmware'])
            self.assertIn('esp-idf >=5.4', claims['repo.firmware'])
            self.assertIn('not known from the repository', claims['repo.firmware'])

    def test_bundles_scanned_before_d14_get_no_firmware_claim(self):
        m, d = compline.load(NEW)
        self.assertNotIn('repo.firmware', {c['key'] for c in compline.scan_claims(m, d)})


class Annex(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        out = Path(cls.tmp.name) / 'annex.md'
        r = cli('annex', NEW, '--answers', ANSWERS, '--out', out)
        assert r.returncode == 0, r.stderr
        cls.md = out.read_text()
        cls.annex = json.loads(out.with_suffix('.json').read_text())
        cls.manifest = json.loads((NEW / 'manifest.json').read_text())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_numbers_come_from_the_artefacts(self):
        grype = json.loads(raw(NEW, 'grype.json'))
        sbom = json.loads(raw(NEW, 'sbom.cdx.json'))
        components = sum(1 for c in sbom['components'] if c['type'] != 'file')
        self.assertIn(f"{len(grype['matches'])} matches", self.md)
        self.assertIn(f'{components} components', self.md)

    def test_every_scan_claim_cites_the_hash_of_its_artefact(self):
        hashes = {a['file']: a['sha256'] for a in self.manifest['artefacts'].values()}
        hashes['manifest.json'] = hashlib.sha256((NEW / 'manifest.json').read_bytes()).hexdigest()
        evidence = [c for it in self.annex['items'] for c in it['claims'] if c['status'] == 'evidence']
        self.assertGreaterEqual(len(evidence), 10)
        for c in evidence:
            for s in c['sources']:
                self.assertEqual(s['sha256'], hashes[s['artefact']], c['key'])
        self.assertIn(f"grype.json sha256:{hashes['grype.json'][:12]}", self.md)

    def test_answers_carry_their_source(self):
        answered = [c for it in self.annex['items'] for c in it['claims'] if c['status'] == 'answered']
        self.assertTrue(answered)
        for c in answered:
            self.assertTrue(c['sources'][0].get('url') and c['sources'][0].get('retrieved'), c['key'])
        self.assertIn('[source: https://github.com/Koenkk/zigbee2mqtt/security/policy, retrieved 2026-10-26]', self.md)

    def test_changed_evidence_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / 'bundle'
            shutil.copytree(NEW, bundle)
            grype = json.loads(raw(bundle, 'grype.json'))
            grype['matches'] = grype['matches'][1:]  # someone drops an inconvenient finding
            (bundle / 'grype.json.gz').write_bytes(gzip.compress(json.dumps(grype).encode()))
            r = cli('annex', bundle, '--out', Path(tmp) / 'a.md')
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('does not match its manifest hash', r.stderr)


class Interview(unittest.TestCase):
    def test_lists_what_is_still_to_ask(self):
        questions = compline.read_yaml(compline.QUESTIONS)['questions']
        answered = len(compline.read_yaml(ANSWERS)['answers'])
        r = cli('interview', '--answers', ANSWERS)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f'{answered} of {len(questions)} questions answered with a source; {len(questions) - answered} still to ask', r.stdout)
        self.assertIn('Q-4', r.stdout)

    def test_refuses_answers_without_a_source_or_to_unknown_questions(self):
        cases = {
            'source must be': {'answers': [{'question': 'Q-4', 'answer': 'Five years.'}]},
            'no such question': {'answers': [{'question': 'Q-99', 'answer': 'x', 'source': {'url': 'https://example.org', 'retrieved': '2026-10-26'}}]},
            'answered twice': {'answers': [{'question': 'Q-4', 'answer': 'x', 'source': {'person': 'CTO', 'date': '2026-10-27'}}] * 2},
        }
        for message, answers in cases.items():
            with tempfile.NamedTemporaryFile('w', suffix='.yaml', delete=False) as f:
                json.dump(answers, f)  # JSON is valid YAML
            try:
                r = cli('interview', '--answers', f.name)
                self.assertNotEqual(r.returncode, 0, message)
                self.assertIn(message, r.stderr)
            finally:
                os.unlink(f.name)


class Parity(unittest.TestCase):
    def test_every_annex_vii_point_is_evidenced_answered_or_pending(self):
        for answers in (None, ANSWERS):
            annex = compline.build_annex(NEW, answers)
            self.assertEqual(compline.parity_problems(annex), [])
            self.assertEqual([it['id'] for it in annex['items']], [i for i, _ in compline.ANNEX_VII])
            n = compline.counts(annex)
            sys.stderr.write(f"\n  parity ({'demo answers' if answers else 'no answers'}): "
                             f"{n['evidence']} evidenced, {n['answered']} answered, {n['pending']} PENDING ")

    def test_every_point_the_scan_cannot_prove_has_a_question(self):
        asked = {str(q['item']) for q in compline.read_yaml(compline.QUESTIONS)['questions']}
        self.assertEqual({i for i, _ in compline.ANNEX_VII} - asked, {'8'})  # point 8 is the SBOM itself

    def test_the_parity_check_itself_catches_each_kind_of_gap(self):
        annex = compline.build_annex(NEW, ANSWERS)
        breaks = {
            'empty': lambda a: a['items'][3].update(claims=[]),
            'empty text': lambda a: a['items'][0]['claims'][0].update(text=' '),
            'without a source': lambda a: next(c for it in a['items'] for c in it['claims'] if c['status'] == 'evidence').update(sources=[]),
            'not marked PENDING': lambda a: next(c for it in a['items'] for c in it['claims'] if c['status'] == 'pending').update(text='Five years.'),
            'missing or out of order': lambda a: a['items'].pop(),
        }
        for message, damage in breaks.items():
            broken = copy.deepcopy(annex)
            damage(broken)
            self.assertTrue(any(message in p for p in compline.parity_problems(broken)), message)


class Diff(unittest.TestCase):
    def test_reports_component_vulnerability_and_claim_changes(self):
        r = cli('diff', OLD, NEW, '--answers', ANSWERS)
        self.assertEqual(r.returncode, 0, r.stderr)
        purls = lambda bundle: {c['purl'].split('@')[0] for c in json.loads(raw(bundle, 'sbom.cdx.json'))['components'] if c.get('purl')}
        added, removed = len(purls(NEW) - purls(OLD)), len(purls(OLD) - purls(NEW))
        self.assertIn(f'## Components: {added} added, {removed} removed', r.stdout)
        self.assertIn('zigbee2mqtt 2.13.0', r.stdout)
        self.assertIn('- 1b scan.version', r.stdout)
        self.assertIn('## Vulnerabilities:', r.stdout)


class Demo(unittest.TestCase):
    def test_demo_runs_offline_from_the_bundles_in_under_60_seconds(self):
        script = (HERE / 'demo.sh').read_text()
        for word in ('curl', 'wget', 'git clone', 'compline.py scan', 'http:', 'https:'):
            self.assertNotIn(word, script, f'demo.sh must not reach the network ({word})')
        with tempfile.TemporaryDirectory() as tmp:
            start = time.monotonic()
            r = subprocess.run(['bash', str(HERE / 'demo.sh'), tmp], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertLess(time.monotonic() - start, 60)
            self.assertTrue(any(Path(tmp).glob('annex-vii-*.md')) and any(Path(tmp).glob('diff-*.md')))


if __name__ == '__main__':
    unittest.main()
