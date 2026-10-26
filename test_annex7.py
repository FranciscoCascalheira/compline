"""Checks that annex7.py drafts the Annex VII file from relatorio.md without inventing anything.

Run: python3 -m unittest -v
"""
import hashlib, os, re, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPORT = os.path.join(HERE, 'relatorio.md')


class Annex7Draft(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        out = tempfile.NamedTemporaryFile(suffix='.md', delete=False).name
        subprocess.run([sys.executable, 'annex7.py', 'relatorio.md', out],
                       cwd=HERE, check=True, capture_output=True)
        cls.draft = open(out, encoding='utf8').read()
        cls.report = open(REPORT, encoding='utf8').read()
        os.unlink(out)

    def test_all_eight_annex_vii_sections_in_order(self):
        positions = [self.draft.index(f'\n## {n}. ') for n in range(1, 9)]
        self.assertEqual(positions, sorted(positions))

    def test_every_scan_claim_carries_the_report_hash(self):
        sha = hashlib.sha256(self.report.encode('utf8')).hexdigest()[:12]
        tags = re.findall(r'\[evidence: relatorio\.md sha256:([0-9a-f]{12}) @ \w+\]', self.draft)
        self.assertGreaterEqual(len(tags), 9)
        self.assertEqual(set(tags), {sha})

    def test_numbers_come_from_the_report(self):
        components = re.search(r'componentes identificados no SBOM:\s*(\d+)', self.report).group(1)
        vulns = re.search(r'vulnerabilidades reportadas pelo Grype:\s*(\d+)', self.report).group(1)
        self.assertIn(f'**{components} components**', self.draft)
        self.assertIn(f'**{vulns}** reported by Grype', self.draft)

    def test_interview_sections_are_marked_not_invented(self):
        sections = re.split(r'\n## ', self.draft)
        by_number = {sec.split('.', 1)[0]: sec for sec in sections if sec[:1].isdigit()}
        for n in ('1', '4', '5', '7'):
            self.assertIn('PENDING', by_number[n], f'section {n} should wait for the interview')
            self.assertNotIn('[evidence:', by_number[n], f'section {n} must not claim scan evidence')

if __name__ == '__main__':
    unittest.main()
