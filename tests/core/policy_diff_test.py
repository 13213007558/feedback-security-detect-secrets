import copy
import json
import re

import pytest

from detect_secrets.__version__ import VERSION
from detect_secrets.core import baseline as baseline_module
from detect_secrets.core import policy_diff


SAMPLE_OLD = 'test_data/policy_diff/old_baseline.json'
SAMPLE_NEW = 'test_data/policy_diff/new_baseline.json'


def load_sample():
    with open(SAMPLE_OLD) as f:
        old = json.load(f)
    with open(SAMPLE_NEW) as f:
        new = json.load(f)
    return old, new


def explanations_by_file(report):
    return {
        finding['filename']: finding['explanation']
        for finding in report['disappeared_findings']
    }


class TestMigrationSample:
    """Validates the report against the checked-in migration sample."""

    def test_old_format_is_upgraded_in_place(self):
        old, new = load_sample()
        report = policy_diff.compare_baselines(old, new)

        assert report['old_version'] == '0.11.0'
        assert report['new_version'] == '1.5.0'
        assert report['normalized_to_version'] == VERSION

    def test_inputs_are_not_mutated(self):
        old, new = load_sample()
        old_copy = copy.deepcopy(old)
        new_copy = copy.deepcopy(new)

        policy_diff.compare_baselines(old, new)

        assert old == old_copy
        assert new == new_copy

    def test_policy_changes_detected_across_formats(self):
        old, new = load_sample()
        changes = policy_diff.compare_baselines(old, new)['policy_changes']

        assert changes['plugins']['disabled'] == ['SlackDetector']
        assert changes['plugins']['config_changed'] == [
            {
                'name': 'HexHighEntropyString',
                'old': {'limit': 3},
                'new': {'limit': 8},
            },
        ]
        assert changes['file_exclusions']['added'] == ['^vendor/']
        assert changes['line_exclusions']['added'] == ['example']
        assert (
            'detect_secrets.filters.regex.should_exclude_line'
            in changes['filters']['added']
        )

    def test_disappeared_findings_are_attributed(self):
        old, new = load_sample()
        report = policy_diff.compare_baselines(old, new)
        explanations = explanations_by_file(report)

        assert explanations['config/settings.py']['reason'] == 'plugin_disabled'
        assert explanations['config/settings.py']['verifiable'] is True

        assert explanations['vendor/lib/deprecated.js']['reason'] == 'file_excluded'
        assert explanations['vendor/lib/deprecated.js']['verifiable'] is True

        assert explanations['src/api.py']['reason'] == 'plugin_config_changed'
        assert explanations['src/api.py']['verifiable'] is False

        assert explanations['README.md']['reason'] == 'filter_changed'
        assert explanations['src/legacy.py']['reason'] == 'filter_changed'

    def test_rescan_recommendation(self):
        old, new = load_sample()
        report = policy_diff.compare_baselines(
            old, new, old_filename=SAMPLE_OLD, new_filename=SAMPLE_NEW,
        )

        assert report['rescan']['required'] is True
        assert report['rescan']['files'] == ['README.md', 'src/api.py', 'src/legacy.py']
        assert SAMPLE_OLD in report['rescan']['command']

        summary = report['summary']
        assert summary['disappeared'] == 5
        assert summary['disappeared_explained_by_policy'] == 2
        assert summary['disappeared_needs_rescan'] == 3
        assert summary['audited_secrets_disappeared'] == 1
        assert summary['new'] == 1
        assert summary['unchanged'] == 1

    def test_report_is_json_serializable_and_contains_no_raw_secrets(self):
        old, new = load_sample()
        report = policy_diff.compare_baselines(old, new)
        serialized = json.dumps(report)

        for finding in report['disappeared_findings'] + report['new_findings']:
            assert re.match(r'^[0-9a-f]{40}$', finding['hashed_secret'])
            assert 'secret' not in finding
        # Only hashes, filenames, line numbers and audit labels are reported.
        assert 'hashed_secret' in serialized

    def test_text_report_mentions_key_sections(self):
        old, new = load_sample()
        report = policy_diff.compare_baselines(old, new)
        text = policy_diff.format_text_report(report)

        assert 'Policy Changes' in text
        assert 'Disappeared Findings' in text
        assert 'Rescan Recommendation' in text
        assert 'NEEDS RESCAN' in text
        assert 'SlackDetector' in text


class TestEdgeCases:
    @staticmethod
    def make_baseline(results):
        return {
            'version': VERSION,
            'plugins_used': [{'name': 'KeywordDetector'}],
            'filters_used': [],
            'results': results,
        }

    def test_identical_baselines_require_no_rescan(self):
        baseline = self.make_baseline({
            'a.py': [
                {
                    'type': 'Secret Keyword',
                    'hashed_secret': 'a' * 40,
                    'line_number': 1,
                    'is_verified': False,
                },
            ],
        })

        report = policy_diff.compare_baselines(baseline, baseline)

        assert report['summary']['disappeared'] == 0
        assert report['summary']['new'] == 0
        assert report['rescan']['required'] is False
        assert report['rescan']['files'] == []

    def test_undetermined_disappearance(self):
        finding = {
            'type': 'Secret Keyword',
            'hashed_secret': 'b' * 40,
            'line_number': 5,
            'is_verified': False,
        }
        old = self.make_baseline({'a.py': [finding]})
        new = self.make_baseline({})

        report = policy_diff.compare_baselines(old, new)

        explanation = report['disappeared_findings'][0]['explanation']
        assert explanation['reason'] == 'undetermined'
        assert explanation['verifiable'] is False
        assert report['rescan']['required'] is True
        assert report['rescan']['files'] == ['a.py']

    def test_old_baseline_against_itself_after_upgrade(self):
        """Old formats must not require manual reformatting before comparison."""
        with open(SAMPLE_OLD) as f:
            old = json.load(f)

        report = policy_diff.compare_baselines(old, old)

        assert report['summary']['disappeared'] == 0
        assert report['rescan']['required'] is False

    def test_plugin_disabled_beats_other_explanations(self):
        old = self.make_baseline({
            'a.py': [
                {
                    'type': 'Secret Keyword',
                    'hashed_secret': 'c' * 40,
                    'line_number': 2,
                    'is_verified': False,
                },
            ],
        })
        new = self.make_baseline({})
        new['plugins_used'] = []
        new['filters_used'] = [
            {
                'path': 'detect_secrets.filters.regex.should_exclude_file',
                'pattern': ['^a.py$'],
            },
        ]

        report = policy_diff.compare_baselines(old, new)
        explanation = report['disappeared_findings'][0]['explanation']

        # Both explanations are verifiable; plugin removal is listed first.
        assert explanation['reason'] == 'plugin_disabled'
        assert explanation['verifiable'] is True


class TestScriptIntegration:
    def test_script_exit_codes(self, tmp_path):
        import subprocess
        import sys

        result = subprocess.run(
            [
                sys.executable,
                'scripts/compare_baselines.py',
                SAMPLE_OLD,
                SAMPLE_NEW,
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert 'Rescan Recommendation' in result.stdout

        result = subprocess.run(
            [
                sys.executable,
                'scripts/compare_baselines.py',
                '--json',
                SAMPLE_NEW,
                SAMPLE_NEW,
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        report = json.loads(result.stdout)
        assert report['rescan']['required'] is False

    def test_script_rejects_unreadable_baseline(self):
        import subprocess
        import sys

        result = subprocess.run(
            [
                sys.executable,
                'scripts/compare_baselines.py',
                SAMPLE_NEW,
                'does-not-exist.json',
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert 'error' in result.stderr.lower()


@pytest.mark.parametrize('filename', [SAMPLE_OLD, SAMPLE_NEW])
def test_sample_baselines_are_loadable_through_standard_path(filename):
    """The migration sample must work with the existing baseline loading."""
    baseline_module.load(baseline_module.load_from_file(filename), filename=filename)
