from pathlib import Path
from unittest import mock

import pytest

from detect_secrets.core.secrets_collection import INHERITED_EXACT_IDENTITY
from detect_secrets.core.secrets_collection import REAUDIT_DETECTOR_CHANGED
from detect_secrets.core.secrets_collection import REAUDIT_FILE_CHANGED
from detect_secrets.core.secrets_collection import REAUDIT_NEW_FINDING
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.settings import get_settings
from detect_secrets.settings import transient_settings
from testing.factories import potential_secret_factory


@pytest.fixture(autouse=True)
def configure_plugins():
    config = {
        'plugins_used': [
            {'name': 'AWSKeyDetector'},
            {
                'name': 'Base64HighEntropyString',
                'limit': 4.5,
            },
        ],
    }
    with transient_settings(config):
        yield config


class TestScanFile:
    @staticmethod
    def test_filename_filters_are_invoked_first(mock_log):
        # This is a directory, which should be ignored via
        # detect_secrets.filters.common.is_invalid_file
        SecretsCollection().scan_file('test_data')

        assert (
            'Skipping "test_data" due to `detect_secrets.filters.common.is_invalid_file`'
            in mock_log.info_messages
        )

    @staticmethod
    def test_error_reading_file(mock_log_warning):
        with mock.patch(
            'detect_secrets.core.scan.open',
            side_effect=IOError,
        ):
            SecretsCollection().scan_file('test_data/config.env')

        file_warning = str(Path('test_data/config.env'))
        assert 'Unable to open file: %s' % file_warning in mock_log_warning.warning_messages

    @staticmethod
    def test_line_based_success():
        # Explicitly configure filters, so that additions to filters won't affect this test.
        get_settings().configure_filters([
            # This will remove the `id` string
            {'path': 'detect_secrets.filters.heuristic.is_likely_id_string'},

            # This gets rid of the aws keys with `EXAMPLE` in them.
            {
                'path': 'detect_secrets.filters.regex.should_exclude_line',
                'pattern': [
                    'EXAMPLE',
                ],
            },
        ])

        secrets = SecretsCollection()
        secrets.scan_file('test_data/each_secret.py')

        secret = next(iter(secrets[str(Path('test_data/each_secret.py'))]))
        assert secret.secret_value.startswith('c2VjcmV0IG1lc')
        assert len(secrets[str(Path('test_data/each_secret.py'))]) == 1

    @staticmethod
    def test_file_based_success_config():
        get_settings().configure_plugins([
            {
                'name': 'Base64HighEntropyString',
                'limit': 3.0,
            },
        ])
        secrets = SecretsCollection()
        secrets.scan_file('test_data/config.ini')

        assert [str(secret).splitlines()[1] for _, secret in secrets] == [
            'Location:    %s:2' % str(Path('test_data/config.ini')),
            'Location:    %s:10' % str(Path('test_data/config.ini')),
            'Location:    %s:21' % str(Path('test_data/config.ini')),
            'Location:    %s:22' % str(Path('test_data/config.ini')),
            'Location:    %s:32' % str(Path('test_data/config.ini')),
        ]

    @staticmethod
    def test_file_based_success_yaml():
        get_settings().configure_plugins([
            {
                'name': 'HexHighEntropyString',
                'limit': 3.0,
            },
        ])
        secrets = SecretsCollection()
        secrets.scan_file('test_data/config.yaml')

        assert [str(secret).splitlines()[1] for _, secret in secrets] == [
            'Location:    %s:3' % str(Path('test_data/config.yaml')),
            'Location:    %s:5' % str(Path('test_data/config.yaml')),
            'Location:    %s:13' % str(Path('test_data/config.yaml')),
        ]

    @staticmethod
    def test_file_based_yaml_only_comments():
        secrets = SecretsCollection()
        secrets.scan_file('test_data/only_comments.yaml')

        assert not secrets

    @staticmethod
    @pytest.mark.parametrize(
        'filename',
        (
            'test_data/config.env',

            # Markdown files with colons and unicode characters preceding the colon on the line
            # would have caused the scanner to fail and exit on python2.7.
            # This test case ensures scanning can complete and still find high entropy strings.
            'test_data/config.md',
        ),
    )
    def test_file_based_success_unexpected_config_file(filename):
        secrets = SecretsCollection()
        secrets.scan_file(filename)

        assert bool(secrets)


class TestScanDiff:
    @staticmethod
    def test_filename_filters_are_invoked_first():
        get_settings().configure_filters([
            {
                'path': 'detect_secrets.filters.regex.should_exclude_file',
                'pattern': [
                    'test|baseline',
                ],
            },
        ])

        secrets = SecretsCollection()
        with open('test_data/sample.diff') as f:
            secrets.scan_diff(f.read())

        assert len(secrets.files) == 0

    @staticmethod
    def test_success():
        with transient_settings({
            'plugins_used': [
                {
                    'name': 'HexHighEntropyString',
                    'limit': 3,
                },
            ],
            'filters_used': [],
        }):
            secrets = SecretsCollection()
            with open('test_data/sample.diff') as f:
                secrets.scan_diff(f.read())

        assert secrets.files == {
            'detect_secrets/core/baseline.py',
            'tests/core/secrets_collection_test.py',
            '.secrets.baseline',
        }


def test_merge():
    old_secrets = SecretsCollection()
    old_secrets.scan_file('test_data/each_secret.py')
    assert len(list(old_secrets)) >= 4      # otherwise, this test won't work.

    index = 0
    for _, secret in old_secrets:
        if index == 0:
            secret.is_secret = False
        elif index == 1:
            secret.is_secret = True
        elif index == 2:
            secret.is_verified = True

        index += 1

    new_secrets = SecretsCollection()
    new_secrets.scan_file('test_data/each_secret.py')
    list(new_secrets)[-2][1].is_secret = True

    new_secrets.merge(old_secrets)

    index = 0
    for _, secret in new_secrets:
        if index == 0:
            assert secret.is_secret is False
            assert secret.is_verified is False
        elif index == 1:
            assert secret.is_secret is True
            assert secret.is_verified is False
        elif index == 2:
            assert secret.is_secret is True
            assert secret.is_verified is True
        elif index == 3:
            assert secret.is_secret is None
            assert secret.is_verified is False

        index += 1


class TestMergeInheritance:
    @staticmethod
    def _merge(new_secrets, old_secrets):
        inheritance_log = []
        new_secrets.merge(old_secrets, inheritance_log=inheritance_log)
        return {
            (record.filename, record.secret_hash, record.secret_type): record
            for record in inheritance_log
        }

    def test_line_number_move_keeps_audit_conclusion(self):
        old_secret = potential_secret_factory(
            type='type', filename='file', secret='value', line_number=1, is_secret=False,
        )
        new_secret = potential_secret_factory(
            type='type', filename='file', secret='value', line_number=42,
        )
        old_secrets = SecretsCollection.load_from_baseline(
            {'results': {'file': [old_secret.json()]}},
        )
        new_secrets = SecretsCollection.load_from_baseline(
            {'results': {'file': [new_secret.json()]}},
        )

        log = self._merge(new_secrets, old_secrets)
        merged = next(iter(new_secrets['file']))

        assert merged.is_secret is False
        record = log[('file', merged.secret_hash, 'type')]
        assert record.reason == INHERITED_EXACT_IDENTITY
        assert record.previous_location == ('file', 1)

    def test_repeated_occurrence_in_same_file_is_same_finding(self):
        # Sets dedupe identical (filename, hash, type) entries: a secret appearing
        # twice in one file is one finding, and its verdict stays attached to it.
        old_secret = potential_secret_factory(
            type='type', filename='file', secret='value', line_number=1, is_secret=False,
        )
        moved_copy = potential_secret_factory(
            type='type', filename='file', secret='value', line_number=8,
        )
        old_secrets = SecretsCollection.load_from_baseline(
            {'results': {'file': [old_secret.json()]}},
        )
        new_secrets = SecretsCollection.load_from_baseline(
            {'results': {'file': [moved_copy.json()]}},
        )

        log = self._merge(new_secrets, old_secrets)
        assert len(new_secrets['file']) == 1
        merged = next(iter(new_secrets['file']))
        assert merged.is_secret is False
        assert log[('file', merged.secret_hash, 'type')].reason == INHERITED_EXACT_IDENTITY

    def test_renamed_file_requires_re_audit(self):
        old_secret = potential_secret_factory(
            type='type', filename='old_file', secret='value', line_number=1, is_secret=False,
        )
        new_secret = potential_secret_factory(
            type='type', filename='renamed_file', secret='value', line_number=1,
        )
        old_secrets = SecretsCollection.load_from_baseline(
            {'results': {'old_file': [old_secret.json()]}},
        )
        new_secrets = SecretsCollection.load_from_baseline(
            {'results': {'renamed_file': [new_secret.json()]}},
        )

        log = self._merge(new_secrets, old_secrets)
        merged = next(iter(new_secrets['renamed_file']))

        assert merged.is_secret is None
        record = log[('renamed_file', merged.secret_hash, 'type')]
        assert record.reason == REAUDIT_FILE_CHANGED
        assert record.previous_location is None

    def test_copied_fake_secret_in_new_file_does_not_inherit_verdict(self):
        # The false-positive label lives on one location; pasting the same fake
        # secret into another file must not silently label the new copy.
        old_secret = potential_secret_factory(
            type='type', filename='original', secret='value', line_number=1, is_secret=False,
        )
        new_secrets = SecretsCollection.load_from_baseline({'results': {
            'original': [potential_secret_factory(
                type='type', filename='original', secret='value', line_number=1,
            ).json()],
            'copy': [potential_secret_factory(
                type='type', filename='copy', secret='value', line_number=3,
            ).json()],
        }})
        old_secrets = SecretsCollection.load_from_baseline(
            {'results': {'original': [old_secret.json()]}},
        )

        log = self._merge(new_secrets, old_secrets)

        original = next(iter(new_secrets['original']))
        copied = next(iter(new_secrets['copy']))
        assert original.is_secret is False
        assert copied.is_secret is None
        assert log[('copy', copied.secret_hash, 'type')].reason == REAUDIT_FILE_CHANGED
        assert log[('original', original.secret_hash, 'type')].reason == INHERITED_EXACT_IDENTITY

    def test_detector_type_change_requires_re_audit(self):
        old_secret = potential_secret_factory(
            type='old_type', filename='file', secret='value', line_number=1, is_secret=False,
        )
        new_secret = potential_secret_factory(
            type='new_type', filename='file', secret='value', line_number=1,
        )
        old_secrets = SecretsCollection.load_from_baseline(
            {'results': {'file': [old_secret.json()]}},
        )
        new_secrets = SecretsCollection.load_from_baseline(
            {'results': {'file': [new_secret.json()]}},
        )

        log = self._merge(new_secrets, old_secrets)
        merged = next(iter(new_secrets['file']))

        assert merged.is_secret is None
        assert log[('file', merged.secret_hash, 'new_type')].reason == REAUDIT_DETECTOR_CHANGED

    def test_new_finding_is_kept_and_queued_for_audit(self):
        new_secret = potential_secret_factory(
            type='type', filename='file', secret='brand-new', line_number=2,
        )
        old_secrets = SecretsCollection.load_from_baseline({'results': {
            'file': [potential_secret_factory(
                type='type', filename='file', secret='value', line_number=1, is_secret=False,
            ).json()],
        }})
        new_secrets = SecretsCollection.load_from_baseline(
            {'results': {'file': [new_secret.json()]}},
        )

        log = self._merge(new_secrets, old_secrets)
        merged = next(iter(new_secrets['file']))

        # The new finding is neither dropped nor auto-labelled.
        assert merged.secret_hash == new_secret.secret_hash
        assert merged.is_secret is None
        assert log[('file', merged.secret_hash, 'type')].reason == REAUDIT_NEW_FINDING

    def test_existing_newer_label_is_not_overwritten(self):
        old_secret = potential_secret_factory(
            type='type', filename='file', secret='value', line_number=1, is_secret=False,
        )
        new_secret = potential_secret_factory(
            type='type', filename='file', secret='value', line_number=2, is_secret=True,
        )
        old_secrets = SecretsCollection.load_from_baseline(
            {'results': {'file': [old_secret.json()]}},
        )
        new_secrets = SecretsCollection.load_from_baseline(
            {'results': {'file': [new_secret.json()]}},
        )

        self._merge(new_secrets, old_secrets)
        assert next(iter(new_secrets['file'])).is_secret is True


class TestTrim:
    @staticmethod
    def test_deleted_secret():
        secrets = SecretsCollection()
        secrets.scan_file('test_data/each_secret.py')

        results = SecretsCollection.load_from_baseline({'results': secrets.json()})
        results.data[str(Path('test_data/each_secret.py'))].pop()

        original_size = len(secrets[str(Path('test_data/each_secret.py'))])
        secrets.trim(results)

        assert len(secrets[str(Path('test_data/each_secret.py'))]) < original_size

    @staticmethod
    def test_deleted_secret_file():
        secrets = SecretsCollection()
        secrets.scan_file('test_data/each_secret.py')

        secrets.trim(SecretsCollection())
        assert secrets

        secrets.trim(SecretsCollection(), filelist=[str(Path('test_data/each_secret.py'))])
        assert not secrets

    @staticmethod
    def test_same_secret_new_location():
        old_secret = potential_secret_factory()
        new_secret = potential_secret_factory(line_number=2)

        secrets = SecretsCollection.load_from_baseline({'results': {'blah': [old_secret.json()]}})
        results = SecretsCollection.load_from_baseline({'results': {'blah': [new_secret.json()]}})

        secrets.trim(results)

        count = 0
        for filename, secret in secrets:
            assert secret.line_number == 2
            count += 1

        assert count == 1

    @staticmethod
    @pytest.mark.parametrize(
        'base_state, scanned_results',
        (
            (
                {
                    'blah': [potential_secret_factory().json()],
                },
                {},
            ),

            # Exact same secret, so no modifications necessary
            (
                {
                    'blah': [potential_secret_factory().json()],
                },
                {
                    'blah': [potential_secret_factory().json()],
                },
            ),
        ),
    )
    def test_no_modifications(base_state, scanned_results):
        secrets = SecretsCollection.load_from_baseline({'results': base_state})
        results = SecretsCollection.load_from_baseline({'results': scanned_results})

        secrets.trim(results)

        assert secrets.json() == base_state

    @staticmethod
    def test_remove_non_existent_files():
        secrets = SecretsCollection()
        secrets.scan_file('test_data/each_secret.py')
        assert bool(secrets)

        secrets.data['does-not-exist'] = secrets.data.pop(str(Path('test_data/each_secret.py')))
        secrets.trim()

        assert not bool(secrets)

    @staticmethod
    def test_maintains_labels():
        labelled_secrets = SecretsCollection()
        labelled_secrets.scan_file('test_data/each_secret.py')
        for _, secret in labelled_secrets:
            secret.is_secret = True
            break

        secrets = SecretsCollection()
        secrets.scan_file('test_data/each_secret.py')

        labelled_secrets.trim(scanned_results=secrets)

        assert any([secret.is_secret for _, secret in labelled_secrets])


def test_bool():
    secrets = SecretsCollection()
    assert not secrets

    secrets.scan_file('test_data/each_secret.py')
    assert secrets

    secrets[str(Path('test_data/each_secret.py'))].clear()
    assert not secrets


class TestEqual:
    @staticmethod
    def test_mismatch_files():
        secretsA = SecretsCollection()
        secretsA.scan_file('test_data/each_secret.py')

        secretsB = SecretsCollection()
        secretsB.scan_file('test_data/files/file_with_secrets.py')

        assert secretsA != secretsB

    @staticmethod
    def test_strict_equality():
        secret = potential_secret_factory()
        secretsA = SecretsCollection()
        secretsA[secret.filename].add(secret)

        secret = potential_secret_factory(line_number=2)
        secretsB = SecretsCollection()
        secretsB[secret.filename].add(secret)

        assert secretsA == secretsB
        assert not secretsA.exactly_equals(secretsB)


class TestSubtraction:
    @staticmethod
    def test_basic(configure_plugins):
        with transient_settings({**configure_plugins, 'filters_used': []}):
            secrets = SecretsCollection()
            secrets.scan_file('test_data/each_secret.py')

        # This baseline will have less secrets, since it filtered out some.
        with transient_settings({
            **configure_plugins,
            'filters_used': [
                {
                    'path': 'detect_secrets.filters.regex.should_exclude_line',
                    'pattern': [
                        'EXAMPLE',
                    ],
                },
            ],
        }):
            baseline = SecretsCollection()
            baseline.scan_file('test_data/each_secret.py')

        # This tests the != operator for same file, different number of secrets.
        # It's hidden in a different test, but I didn't want to set up the boilerplate
        # again.
        assert secrets != baseline

        result = secrets - baseline
        assert len(result[str(Path('test_data/each_secret.py'))]) == 3
        assert len(secrets[str(Path('test_data/each_secret.py'))]) == 5

    @staticmethod
    def test_no_overlapping_files(configure_plugins):
        secrets_a = SecretsCollection()
        secrets_b = SecretsCollection()
        with transient_settings({**configure_plugins, 'filters_used': []}):
            secrets_a.scan_file('test_data/each_secret.py')
            secrets_b.scan_file('test_data/config.env')

        assert (secrets_a - secrets_b).files == {str(Path('test_data/each_secret.py'))}
        assert (secrets_b - secrets_a).files == {str(Path('test_data/config.env'))}
