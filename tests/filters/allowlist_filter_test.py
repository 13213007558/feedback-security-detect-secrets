import pytest

from detect_secrets.core import scan
from detect_secrets.filters.allowlist import is_line_allowlisted
from detect_secrets.settings import transient_settings
from detect_secrets.util.code_snippet import CodeSnippet
from detect_secrets.util.code_snippet import get_code_snippet
from testing.mocks import mock_named_temporary_file


EXAMPLE_COMMENT_PARTS = (
    ('#', ''),
    ('# ', ' more text'),

    ('//', ''),
    ('// ', ' more text'),

    ('/*', '*/'),
    ('/* ', ' */'),

    ('--', ''),
    ('-- ', ' more text'),

    ('<!--', '-->'),
)


@pytest.mark.parametrize(
    'prefix, suffix',
    EXAMPLE_COMMENT_PARTS,
)
def test_basic(prefix, suffix):
    line = f'AKIAEXAMPLE  {prefix}pragma: allowlist secret{suffix}'
    assert is_line_allowlisted(
        'filename',
        line,
        CodeSnippet([line], 0, 0),
    )


@pytest.mark.parametrize(
    'prefix, suffix',
    EXAMPLE_COMMENT_PARTS,
)
def test_nextline(prefix, suffix):
    comment = f'{prefix}pragma: allowlist nextline secret{suffix}'
    line = 'AKIAEXAMPLE'
    assert is_line_allowlisted(
        'filename',
        line,
        CodeSnippet([comment, line], 0, 1),
    )


def test_nextline_exclusivity():
    line = 'AKIAEXAMPLE  # pragma: allowlist nextline secret'
    assert is_line_allowlisted(
        'filename',
        line,
        CodeSnippet([line], 0, 0),
    ) is False


def test_backwards_compatibility():
    line = 'AKIAEXAMPLE  # pragma: whitelist secret'
    assert is_line_allowlisted(
        'filename',
        line,
        CodeSnippet([line], 0, 0),
    )


@pytest.mark.parametrize(
    'line, expected_result',
    (
        ('key: value # pragma: allowlist secret', True),
        ('key: value // pragma: allowlist secret', False),
    ),
)
def test_file_based_regexes(line, expected_result):
    assert is_line_allowlisted(
        'filename.yaml',
        line,
        CodeSnippet([line], 0, 0),
    ) is expected_result


@pytest.mark.parametrize(
    'comment, expected_result',
    (
        ('# pragma: allowlist nextline secret', True),
        ('// pragma: allowlist nextline secret', False),
    ),
)
def test_file_based_nextline_regexes(comment, expected_result):
    line = 'key: value'
    assert is_line_allowlisted(
        'filename.yaml',
        line,
        CodeSnippet([comment, line], 0, 1),
    ) is expected_result


class TestPythonCommentAwareness:
    """
    For Python files, only *real* comments (as determined by tokenizing the
    source) may allowlist a line -- a string literal that merely contains the
    pragma text must not silence a finding.
    """

    @staticmethod
    def check(lines, line_number):
        context = get_code_snippet(
            lines=[line + '\n' for line in lines],
            line_number=line_number,
        )
        return is_line_allowlisted(
            'filename.py',
            lines[line_number - 1],
            context,
        )

    @pytest.mark.parametrize(
        'lines, line_number, expected',
        (
            # A real trailing comment still allowlists the line.
            (["secret = 'hunter2'  # pragma: allowlist secret"], 1, True),

            # The marker is inside a string literal, not a comment.
            ('text = "# pragma: allowlist secret"', 1, False),
            ("text = '# pragma: allowlist secret'", 1, False),

            # The marker is inside a triple-quoted string.
            (
                ['"""', "secret = 'hunter2'  # pragma: allowlist secret", '"""'],
                2,
                False,
            ),

            # The marker only appears inside an adjacent (concatenated) string.
            (["secret = 'hunter2' '# pragma: allowlist secret'"], 1, False),

            # A real comment on a line continued with an escaped newline.
            (['secret = \\', "    'hunter2'  # pragma: allowlist secret"], 2, True),

            # The marker is a string literal on a continued line, not a comment.
            (["secret = 'hunter2' \\", "    '# pragma: allowlist secret'"], 2, False),

            # Implicit string concatenation across lines, with a real comment.
            (
                ['secret = (', "    'hunter'", "    '2'  # pragma: allowlist secret", ')'],
                3,
                True,
            ),

            # Incomplete syntax is fine, as long as the comment is confirmable.
            (['def foo(', "    secret = 'hunter2'  # pragma: allowlist secret"], 2, True),

            # An unterminated string swallows the marker: it cannot be a comment.
            (["secret = 'hunter2  # pragma: allowlist secret"], 1, False),

            # `whitelist` is still supported for backwards compatibility.
            (["secret = 'hunter2'  # pragma: whitelist secret"], 1, True),
        ),
    )
    def test_inline_pragma(self, lines, line_number, expected):
        assert self.check(lines, line_number) is expected

    @pytest.mark.parametrize(
        'lines, line_number, expected',
        (
            # A standalone marker on the previous line still works.
            (['# pragma: allowlist nextline secret', "secret = 'hunter2'"], 2, True),

            # The marker is inside a triple-quoted string, so it is not a comment.
            (
                ['"""', '# pragma: allowlist nextline secret', "secret = 'hunter2'", '"""'],
                3,
                False,
            ),

            # The marker must be the only thing on the previous line.
            (["x = 1  # pragma: allowlist nextline secret", "secret = 'hunter2'"], 2, False),

            # An inline marker never applies to the next line.
            (["secret = 'hunter2'  # pragma: allowlist nextline secret"], 1, False),
        ),
    )
    def test_nextline_pragma(self, lines, line_number, expected):
        assert self.check(lines, line_number) is expected

    def test_missing_lexical_context_fails_closed(self):
        # When the preceding lines cannot be tokenized (e.g. a diff fragment,
        # or an unterminated string opened outside the scanned window), the
        # marker cannot be confirmed to be a real comment, so it is ignored.
        assert self.check(
            [
                "don't stop",
                "secret = 'hunter2'  # pragma: allowlist secret",
            ],
            2,
        ) is False

    def test_diff_without_preceding_context(self):
        # Diff scans may not provide any lines before the target line. A
        # self-contained trailing comment is still verifiable on its own...
        line = "secret = 'hunter2'  # pragma: allowlist secret"
        assert is_line_allowlisted('filename.py', line, CodeSnippet([], 45, 5)) is True

        # ... but a nextline marker cannot apply without a previous line.
        line = "secret = 'hunter2'"
        assert is_line_allowlisted('filename.py', line, CodeSnippet([], 45, 5)) is False

    def test_non_python_files_keep_regex_contract(self):
        # Other languages still use the regex-based contract, even when the
        # marker appears inside what Python would consider a string.
        line = 'var s = "# pragma: allowlist secret"'
        assert is_line_allowlisted(
            'filename.js',
            line,
            CodeSnippet([line], 0, 0),
        ) is True


class TestPythonScanning:
    SECRET = 'c2VjcmV0IG1lc3NhZ2Ugc28geW91J2xsIG5ldmVyIGd1ZXNzIG15IHBhc3N3b3Jk'

    @pytest.fixture(autouse=True)
    def configure_plugins(self):
        with transient_settings({
            'plugins_used': [
                {
                    'name': 'Base64HighEntropyString',
                    'limit': 4.5,
                },
            ],
        }):
            yield

    def test_scan_file(self):
        lines = [
            # Legitimate inline pragma: suppressed.
            f"key1 = '{self.SECRET}'  # pragma: allowlist secret",
            # No pragma: flagged.
            f"key2 = '{self.SECRET}'",
            # Fake marker, inside a triple-quoted string: flagged.
            '"""',
            f"key3 = '{self.SECRET}'  # pragma: allowlist secret",
            '"""',
            # Fake marker, inside an adjacent concatenated string: flagged.
            f"key4 = '{self.SECRET}' '# pragma: allowlist secret'",
            # Legitimate standalone nextline pragma: suppresses key5.
            '# pragma: allowlist nextline secret',
            f"key5 = '{self.SECRET}'",
            # Fake nextline marker, inside a triple-quoted string: key6 flagged.
            '"""',
            '# pragma: allowlist nextline secret',
            f"key6 = '{self.SECRET}'",
            '"""',
        ]
        with mock_named_temporary_file(suffix='.py') as f:
            f.write(('\n'.join(lines) + '\n').encode())
            f.seek(0)

            secrets = list(scan.scan_file(f.name))

        assert sorted(secret.line_number for secret in secrets) == [2, 4, 6, 11]

    def test_scan_diff(self):
        pytest.importorskip('unidiff')

        # The fake marker only appears inside an added triple-quoted string,
        # so the added secret is still flagged.
        diff = (
            'diff --git a/new_file.py b/new_file.py\n'
            'new file mode 100644\n'
            'index 0000000..6178079\n'
            '--- /dev/null\n'
            '+++ b/new_file.py\n'
            '@@ -0,0 +1,3 @@\n'
            '+"""\n'
            f"+key = '{self.SECRET}'  # pragma: allowlist secret\n"
            '+"""\n'
        )
        secrets = list(scan.scan_diff(diff))

        assert len(secrets) == 1
        assert secrets[0].line_number == 2

    def test_diff_lines_without_full_context(self):
        # `scan_diff` only provides added lines (with their new line numbers);
        # this exercises the same code path without requiring unidiff.
        lines = [
            (1, '"""\n'),
            (2, f"key = '{self.SECRET}'  # pragma: allowlist secret\n"),
            (3, '"""\n'),
        ]
        secrets = list(scan._process_line_based_plugins(lines, filename='new_file.py'))
        assert [secret.line_number for secret in secrets] == [2]

    def test_diff_lines_self_contained_inline_pragma(self):
        # Lines added deep into an existing file come with no preceding
        # context; a self-contained trailing comment is still honored.
        lines = [(50, f"key = '{self.SECRET}'  # pragma: allowlist secret\n")]
        assert not list(scan._process_line_based_plugins(lines, filename='existing_file.py'))

    def test_diff_lines_unverifiable_context_fails_closed(self):
        # When the added fragment cannot be tokenized, the marker cannot be
        # confirmed to be a real comment, so the secret is still flagged.
        lines = [
            (1, "don't stop\n"),
            (2, f"key = '{self.SECRET}'  # pragma: allowlist secret\n"),
        ]
        secrets = list(scan._process_line_based_plugins(lines, filename='new_file.py'))
        assert [secret.line_number for secret in secrets] == [2]
