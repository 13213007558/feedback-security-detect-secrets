import io
import os
import re
import tokenize
from functools import lru_cache
from typing import Dict
from typing import Iterable
from typing import List
from typing import Pattern
from typing import Tuple

from ..util.code_snippet import CodeSnippet


def is_line_allowlisted(filename: str, line: str, context: CodeSnippet) -> bool:
    if _is_python_file(filename):
        return _is_python_line_allowlisted(line, context)

    for payload, regexes in zip(
        [line, context.previous_line],
        _get_allowlist_regexes_for_file(filename),
    ):
        for regex in regexes:
            if regex.search(payload):
                return True

    return False


def _is_python_file(filename: str) -> bool:
    return os.path.splitext(filename)[1] in {'.py', '.pyi', '.pyw'}


def _is_python_line_allowlisted(line: str, context: CodeSnippet) -> bool:
    """
    Unlike other file types (which rely on regexes), Python source is tokenized so
    that only *real* comments can allowlist a line. This prevents a string literal
    that merely contains the pragma text (e.g. inside a triple-quoted string) from
    silencing a valid finding.
    """
    previous_line = context.previous_line
    if 'pragma' not in line and 'pragma' not in previous_line:
        return False

    # NOTE: When scanning diffs, the snippet may not include any lines preceding
    # the target line, so we can only work with the lexical context available.
    preceding_lines = list(context.lines[:context.target_index])

    # Inline pragma, on the same line as the secret.
    if 'pragma' in line:
        comments = _extract_python_comments(preceding_lines + [line])
        comment = comments.get(len(preceding_lines) + 1)
        if comment and get_allowlist_regexes(
            comment_tuple=('#', ''),
            nextline=False,
        ).search(comment):
            return True

    # Standalone pragma, on the line before the secret.
    if preceding_lines and 'pragma' in previous_line:
        comments = _extract_python_comments(preceding_lines)
        if (
            # The marker must be a real comment...
            len(preceding_lines) in comments
            # ... and it must be the only thing on that line.
            and get_allowlist_regexes(
                comment_tuple=('#', ''),
                nextline=True,
            ).search(previous_line)
        ):
            return True

    return False


def _extract_python_comments(lines: List[str]) -> Dict[int, str]:
    """
    Tokenizes the given lines of Python source, and returns a mapping of
    1-indexed line numbers (relative to `lines`) to the comment found on that
    line, if any.

    This fails closed: if the source cannot be tokenized (e.g. unterminated
    string, whether from incomplete syntax or missing lexical context earlier
    in the file), only comments confirmed before the error are returned. The
    source is merely parsed, never executed.
    """
    source = ''.join(
        line if line.endswith('\n') else line + '\n'
        for line in lines
    )

    comments = {}
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT:
                comments[token.start[0]] = token.string
    except (tokenize.TokenError, SyntaxError):
        # Tokens yielded before the error are still trustworthy; anything
        # afterwards cannot be confirmed to be a real comment.
        pass

    return comments


@lru_cache(maxsize=1)
def _get_file_to_index_dict() -> Dict[str, int]:
    # Add to this mapping (and ALLOWLIST_REGEXES if applicable) lazily,
    # as more language specific file parsers are implemented.
    # Discussion: https://github.com/Yelp/detect-secrets/pull/105
    return {
        'yaml': 0,
    }


@lru_cache(maxsize=1)
def _get_comment_tuples() -> List[Tuple[str, str]]:
    return [
        ('#', ''),                    # e.g. python or yaml
        ('//', ''),                   # e.g. golang
        (r'/\*', r' *\*/'),           # e.g. c
        ('\'', ''),                   # e.g. visual basic .net
        ('--', ''),                   # e.g. sql
        (r'<!--[# \t]*?', ' *?-->'),  # e.g. xml
        # many other inline comment syntaxes are not included,
        # because we want to be performant for
        # any(regex.search(line) for regex in ALLOWLIST_REGEXES)
        # calls. of course, this won't be a concern if detect-secrets
        # switches over to implementing file plugins for each supported
        # filetype.
    ]


def _get_allowlist_regexes_for_file(filename: str) -> Iterable[List[Pattern]]:
    comment_tuples = _get_comment_tuples()

    _, ext = os.path.splitext(filename)
    if ext[1:] in _get_file_to_index_dict():
        comment_tuples = [comment_tuples[_get_file_to_index_dict()[ext[1:]]]]

    yield [
        get_allowlist_regexes(comment_tuple=t, nextline=False)
        for t in comment_tuples
    ]
    yield [
        get_allowlist_regexes(comment_tuple=t, nextline=True)
        for t in comment_tuples
    ]


# Note: Cache size should be 2x the number of comment types
@lru_cache(maxsize=12)
def get_allowlist_regexes(comment_tuple: Tuple[str, str], nextline: bool) -> Pattern:
    start = comment_tuple[0]
    end = comment_tuple[1]
    return re.compile(
        r'{}[ \t]*{} *pragma: ?{}{}[ -]secret.*?{}[ \t]*$'.format(
            # Note: No text can precede a nextline pragma, this prevents obscuring what is allowed
            # For instance, we want to prevent the following case from working:
            #     foo = 'bar' # pragma: allowlist nextline secret
            #     pass = 'hunter2'
            r'^' if nextline else '',
            start,
            # Note: Always use allowlist, whitelist will be deprecated in the future
            r'allowlist' if nextline else r'(allow|white)list',
            r'[ -]nextline' if nextline else '',
            end,
        ),
    )
