import argparse
import json
import os
import subprocess
import sys
import textwrap
from typing import List
from typing import Optional
from typing import Tuple

from detect_secrets.__version__ import VERSION
from detect_secrets.core import baseline
from detect_secrets.core.log import log
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.core.usage import ParserBuilder
from detect_secrets.settings import get_settings
from detect_secrets.types import NamedIO
from detect_secrets.types import NamedStringIO
from detect_secrets.util import color
from detect_secrets.util import git
from detect_secrets.util.path import convert_local_os_path


def main(argv: Optional[List[str]] = None) -> int:
    try:
        args = parse_args(argv)
    except ValueError:
        return 1

    if args.verbose:    # pragma: no cover
        log.set_debug_level(args.verbose)

    # The hook supplies file contents itself (either from the git index, or through
    # explicitly opened file handles), so the on-disk existence check is both
    # redundant and wrong: e.g. a staged file whose worktree copy was deleted would
    # otherwise be silently skipped, even though its contents are being committed.
    get_settings().disable_filters('detect_secrets.filters.common.is_invalid_file')

    # Find all secrets in files to be committed. We scan the contents of the git index
    # (rather than whatever happens to be on disk), so that partially-staged files,
    # renames, deletions and worktree-only edits can never cause us to judge a different
    # snapshot than the one that is actually being committed.
    secrets = SecretsCollection()
    for filename, fileobj in _get_contents_to_commit(args.filenames):
        secrets.scan_file(filename, fileobj)

    new_secrets = secrets
    if args.baseline:
        new_secrets = secrets - args.baseline

    if new_secrets:
        if args.json:
            print(json.dumps(baseline.format_for_output(new_secrets), indent=2))
        else:
            pretty_print_diagnostics(new_secrets)
        return 1

    if not args.baseline:
        return 0

    # Only attempt baseline modifications if we don't find any new secrets.
    is_modified = should_update_baseline(
        args.baseline,
        scanned_results=secrets,
        filelist=args.filenames,
        baseline_version=args.baseline_version,
    )

    if is_modified:
        if args.baseline_version != VERSION:
            with open(args.baseline_filename) as f:
                old_baseline = json.loads(f.read())

            # Override the results, because this has been updated in `should_update_baseline`.
            old_baseline['results'] = args.baseline.json()

            args.baseline = baseline.upgrade(old_baseline)

        baseline.save_to_file(args.baseline, filename=args.baseline_filename)
        print(
            'The baseline file was updated.\n'
            'Probably to keep line numbers of secrets up-to-date.\n'
            'Please `git add {}`, thank you.\n\n'.format(args.baseline_filename),
        )
        return 3

    return 0


def _get_contents_to_commit(
    filenames: List[str],
) -> List[Tuple[str, Optional[NamedIO]]]:
    """
    Pairs each file that the hook was asked to check with a readable handle over the
    exact content that would be committed for it.

    Returns a list of ``(filename, fileobj)`` tuples, where ``fileobj`` is:

    * a readable in-memory stream of the blob stored in the git index, when the file
      has a staged version (this is what makes partial staging safe);
    * ``None`` when the path is staged for deletion, since there is no content to
      commit and therefore nothing to scan;
    * a real on-disk file handle as a fallback, when we are not inside a git
      repository or the path has no index entry (e.g. an untracked file passed in
      adhoc), preserving the hook's previous behavior.

    The returned ``filename`` is always the original, repository-relative path, so
    filename-based filters and allowlist comments are evaluated against the same
    snapshot as the detectors.
    """
    try:
        root = git.get_root_directory()
        keys = {
            filename: _to_git_path(root, filename)
            for filename in filenames
        }
        staged = git.get_staged_file_contents(root, list(keys.values()))
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Not inside a git repository (or git is unavailable): fall back to disk.
        staged = None
        keys = {}

    output = []
    for filename in filenames:
        if staged is not None and keys.get(filename) in staged:
            contents = staged[keys[filename]]
            if contents is None:
                # Staged deletion: nothing is being committed for this path.
                continue
            try:
                text = contents.decode('utf-8')
            except UnicodeDecodeError:
                # Match the on-disk behavior: binary files are ignored entirely.
                continue
            output.append((filename, NamedStringIO(text, name=filename)))
            continue

        # No index entry: keep the historical behavior of scanning the file on disk.
        try:
            output.append((filename, open(filename)))
        except IOError:
            log.warning(f'Unable to open file: {filename}')

    return output


def _to_git_path(root: str, filename: str) -> str:
    """Converts a hook-provided path into git's repository-relative form."""
    path = os.path.realpath(filename)
    root = os.path.realpath(root)
    if path == root:
        return ''

    prefix = root.rstrip(os.sep) + os.sep
    if path.startswith(prefix):
        path = path[len(prefix):]

    return convert_local_os_path(path)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """
    :raises: ValueError
    """
    output = ParserBuilder().add_pre_commit_arguments().parse_args(argv)
    if output.baseline:
        raise_exception_if_baseline_file_is_unstaged(output.baseline_filename)

    return output


def raise_exception_if_baseline_file_is_unstaged(filename: str) -> None:
    """
    We want to make sure that if there are changes to the baseline
    file, they will be included in the commit. This way, we can keep
    our baselines up-to-date.

    :raises: ValueError
    """
    if filename in git.get_changed_but_unstaged_files():
        print(
            f'Your baseline file ({filename}) is unstaged.\n'
            f'`git add {filename}` to fix this.',
        )
        raise ValueError


def should_update_baseline(
    secrets: SecretsCollection,
    scanned_results: SecretsCollection,
    filelist: List[str],
    baseline_version: str,
) -> bool:
    """
    :returns: True if changes occurred.
    """
    original = SecretsCollection.load_from_baseline({'results': secrets.json()})

    secrets.trim(scanned_results=scanned_results, filelist=filelist)

    if baseline_version != VERSION:
        return True

    if not secrets.exactly_equals(original):
        return True

    return False


def pretty_print_diagnostics(secrets: SecretsCollection, width: int = 80) -> None:
    # Header
    print(
        textwrap.fill(
            color.colorize(
                'ERROR: Potential secrets about to be committed to git repo!',
                color.AnsiColor.RED,
            ),
            width=width,
        ),
    )
    print()

    # Display found secrets
    for _, secret in secrets:
        print(secret)

    # Display the number of detected secrets
    print(f'\nTotal secrets detected: {len(secrets)}')

    # Display mitigation suggestions
    print('Possible mitigations:')
    wrapper = textwrap.TextWrapper(
        initial_indent='  - ',
        subsequent_indent='    ',
        width=width,
    )
    for suggestion in [
        'For information about putting your secrets in a safer place, '
        'please ask {0}'.format(os.environ.get('DETECT_SECRETS_SECURITY_TEAM', 'in #security')),

        'Mark false positives with an inline '
        '`{0}` comment'.format(color.colorize('pragma: allowlist secret', color.AnsiColor.BOLD)),
    ]:
        print(wrapper.fill(suggestion))

    print()
    print(
        textwrap.fill(
            'If a secret has already been committed, visit '
            'https://help.github.com/articles/removing-sensitive-data-from-a-repository',
            width=width,
        ),
    )


if __name__ == '__main__':
    sys.exit(main())
