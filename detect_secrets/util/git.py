import os
import subprocess
from typing import Dict
from typing import List
from typing import Optional
from typing import Set

from ..core.log import log
from .path import get_relative_path


def get_root_directory(path: str = '') -> str:
    """
    :raises: CalledProcessError
    """
    command = ['git']
    if path:
        command.extend(['-C', path])

    command.extend(['rev-parse', '--show-toplevel'])
    return subprocess.check_output(command).decode('utf-8').strip()


def get_tracked_files(root: str) -> Set[str]:
    """Parsing .gitignore rules is hard.

    However, a way we can get around this problem by just listing all
    currently tracked git files, and start our search from there.
    After all, if it isn't in the git repo, we're not concerned about
    it, because secrets aren't being entered in a shared place.

    :raises: CalledProcessError
    """
    output = set()
    try:
        files = subprocess.check_output(
            ['git', '-C', root, 'ls-files'],
            stderr=subprocess.DEVNULL,
        )

        for filename in files.decode('utf-8').splitlines():
            path = get_relative_path(root, os.path.join(root, filename))
            if path:
                output.add(path)

    except subprocess.CalledProcessError:
        pass
    except FileNotFoundError:   # pragma: no cover
        log.warning('Unable to find `git` in PATH, and therefore, unable to get tracked files.')

    return output


def get_changed_but_unstaged_files() -> Set[str]:
    try:
        files = subprocess.check_output('git diff --name-only'.split()).decode().splitlines()
    except subprocess.CalledProcessError:   # pragma: no cover
        # Since we don't pipe stderr, we get free logging through git.
        raise ValueError

    return set(files)


def get_staged_file_contents(
    root: str = '',
    filenames: Optional[List[str]] = None,
) -> Dict[str, Optional[bytes]]:
    """
    Returns the contents of blobs in the git index, keyed by the repository-relative
    path of each file (using forward slashes, as git itself does).

    A value of ``None`` means that the path is staged for deletion (i.e. it has no
    corresponding blob in the index), and therefore has no content that would be
    committed.

    Reading the index -- rather than the files on disk -- is what makes the pre-commit
    hook examine exactly what is about to be committed, even when the working tree
    contains additional, unstaged changes.

    :param filenames: if provided, only these (repository-relative) paths are
        considered. Paths without an index entry are simply absent from the result.
    :raises: CalledProcessError
    """
    wanted = set(filenames) if filenames is not None else None

    output: Dict[str, Optional[bytes]] = {}

    # NUL terminators let us handle arbitrary paths (including spaces or
    # newlines) without any ambiguity.
    listing = subprocess.check_output(
        ['git'] + (['-C', root] if root else []) + ['ls-files', '-z', '--stage'],
    )

    # Maps a path to its staged blob id. A path that only appears in the
    # unmerged (stage != 0) section is tracked separately as deleted.
    blob_for_path: Dict[str, str] = {}
    unmerged_paths: Set[str] = set()
    for entry in listing.split(b'\0'):
        if not entry:
            continue

        metadata, _, path = entry.partition(b'\t')
        filename = path.decode('utf-8')
        if wanted is not None and filename not in wanted:
            continue

        parts = metadata.split(b' ')
        # Format: <mode> <object> <stage>
        if len(parts) == 3 and parts[2] == b'0':
            blob_for_path[filename] = parts[1].decode('ascii')
        else:
            unmerged_paths.add(filename)

    for filename, blob_id in blob_for_path.items():
        output[filename] = subprocess.check_output(
            ['git'] + (['-C', root] if root else []) + ['cat-file', 'blob', blob_id],
        )

    for filename in unmerged_paths:
        output.setdefault(filename, None)

    # Staged deletions show up as tracked paths with no index entry at all.
    deleted_files = subprocess.check_output(
        ['git'] + (['-C', root] if root else [])
        + ['diff', '--cached', '--name-only', '--diff-filter=D', '-z'],
    )
    for path in deleted_files.split(b'\0'):
        if not path:
            continue

        filename = path.decode('utf-8')
        if wanted is None or filename in wanted:
            output[filename] = None

    return output
