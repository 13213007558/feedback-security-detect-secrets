import multiprocessing as mp
import os
from collections import defaultdict
from typing import Any
from typing import Dict
from typing import Generator
from typing import List
from typing import NamedTuple
from typing import Optional
from typing import Set
from typing import Tuple

from . import scan
from ..util.path import convert_local_os_path
from .potential_secret import PotentialSecret
from detect_secrets.settings import configure_settings_from_baseline
from detect_secrets.settings import get_settings


# Inheritance outcomes, explaining why a finding in the new scan keeps (or loses)
# the audit conclusion recorded for it in the old baseline.
INHERITED_EXACT_IDENTITY = 'inherited:exact-identity'
REAUDIT_DETECTOR_CHANGED = 're-audit:detector-type-changed'
REAUDIT_FILE_CHANGED = 're-audit:filename-changed'
REAUDIT_NEW_FINDING = 're-audit:new-finding'


class InheritanceRecord(NamedTuple):
    """
    Describes what happened to a single finding in the new scan while inheriting
    audit conclusions from the old baseline.

    Only fingerprints (``secret_hash``) and locations are recorded; the candidate
    secret value itself is intentionally never part of this record.
    """
    reason: str
    filename: str
    line_number: int
    secret_hash: str
    secret_type: str
    is_secret: Optional[bool]
    previous_location: Optional[Tuple[str, int]] = None


class PatchedFile:
    """This exists so that we can do typecasting, without importing unidiff."""
    path: str

    def __iter__(self) -> Generator:
        pass


class SecretsCollection:
    def __init__(self, root: str = '') -> None:
        """
        :param root: if specified, will scan as if the root was the value provided,
            rather than the current working directory. We still store results as if
            relative to root, since we're running as if it was in a different directory,
            rather than scanning a different directory.
        """
        self.data: Dict[str, Set[PotentialSecret]] = defaultdict(set)
        self.root = root

    @classmethod
    def load_from_baseline(cls, baseline: Dict[str, Any]) -> 'SecretsCollection':
        output = cls()
        for filename in baseline['results']:
            for item in baseline['results'][filename]:
                secret = PotentialSecret.load_secret_from_dict({'filename': filename, **item})
                output[convert_local_os_path(filename)].add(secret)

        return output

    @property
    def files(self) -> Set[str]:
        return set(self.data.keys())

    def scan_files(self, *filenames: str, num_processors: Optional[int] = None) -> None:
        """Just like scan_file, but optimized through parallel processing."""
        if len(filenames) == 1:
            self.scan_file(filenames[0])
            return

        if not num_processors:
            num_processors = mp.cpu_count()

        child_process_settings = get_settings().json()

        with mp.Pool(
            processes=num_processors,
            initializer=configure_settings_from_baseline,
            initargs=(child_process_settings,),
        ) as p:
            for secrets in p.imap_unordered(
                _scan_file_and_serialize,
                [os.path.join(self.root, filename) for filename in filenames],
            ):
                for secret in secrets:
                    self[os.path.relpath(secret.filename, self.root)].add(secret)

    def scan_file(self, filename: str) -> None:
        for secret in scan.scan_file(os.path.join(self.root, convert_local_os_path(filename))):
            self[convert_local_os_path(filename)].add(secret)

    def scan_diff(self, diff: str) -> None:
        """
        :raises: UnidiffParseError
        """
        try:
            for secret in scan.scan_diff(diff):
                self[secret.filename].add(secret)
        except ImportError:     # pragma: no cover
            raise NotImplementedError(
                'SecretsCollection.scan_diff requires `unidiff` to work. Try pip '
                'installing that package, and try again.',
            )

    def merge(
        self,
        old_results: 'SecretsCollection',
        inheritance_log: Optional[List[InheritanceRecord]] = None,
    ) -> None:
        """
        We operate under an assumption that the latest results are always more accurate,
        assuming that the baseline is created on the same repository. However, we cannot
        merely discard the old results in favor of the new, since there is valuable information
        that ought to be preserved: verification of secrets, both automated and manual.

        Therefore, this function serves to extract this information from the old results,
        and amend the new results with it.

        A finding's identity is the tuple ``(filename, hashed_secret, type)``: line numbers
        are deliberately excluded, since a secret is expected to move within its file. The
        only identity change for which an audit conclusion is automatically kept is a line
        number shift inside the same file. Any other change (file rename, a copy of the same
        fake secret into another file, or a different detector type) describes a *different*
        finding, and must be audited again -- a false-positive verdict for one location must
        never be applied to every other location that happens to contain the same string.

        New findings are never removed or suppressed to preserve a label: they simply stay
        unaudited and show up in the triage queue.

        :param inheritance_log: if supplied, one :class:`InheritanceRecord` per new finding
            is appended to it, making the provenance (or re-audit reason) of every label
            explicit. Candidate secret values are never written to this log.
        """
        old_index = _build_old_secret_index(old_results)

        for filename in sorted(self.files):
            for new_secret in sorted(
                self.data[filename],
                key=lambda secret: (secret.line_number, secret.secret_hash, secret.type),
            ):
                # NOTE: we deliberately match on the collection's filename key (the one
                # serialized into the baseline), not on `new_secret.filename`, which may
                # still hold the path that was used to locate the file on disk.
                reason, old_secret = _classify_inheritance(filename, new_secret, old_index)
                if reason == INHERITED_EXACT_IDENTITY and old_secret is not None:
                    # Only override if there's no newer value.
                    if new_secret.is_secret is None:
                        new_secret.is_secret = old_secret.is_secret

                    # If the old value is false, it won't make a difference.
                    if not new_secret.is_verified:
                        new_secret.is_verified = old_secret.is_verified

                if inheritance_log is not None:
                    inheritance_log.append(
                        InheritanceRecord(
                            reason=reason,
                            filename=filename,
                            line_number=new_secret.line_number,
                            secret_hash=new_secret.secret_hash,
                            secret_type=new_secret.type,
                            is_secret=new_secret.is_secret,
                            previous_location=(
                                (filename, old_secret.line_number)
                                if reason == INHERITED_EXACT_IDENTITY and old_secret
                                else None
                            ),
                        ),
                    )

    def trim(
        self,
        scanned_results: Optional['SecretsCollection'] = None,
        filelist: Optional[List[str]] = None,
    ) -> None:
        """
        Removes invalid entries in the current SecretsCollection.

        This behaves *kinda* like set intersection and left-join. That is, for matching files,
        a set intersection is performed. For non-matching files, only the files in `self` will
        be kept.

        This is because we may not be constructing the other SecretsCollection with the same
        information as we are with the current SecretsCollection, and we cannot infer based on
        incomplete information. As such, we will keep the status quo.

        Assumptions:
            1. Both `scanned_results` and the current SecretsCollection are constructed using
               the same settings (otherwise, we can't determine whether a missing secret is due
               to newly filtered secrets, or actually removed).

        :param scanned_results: if None, will just clear out non-existent files.
        :param filelist: files without secrets are not present in `scanned_results`. Therefore,
            by supplying this additional filelist, we can assert that if an entry is missing in
            `scanned_results`, it must not have secrets in it.
        """
        if scanned_results is None:
            scanned_results = SecretsCollection()
            filelist = [
                filename
                for filename in self.files
                if not os.path.exists(filename)
            ]

        if not filelist:
            fileset = set()
        else:
            fileset = set(filelist)

        # Unfortunately, we can't merely do a set intersection since we want to update the line
        # numbers (if applicable). Therefore, this does it manually.
        result: Dict[str, Set[PotentialSecret]] = defaultdict(set)

        for filename in scanned_results.files:
            if filename not in self.files:
                continue

            # We construct this so we can get O(1) retrieval of secrets.
            existing_secret_map = {secret: secret for secret in self[filename]}
            for secret in scanned_results[filename]:
                if secret not in existing_secret_map:
                    continue

                # Currently, we assume that the `scanned_results` have no labelled data, so
                # we only want to obtain the latest line number from it.
                existing_secret = existing_secret_map[secret]
                if existing_secret.line_number:
                    # Only update line numbers if we're tracking them.
                    existing_secret.line_number = secret.line_number

                result[filename].add(existing_secret)

        for filename in self.files:
            # If this is already populated by scanned_results, then the set intersection
            # is already completed.
            if filename in result:
                continue

            # All secrets relating to that file was removed.
            # We know this because:
            #   1. It's a file that was scanned (in filelist)
            #   2. It would have been in the baseline, if there were secrets...
            #   3. ...but it isn't.
            if filename in fileset:
                continue

            result[filename] = self[filename]

        self.data = result

    def json(self) -> Dict[str, Any]:
        """Custom JSON encoder"""
        output = defaultdict(list)
        for filename, secret in self:
            output[filename].append(secret.json())

        return dict(output)

    def exactly_equals(self, other: Any) -> bool:
        return self.__eq__(other, strict=True)      # type: ignore

    def __getitem__(self, filename: str) -> Set[PotentialSecret]:
        return self.data[filename]

    def __setitem__(self, filename: str, value: Set[PotentialSecret]) -> None:
        self.data[filename] = value

    def __iter__(self) -> Generator[Tuple[str, PotentialSecret], None, None]:
        for filename in sorted(self.files):
            secrets = self[filename]

            # NOTE: If line numbers aren't supplied, they are supposed to default to 0.
            for secret in sorted(
                secrets,
                key=lambda secret: (
                    getattr(secret, 'line_number', 0),
                    secret.secret_hash,
                    secret.type,
                ),
            ):
                yield filename, secret

    def __bool__(self) -> bool:
        # This checks whether there are secrets, rather than just empty files.
        # Empty files can occur with SecretsCollection subtraction.
        return bool(list(self))

    def __eq__(self, other: Any, strict: bool = False) -> bool:
        """
        :param strict: if strict, will return False even if secrets match
            (e.g. if line numbers are different)
        """
        if not isinstance(other, SecretsCollection):
            raise NotImplementedError

        if self.files != other.files:
            return False

        for filename in self.files:
            self_mapping = {
                (secret.secret_hash, secret.type): secret for secret in self[filename]
            }
            other_mapping = {
                (secret.secret_hash, secret.type): secret for secret in other[filename]
            }

            # Since PotentialSecret is hashable, we compare their identities through this.
            if set(self_mapping.values()) != set(other_mapping.values()):
                return False

            if not strict:
                continue

            for secretA in self_mapping.values():
                secretB = other_mapping[(secretA.secret_hash, secretA.type)]

                valuesA = vars(secretA)
                valuesA.pop('secret_value')
                valuesB = vars(secretB)
                valuesB.pop('secret_value')

                if valuesA['line_number'] == 0 or valuesB['line_number'] == 0:
                    # If line numbers are not provided (for either one), then don't compare
                    # line numbers.
                    valuesA.pop('line_number')
                    valuesB.pop('line_number')

                if valuesA != valuesB:
                    return False

        return True

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __sub__(self, other: Any) -> 'SecretsCollection':
        """This behaves like set subtraction."""
        if not isinstance(other, SecretsCollection):
            raise NotImplementedError

        # We want to create a copy to follow convention and adhere to the principle
        # of least surprise.
        output = SecretsCollection()
        for filename in other.files:
            if filename not in self.files:
                continue

            output[filename] = self[filename] - other[filename]

        for filename in self.files:
            if filename in other.files:
                continue

            output[filename] = self[filename]

        return output

    def __len__(self) -> int:
        """Returns the total number of secrets in the collection."""
        return sum(len(secrets) for secrets in self.data.values())


def _build_old_secret_index(
    old_results: 'SecretsCollection',
) -> Dict[Tuple[str, str], List[PotentialSecret]]:
    """
    Groups audited findings by ``(filename, hashed_secret)``. This lets us tell apart the
    three ways a new finding can relate to an old one sharing its fingerprint:
    same detector, different detector, or merely a same-valued string in another file.
    """
    index: Dict[Tuple[str, str], List[PotentialSecret]] = defaultdict(list)
    for filename in old_results.files:
        for old_secret in old_results.data[filename]:
            index[(filename, old_secret.secret_hash)].append(old_secret)

    return index


def _classify_inheritance(
    filename: str,
    new_secret: PotentialSecret,
    old_index: Dict[Tuple[str, str], List[PotentialSecret]],
) -> Tuple[str, Optional[PotentialSecret]]:
    """
    Decides whether the audit conclusion recorded for ``new_secret`` may be inherited.

    The match keys are intentionally strict, so that a verdict for one location never
    spreads to other locations:

    * ``(filename, hashed_secret, type)`` identical  -> keep the conclusion. A changed
      line number does not affect the identity, which covers line-only moves and
      repeated occurrences of the same finding within one file.
    * same file and fingerprint, different type      -> the detector changed; re-audit.
    * same fingerprint, different file               -> rename or a copy of the same
      fake secret elsewhere; re-audit.
    * no matching fingerprint at all                 -> genuinely new finding; re-audit.

    :param filename: the collection's key for this finding (as serialized in baselines),
        which is not necessarily identical to ``new_secret.filename``.
    """
    same_file_matches = old_index.get((filename, new_secret.secret_hash), [])
    for old_secret in same_file_matches:
        if old_secret.type == new_secret.type:
            return INHERITED_EXACT_IDENTITY, old_secret

    if same_file_matches:
        # The string is still in the same file, but a different detector now flags it.
        return REAUDIT_DETECTOR_CHANGED, None

    for (old_filename, old_hash), old_secrets in old_index.items():
        if old_hash == new_secret.secret_hash and old_filename != filename:
            # Same string, different file: a rename or a copy of the fake secret.
            # The old verdict belongs to the old location only.
            return REAUDIT_FILE_CHANGED, None

    return REAUDIT_NEW_FINDING, None


def _scan_file_and_serialize(filename: str) -> List[PotentialSecret]:
    """Used for multiprocessing, since lambdas can't be serialized."""
    return list(scan.scan_file(filename))
