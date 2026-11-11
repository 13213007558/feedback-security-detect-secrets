"""
When a baseline is regenerated, findings can disappear for reasons that have
nothing to do with the underlying source code being fixed: a plugin may have
been disabled, an entropy limit raised, a file exclusion pattern added, or a
filter reconfigured. Interpreting "not scanned this time" as "problem resolved"
is a common and dangerous mistake.

This module compares the *policy* (plugins, filters, exclusions) recorded in
two baselines alongside their results, and produces a report that attributes
each disappeared finding to a concrete policy change where that is
deterministically possible. Everything that cannot be explained this way is
explicitly flagged as requiring a rescan, so maintainers can decide whether
the update needs a re-audit.

Both baselines are normalized through the existing upgrade path
(`detect_secrets.core.baseline.upgrade`), so older baseline formats are
accepted as-is -- no manual reformatting required.

Only metadata already present in baseline files is used: filenames, line
numbers, secret types, audit labels and hashed secrets. Baselines never store
raw secrets, and neither does this report.
"""
import copy
import json
import re
from typing import Any
from typing import Dict
from typing import List
from typing import Tuple

from . import baseline as baseline_module
from ..__version__ import VERSION


FILE_EXCLUSION_FILTER = 'detect_secrets.filters.regex.should_exclude_file'
LINE_EXCLUSION_FILTER = 'detect_secrets.filters.regex.should_exclude_line'

REASON_PLUGIN_DISABLED = 'plugin_disabled'
REASON_FILE_EXCLUDED = 'file_excluded'
REASON_PLUGIN_CONFIG_CHANGED = 'plugin_config_changed'
REASON_FILTER_CHANGED = 'filter_changed'
REASON_UNDETERMINED = 'undetermined'

FindingKey = Tuple[str, str, str]


def compare_baselines(
    old_baseline: Dict[str, Any],
    new_baseline: Dict[str, Any],
    old_filename: str = '',
    new_filename: str = '',
) -> Dict[str, Any]:
    """
    Compare two baselines (in any historical format) and explain how policy
    changes relate to findings that disappeared or appeared.

    :param old_baseline: parsed JSON of the previous baseline
    :param new_baseline: parsed JSON of the regenerated baseline
    :param old_filename: only used to render a runnable rescan suggestion
    :param new_filename: only used to render a runnable rescan suggestion
    :return: JSON-serializable report
    """
    old = _normalize(old_baseline)
    new = _normalize(new_baseline)

    policy_changes = _diff_policy(old, new)

    old_findings = _index_results(old)
    new_findings = _index_results(new)

    disappeared_keys = set(old_findings) - set(new_findings)
    appeared_keys = set(new_findings) - set(old_findings)

    secret_type_mapping = _get_secret_type_mapping(old, new)
    disappeared = [
        _explain_disappearance(old_findings[key], old, new, policy_changes, secret_type_mapping)
        for key in sorted(disappeared_keys)
    ]
    appeared = [new_findings[key] for key in sorted(appeared_keys)]

    needs_rescan = [finding for finding in disappeared if not finding['explanation']['verifiable']]
    audited_disappeared = [
        finding for finding in disappeared
        if finding['is_secret'] is True
    ]

    report = {
        'old_version': old_baseline.get('version'),
        'new_version': new_baseline.get('version'),
        'normalized_to_version': VERSION,
        'policy_changes': policy_changes,
        'disappeared_findings': disappeared,
        'new_findings': appeared,
        'summary': {
            'old_total': len(old_findings),
            'new_total': len(new_findings),
            'unchanged': len(set(old_findings) & set(new_findings)),
            'disappeared': len(disappeared),
            'disappeared_explained_by_policy': len(disappeared) - len(needs_rescan),
            'disappeared_needs_rescan': len(needs_rescan),
            'new': len(appeared),
            'audited_secrets_disappeared': len(audited_disappeared),
        },
        'rescan': _build_rescan_recommendation(
            needs_rescan=needs_rescan,
            audited_disappeared=audited_disappeared,
            old_filename=old_filename,
        ),
    }
    return report


def format_text_report(report: Dict[str, Any]) -> str:
    """Renders the report for a maintainer reading a terminal."""
    lines = []
    summary = report['summary']

    lines.append('Baseline Policy Change Report')
    lines.append('=============================')
    lines.append(
        'Baseline versions: {old} -> {new} (normalized to {norm} for comparison)'.format(
            old=report['old_version'],
            new=report['new_version'],
            norm=report['normalized_to_version'],
        ),
    )
    lines.append(
        'Findings: {old} old / {new} new / {unchanged} unchanged / '
        '{disappeared} disappeared / {appeared} newly found'.format(
            old=summary['old_total'],
            new=summary['new_total'],
            unchanged=summary['unchanged'],
            disappeared=summary['disappeared'],
            appeared=summary['new'],
        ),
    )
    lines.append('')

    lines.append('Policy Changes')
    lines.append('--------------')
    lines.extend(_format_policy_changes(report['policy_changes']))
    lines.append('')

    lines.append('Disappeared Findings')
    lines.append('--------------------')
    if not report['disappeared_findings']:
        lines.append('  (none)')
    for finding in report['disappeared_findings']:
        explanation = finding['explanation']
        verifiable = 'verified' if explanation['verifiable'] else 'NEEDS RESCAN'
        audited = ' [audited: is_secret={}]'.format(finding['is_secret']) \
            if finding['is_secret'] is not None else ''
        lines.append(
            '  {filename}:{line} ({type}) [{reason}; {verifiable}]{audited}'.format(
                filename=finding['filename'],
                line=finding.get('line_number') or '?',
                type=finding['type'],
                reason=explanation['reason'],
                verifiable=verifiable,
                audited=audited,
            ),
        )
        lines.append('    {}'.format(explanation['details']))
    lines.append('')

    lines.append('Rescan Recommendation')
    lines.append('---------------------')
    for note in report['rescan']['notes']:
        lines.append('  * {}'.format(note))
    if report['rescan']['required']:
        lines.append('  * Files to rescan:')
        for filename in report['rescan']['files']:
            lines.append('      {}'.format(filename))
        lines.append('  * Suggested command:')
        lines.append('      {}'.format(report['rescan']['command']))

    return '\n'.join(lines)


def _normalize(baseline: Dict[str, Any]) -> Dict[str, Any]:
    """
    Brings any historical baseline format up to the current one, so policies
    can be compared like-for-like. Operates on a copy; the input is untouched.
    """
    return baseline_module.upgrade(copy.deepcopy(baseline))


def _normalize_plugins(baseline: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    output = {}
    for entry in baseline.get('plugins_used', []):
        config = {key: value for key, value in entry.items() if key != 'name'}
        output[entry['name']] = config
    return output


def _normalize_filters(baseline: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    output = {}
    for entry in baseline.get('filters_used', []):
        config = {key: value for key, value in entry.items() if key != 'path'}
        output[entry['path']] = config
    return output


def _get_exclusion_patterns(filters: Dict[str, Dict[str, Any]], path: str) -> List[str]:
    config = filters.get(path) or {}
    return list(config.get('pattern') or [])


def _diff_policy(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    old_plugins = _normalize_plugins(old)
    new_plugins = _normalize_plugins(new)
    old_filters = _normalize_filters(old)
    new_filters = _normalize_filters(new)

    return {
        'plugins': {
            'disabled': sorted(set(old_plugins) - set(new_plugins)),
            'enabled': sorted(set(new_plugins) - set(old_plugins)),
            'config_changed': [
                {
                    'name': name,
                    'old': old_plugins[name],
                    'new': new_plugins[name],
                }
                for name in sorted(set(old_plugins) & set(new_plugins))
                if old_plugins[name] != new_plugins[name]
            ],
        },
        'filters': {
            'removed': sorted(set(old_filters) - set(new_filters)),
            'added': sorted(set(new_filters) - set(old_filters)),
            'config_changed': [
                {
                    'path': path,
                    'old': old_filters[path],
                    'new': new_filters[path],
                }
                for path in sorted(set(old_filters) & set(new_filters))
                if old_filters[path] != new_filters[path]
            ],
        },
        'file_exclusions': {
            'added': sorted(
                set(_get_exclusion_patterns(new_filters, FILE_EXCLUSION_FILTER))
                - set(_get_exclusion_patterns(old_filters, FILE_EXCLUSION_FILTER)),
            ),
            'removed': sorted(
                set(_get_exclusion_patterns(old_filters, FILE_EXCLUSION_FILTER))
                - set(_get_exclusion_patterns(new_filters, FILE_EXCLUSION_FILTER)),
            ),
        },
        'line_exclusions': {
            'added': sorted(
                set(_get_exclusion_patterns(new_filters, LINE_EXCLUSION_FILTER))
                - set(_get_exclusion_patterns(old_filters, LINE_EXCLUSION_FILTER)),
            ),
            'removed': sorted(
                set(_get_exclusion_patterns(old_filters, LINE_EXCLUSION_FILTER))
                - set(_get_exclusion_patterns(new_filters, LINE_EXCLUSION_FILTER)),
            ),
        },
    }


def _index_results(baseline: Dict[str, Any]) -> Dict[FindingKey, Dict[str, Any]]:
    output = {}
    for filename, secrets in baseline.get('results', {}).items():
        for item in secrets:
            key = (filename, item.get('type'), item.get('hashed_secret'))
            output[key] = {
                'filename': filename,
                'type': item.get('type'),
                'hashed_secret': item.get('hashed_secret'),
                'line_number': item.get('line_number'),
                'is_verified': item.get('is_verified', False),
                'is_secret': item.get('is_secret'),
            }
    return output


def _get_secret_type_mapping(
    old: Dict[str, Any],
    new: Dict[str, Any],
) -> Dict[str, str]:
    """Maps secret type -> plugin name, including best-effort custom plugins."""
    from .plugins.util import get_mapping_from_secret_type_to_class
    from .plugins.util import get_plugins_from_file

    output = {
        secret_type: plugin_class.__name__
        for secret_type, plugin_class in get_mapping_from_secret_type_to_class().items()
    }

    for baseline in (old, new):
        for entry in baseline.get('plugins_used', []):
            path = entry.get('path', '')
            if not path.startswith('file://'):
                continue
            try:
                for plugin_class in get_plugins_from_file(path[len('file://'):]):
                    output[plugin_class.secret_type] = plugin_class.__name__
            except Exception:
                # Best effort only: unimportable custom plugins simply fall
                # through to the `undetermined` reason.
                continue

    return output


def _explain_disappearance(
    finding: Dict[str, Any],
    old: Dict[str, Any],
    new: Dict[str, Any],
    policy_changes: Dict[str, Any],
    secret_type_mapping: Dict[str, str],
) -> Dict[str, Any]:
    explanation = _attribute(finding, old, new, policy_changes, secret_type_mapping)
    return {
        **finding,
        'explanation': explanation,
    }


def _attribute(
    finding: Dict[str, Any],
    old: Dict[str, Any],
    new: Dict[str, Any],
    policy_changes: Dict[str, Any],
    secret_type_mapping: Dict[str, str],
) -> Dict[str, Any]:
    old_plugins = _normalize_plugins(old)
    new_plugins = _normalize_plugins(new)

    plugin_name = secret_type_mapping.get(finding['type'])

    # 1. The plugin that produced this finding no longer runs at all.
    if plugin_name and plugin_name in old_plugins and plugin_name not in new_plugins:
        return {
            'reason': REASON_PLUGIN_DISABLED,
            'verifiable': True,
            'details': (
                "Plugin '{name}' was enabled in the old baseline but is absent from the "
                "new one, so '{type}' findings are no longer scanned for. The underlying "
                'content was not re-evaluated; confirm this plugin was disabled '
                'intentionally.'.format(name=plugin_name, type=finding['type'])
            ),
        }

    # 2. The file itself is now excluded from scans.
    matching_patterns = [
        pattern
        for pattern in policy_changes['file_exclusions']['added']
        if _safe_search(pattern, finding['filename'])
    ]
    if matching_patterns:
        return {
            'reason': REASON_FILE_EXCLUDED,
            'verifiable': True,
            'details': (
                'Filename matches file exclusion pattern(s) added in the new baseline: '
                '{}. The file was not scanned at all.'.format(', '.join(matching_patterns))
            ),
        }

    # 3. The plugin still runs, but with different configuration (e.g. a
    #    raised entropy limit). We cannot recompute entropy from a hash.
    if plugin_name and plugin_name in old_plugins and plugin_name in new_plugins \
            and old_plugins[plugin_name] != new_plugins[plugin_name]:
        return {
            'reason': REASON_PLUGIN_CONFIG_CHANGED,
            'verifiable': False,
            'details': (
                "Plugin '{name}' configuration changed: {old} -> {new}. Whether this "
                'finding falls below the new threshold cannot be determined from a '
                'hashed secret; rescan the file to confirm.'.format(
                    name=plugin_name,
                    old=json.dumps(old_plugins[plugin_name], sort_keys=True),
                    new=json.dumps(new_plugins[plugin_name], sort_keys=True),
                )
            ),
        }

    # 4. Filters were added or reconfigured; they need source content to evaluate.
    candidate_filters = (
        policy_changes['filters']['added']
        + [entry['path'] for entry in policy_changes['filters']['config_changed']]
    )
    if candidate_filters:
        return {
            'reason': REASON_FILTER_CHANGED,
            'verifiable': False,
            'details': (
                'Filter(s) added or reconfigured in the new baseline: {}. Filters '
                'cannot be evaluated without the source content; rescan the file to '
                'confirm.'.format(', '.join(candidate_filters))
            ),
        }

    # 5. Nothing in the policy explains it.
    return {
        'reason': REASON_UNDETERMINED,
        'verifiable': False,
        'details': (
            'No policy change between the baselines explains this disappearance. The '
            'source may have changed, or the scan environment differs. Rescan the file '
            'with the old policy to determine whether the finding is actually gone.'
        ),
    }


def _safe_search(pattern: str, value: str) -> bool:
    try:
        return bool(re.search(pattern, value))
    except re.error:
        return False


def _build_rescan_recommendation(
    needs_rescan: List[Dict[str, Any]],
    audited_disappeared: List[Dict[str, Any]],
    old_filename: str,
) -> Dict[str, Any]:
    files = sorted({finding['filename'] for finding in needs_rescan})
    old_baseline_ref = old_filename or '<old-baseline>'

    notes = []
    if not needs_rescan and not audited_disappeared:
        notes.append(
            'All findings changes are accounted for. No rescan or re-audit is '
            'required based on this comparison.',
        )
    else:
        if needs_rescan:
            notes.append(
                '{} disappeared finding(s) could NOT be explained by policy changes '
                'alone. Do not treat them as resolved until a rescan with the old '
                'policy confirms they are gone.'.format(len(needs_rescan)),
            )
        if audited_disappeared:
            notes.append(
                '{} disappeared finding(s) were previously audited as true positives '
                '(is_secret=true). These require a re-audit decision regardless of '
                'the explanation.'.format(len(audited_disappeared)),
            )

    verifiable_only_note = (
        'Findings explained by policy changes were not re-evaluated either: the new '
        'policy simply no longer looks for them. Confirm each policy change was '
        'intentional before accepting the new baseline.'
    )
    notes.append(verifiable_only_note)

    return {
        'required': bool(needs_rescan),
        'files': files,
        'command': 'detect-secrets scan --baseline {} {}'.format(
            old_baseline_ref,
            ' '.join(files) if files else '<files>',
        ),
        'notes': notes,
    }


def _format_policy_changes(policy_changes: Dict[str, Any]) -> List[str]:
    lines = []
    plugins = policy_changes['plugins']
    filters = policy_changes['filters']

    if plugins['disabled']:
        lines.append('  Plugins disabled: {}'.format(', '.join(plugins['disabled'])))
    if plugins['enabled']:
        lines.append('  Plugins enabled: {}'.format(', '.join(plugins['enabled'])))
    for entry in plugins['config_changed']:
        lines.append(
            "  Plugin '{name}' config: {old} -> {new}".format(
                name=entry['name'],
                old=json.dumps(entry['old'], sort_keys=True),
                new=json.dumps(entry['new'], sort_keys=True),
            ),
        )
    if filters['added']:
        lines.append('  Filters added: {}'.format(', '.join(filters['added'])))
    if filters['removed']:
        lines.append('  Filters removed: {}'.format(', '.join(filters['removed'])))
    for entry in filters['config_changed']:
        lines.append(
            "  Filter '{path}' config: {old} -> {new}".format(
                path=entry['path'],
                old=json.dumps(entry['old'], sort_keys=True),
                new=json.dumps(entry['new'], sort_keys=True),
            ),
        )
    if policy_changes['file_exclusions']['added']:
        lines.append(
            '  File exclusion patterns added: {}'.format(
                ', '.join(policy_changes['file_exclusions']['added']),
            ),
        )
    if policy_changes['file_exclusions']['removed']:
        lines.append(
            '  File exclusion patterns removed: {}'.format(
                ', '.join(policy_changes['file_exclusions']['removed']),
            ),
        )
    if policy_changes['line_exclusions']['added']:
        lines.append(
            '  Line exclusion patterns added: {}'.format(
                ', '.join(policy_changes['line_exclusions']['added']),
            ),
        )
    if not lines:
        lines.append('  (no policy changes detected)')
    return lines
