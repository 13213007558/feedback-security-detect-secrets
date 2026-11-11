#!/usr/bin/env python3
"""
Compares two detect-secrets baselines and explains how policy changes
(plugins, limits, exclusions, filters) relate to findings that disappeared
or appeared between them.

Use this whenever a regenerated baseline drops findings: "not scanned this
time" is not the same as "problem resolved". Findings that cannot be
attributed to a verifiable policy change are flagged for rescanning.

Both baselines are normalized through the standard upgrade path, so older
baseline formats are accepted as-is.

Exit codes:
    0 - all disappeared findings are verifiably explained by policy changes
    1 - some disappeared findings require a rescan (or an error occurred)
"""
import argparse
import json
import sys

from detect_secrets.core import baseline
from detect_secrets.core import policy_diff
from detect_secrets.exceptions import UnableToReadBaselineError


def main() -> int:
    args = parse_args()

    try:
        old_baseline = baseline.load_from_file(args.old)
        new_baseline = baseline.load_from_file(args.new)
    except UnableToReadBaselineError as e:
        print('error: unable to read baseline: {}'.format(e), file=sys.stderr)
        return 1

    report = policy_diff.compare_baselines(
        old_baseline,
        new_baseline,
        old_filename=args.old,
        new_filename=args.new,
    )

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(policy_diff.format_text_report(report))

    return 1 if report['rescan']['required'] else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            'Explain why findings disappeared (or appeared) between two '
            'detect-secrets baselines, based on policy changes recorded in '
            'the baselines themselves.'
        ),
    )
    parser.add_argument('old', help='Path to the previous baseline file.')
    parser.add_argument('new', help='Path to the regenerated baseline file.')
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output the raw report as JSON instead of a text summary.',
    )
    return parser.parse_args()


if __name__ == '__main__':
    sys.exit(main())
