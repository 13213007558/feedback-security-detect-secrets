# Upgrades and Version Bumps

`detect-secrets` uses [semver versioning](https://semver.org/) for releases. Specifically,

1. All **code breaking** API changes will result in a MAJOR version change,
2. All **baseline modifications** and/or **features** will result in a MINOR version change,
3. All **bug fixes** will result in a PATCH version change.

This document attempts to standardize version upgrades, and provide a means to make easy,
self-documenting, backwards-compatible changes.

## When

This section provides a list of common actions, and their corresponding need for version bumps:

- **Adding a New Filter**: MINOR version bump, even if the filter does not intend to be added
  by default.

- **Adding a New Plugin**: MINOR version bump, as this will modify the baseline to include it.

- **Modifying Command Line Arguments**: MINOR version bump. While this may be a breaking change
  to the command line API, only code breaking API changes will result in a MAJOR version change.
  Otherwise, we'll have a chance of increasing major version bumps too often (i.e. the addition
  of `--exclude-files` will require a whole new major version upgrade).

- **Modifying Default Configuration Options**: (e.g. `Base64HighEntropyString` limit): PATCH
  version bump. This should only affect new baseline creations, and so this is backwards compatible
  by default.

## What

For all non-PATCH version bumps, a corresponding upgrade file needs to be written. This processes
old versions of baselines, and reformats them into newer, more compatible versions.

`detect_secrets.core.baseline.upgrade` will sequentially execute these upgrade modules. That is,
for a baseline version of `0.11.0`, and two defined upgrade modules `v0_12.py` and `v1_0.py`,
it will:

1. Upgrade from `0.11.0` to be compatible with `0.12.X`,
2. Upgrade from `0.12.X` to be compatible with `1.0.X`

## How

### Writing an Upgrade File

These upgrade files must be named as such: `detect_secrets/core/upgrades/v{major}_{minor}.py`, and
indicate the steps required to convert an older baseline to be compatible with the listed version.
For example, `v1_0.py` will take older baselines and convert them to be compatible with `v1.0.X`.

These files must also declare an `upgrade` function, which will be executed with one parameter:
the dictionary representation of an older baseline file.

It is recommended to **hard-code** values where appropriate, given that dynamic references may
change with the codebase and upgrade scripts should be static. For example, if you reference an
imported enum value in your upgrade script, and the enum value changes over time, the underlying
assumption of the upgrade script will break.

### Changing the Version

`detect-secrets` integrates with `bump2version` to make this process easier. Here's a handy
pre-bump checklist to make sure you haven't forgotten anything:

- [ ] Have you modified the CHANGELOG with the latest changes?
- [ ] Have you written an upgrade file to ensure backwards compatibility?

Then, you (as a `detect-secrets` maintainer) can run:

```bash
scripts/bump-version
```

### Pushing to PyPi

Once the tag from `scripts/bump-version` has been created and pushed to the repository, the pypi
github action will automatically start and publish the package to pypi.

## Explaining Result Changes When Regenerating Baselines

When a baseline is regenerated (e.g. after a version upgrade, a plugin
configuration change, or new exclusion patterns), findings may disappear even
though the underlying source code never changed. **"Not scanned this time" is
not the same as "problem resolved".** Before accepting a baseline update that
drops findings, produce a policy change explanation:

```bash
scripts/compare_baselines.py .secrets.baseline.old .secrets.baseline
```

This compares the two baselines' **plugins** (enabled/disabled, limit and
other configuration changes), **file and line exclusions**, and **filters**,
and attributes each disappeared finding to one of the following:

- `plugin_disabled` / `file_excluded`: verifiable from baseline metadata
  alone. The content was *not* re-evaluated -- the new policy simply no longer
  looks for it. Confirm the policy change was intentional.
- `plugin_config_changed` / `filter_changed`: candidate explanations that
  cannot be confirmed without the source content (entropy cannot be
  recomputed from a hashed secret). Flagged as **NEEDS RESCAN**.
- `undetermined`: no policy change explains the disappearance. Flagged as
  **NEEDS RESCAN** -- the source may have changed, or the finding may have
  been silently lost.

The report ends with a rescan recommendation: the exact files to re-scan and
a ready-to-run command using the *old* baseline's policy. Findings previously
audited as `is_secret=true` are called out separately, since those always
require a re-audit decision. The script exits non-zero whenever a rescan is
recommended, so it can gate the baseline update in automation.

Notes:

- Both baselines are normalized through the standard upgrade path
  (`detect_secrets.core.baseline.upgrade`), so older baseline formats are
  accepted as-is -- no manual reformatting needed.
- The report only contains metadata already present in baselines (filenames,
  line numbers, secret types, audit labels, hashed secrets). Raw secrets
  never appear in it.
- A checked-in migration sample (`test_data/policy_diff/`) demonstrates the
  workflow: a `0.11.0` baseline compared against a regenerated `1.5.0`
  baseline. See `tests/core/policy_diff_test.py` for the expected report.
