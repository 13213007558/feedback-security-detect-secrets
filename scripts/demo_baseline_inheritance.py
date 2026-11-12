#!/usr/bin/env python3
"""
End-to-end demo: how audit conclusions are inherited when a detect-secrets
baseline is updated (i.e. the repository is rescanned and merged with the
previously audited baseline).

A throwaway project is scanned twice, with code mutations in between, covering:

    1. line-only move                       -> conclusion is kept
    2. file rename                          -> must be re-audited
    3. same fake secret copied to a new file -> must be re-audited
    4. detector type change                 -> must be re-audited
    5. repeated occurrence in the same file -> one finding, label kept

The report only shows fingerprints (hashed secrets) and locations; candidate
secret values are never echoed. All "secrets" below are public test vectors
from test_data/each_secret.py, not real credentials.
"""
import json
import os
import shutil
import sys
import tempfile
from typing import Dict
from typing import List
from typing import Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detect_secrets.core import baseline                                # noqa: E402
from detect_secrets.core.potential_secret import PotentialSecret        # noqa: E402
from detect_secrets.core.secrets_collection import (                    # noqa: E402
    INHERITED_EXACT_IDENTITY,
    REAUDIT_DETECTOR_CHANGED,
    REAUDIT_FILE_CHANGED,
    REAUDIT_NEW_FINDING,
    InheritanceRecord,
    SecretsCollection,
)
from detect_secrets.settings import transient_settings                  # noqa: E402

# Fake secrets (public test vectors, safe to store in this script).
FAKE_BASE64 = 'c2VjcmV0IG1lc3NhZ2Ugc28geW91J2xsIG5ldmVyIGd1ZXNzIG15IHBhc3N3b3Jk'
FAKE_AWS = 'AKIAIOSFODNN7EXAMPLE'
FAKE_HEX = '8b1118b376c313ed420e5133ba91307817ed52c2'
FAKE_HEX_LEGACY = '9f2c4a77d10eb6c358a0f2d94b71e6ca53d8f902'
FAKE_BASE64_NEW = 'YW1pYWx3YXlzZ2VuZXJhdGluZ3BheWxvYWRzd2hlbmltaHVuZ3J5b3JhbWlhbHdheXNodW5ncnk'  # noqa: E501

PLUGINS_SCAN_1 = [
    {'name': 'AWSKeyDetector'},
    {'name': 'Base64HighEntropyString', 'limit': 4.5},
    {'name': 'HexHighEntropyString', 'limit': 3.0},
]
# Second scan adds KeywordDetector, so the string in config/service.py is
# flagged by a *different* detector type as well.
PLUGINS_SCAN_2 = PLUGINS_SCAN_1 + [{'name': 'KeywordDetector'}]

SCAN_1_FILES = ['src/app.py', 'config/service.py', 'src/legacy.py']
SCAN_2_FILES = ['src/app.py', 'config/service.py', 'src/legacy_renamed.py', 'docs/example.py']

# Simulated human audit of the first baseline, keyed by (filename, secret type).
AUDIT_VERDICTS = {
    ('src/app.py', 'Base64 High Entropy String'): False,    # false positive
    ('src/app.py', 'AWS Access Key'): True,                 # confirmed secret
    ('config/service.py', 'Hex High Entropy String'): False,
    ('src/legacy.py', 'Hex High Entropy String'): False,
}


def write_file(root: str, relpath: str, content: str) -> None:
    path = os.path.join(root, relpath)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(content)


def write_snapshot_1(root: str) -> None:
    write_file(root, 'src/app.py', (
        f"legacy_blob = '{FAKE_BASE64}'\n"
        f"aws_key = '{FAKE_AWS}'\n"
    ))
    write_file(root, 'config/service.py', f"password = '{FAKE_HEX}'\n")
    write_file(root, 'src/legacy.py', f"token = '{FAKE_HEX_LEGACY}'\n")


def write_snapshot_2(root: str) -> None:
    # 1+5. Both secrets move down; the base64 string now appears twice in the file.
    write_file(root, 'src/app.py', (
        '# --------------------------------------------------------------\n'
        '# banner: application bootstrap\n'
        '# --------------------------------------------------------------\n'
        f"legacy_blob = '{FAKE_BASE64}'\n"
        f"aws_key = '{FAKE_AWS}'\n"
        f"legacy_blob_copy = '{FAKE_BASE64}'\n"
        f"fresh_blob = '{FAKE_BASE64_NEW}'\n"      # genuinely new finding
    ))
    # 4. Unchanged file; the added KeywordDetector flags the same string too.
    # 2. Renamed file, content untouched.
    os.rename(
        os.path.join(root, 'src/legacy.py'),
        os.path.join(root, 'src/legacy_renamed.py'),
    )
    # 3. The same fake base64 string is copied into a brand new file.
    write_file(root, 'docs/example.py', f"example = '{FAKE_BASE64}'\n")


def scan(root: str, files: List[str], plugins: List[Dict]) -> SecretsCollection:
    with transient_settings({'plugins_used': plugins, 'filters_used': []}):
        secrets = SecretsCollection(root=root)
        for filename in files:
            secrets.scan_file(filename)
    return secrets


def fingerprint(secret_hash: str) -> str:
    return f'{secret_hash[:12]}…'


def label_of(is_secret) -> str:
    return {True: '真密钥', False: '误报', None: '未审计'}[is_secret]


def main() -> None:
    project = tempfile.mkdtemp(prefix='detect-secrets-inheritance-')
    try:
        run(project)
    finally:
        shutil.rmtree(project, ignore_errors=True)


def run(project: str) -> None:
    print(f'临时项目目录: {project}\n')

    # --- First scan + simulated human audit -------------------------------
    write_snapshot_1(project)
    scan_1 = scan(project, SCAN_1_FILES, PLUGINS_SCAN_1)
    for filename, secret in scan_1:
        verdict = AUDIT_VERDICTS.get((filename, secret.type))
        if verdict is not None:
            secret.is_secret = verdict

    baseline_v1 = os.path.join(project, 'baseline_v1.json')
    with transient_settings({'plugins_used': PLUGINS_SCAN_1, 'filters_used': []}):
        baseline.save_to_file(scan_1, baseline_v1)

    # The same audit results, stored in the old (v1.0.0) baseline format.
    legacy_format = os.path.join(project, 'baseline_v1.legacy-format.json')
    with open(baseline_v1) as f:
        legacy_baseline = json.load(f)
    legacy_baseline['version'] = '1.0.0'
    with open(legacy_format, 'w') as f:
        json.dump(legacy_baseline, f, indent=2)

    # Old baselines must still be readable; the upgrade path runs on load.
    old_results = baseline.load(baseline.load_from_file(legacy_format))
    assert old_results.exactly_equals(
        baseline.load(baseline.load_from_file(baseline_v1)),
    ), 'old-format baseline must load to identical results'
    print(f'旧格式 (v1.0.0) baseline 读取成功, 与现行格式内容一致: {legacy_format}')

    # --- Second scan, after code mutations --------------------------------
    write_snapshot_2(project)
    scan_2 = scan(project, SCAN_2_FILES, PLUGINS_SCAN_2)

    before = {
        (filename, secret.secret_hash, secret.type): secret.is_secret
        for filename, secret in scan_2
    }

    inheritance_log: List[InheritanceRecord] = []
    scan_2.merge(old_results, inheritance_log=inheritance_log)
    records: Dict[Tuple[str, str, str], InheritanceRecord] = {
        (record.filename, record.secret_hash, record.secret_type): record
        for record in inheritance_log
    }

    baseline_v2 = os.path.join(project, 'baseline_v2.json')
    with transient_settings({'plugins_used': PLUGINS_SCAN_2, 'filters_used': []}):
        baseline.save_to_file(scan_2, baseline_v2)

    print_report(scan_2, before, records, project, baseline_v2)


def print_report(
    scan_2: SecretsCollection,
    before: Dict[Tuple[str, str, str], object],
    records: Dict[Tuple[str, str, str], InheritanceRecord],
    project: str,
    baseline_v2: str,
) -> None:
    print('\n=== 继承前后对比 (每条新 finding 的标签变化) ===')
    for filename, secret in scan_2:
        key = (filename, secret.secret_hash, secret.type)
        record = records[key]
        print(
            f'  {fingerprint(secret.secret_hash)}  {secret.type:<28} '
            f'{filename}:{secret.line_number}\n'
            f'      合并前: {label_of(before[key])}  ->  合并后: {label_of(secret.is_secret)}'
            f'  [{record.reason}]',
        )

    print('\n=== 最终待审计队列 (is_secret 未判定, 必须人工审计) ===')
    pending = [
        (filename, secret)
        for filename, secret in scan_2
        if secret.is_secret is None
    ]
    for filename, secret in pending:
        record = records[(filename, secret.secret_hash, secret.type)]
        print(
            f'  {fingerprint(secret.secret_hash)}  {secret.type:<28} '
            f'{filename}:{secret.line_number}  [{record.reason}]',
        )

    print('\n=== 已继承的人工结论 (标签来源可追溯) ===')
    for filename, secret in scan_2:
        if secret.is_secret is None:
            continue
        record = records[(filename, secret.secret_hash, secret.type)]
        source = (
            f'{record.previous_location[0]}:{record.previous_location[1]}'
            if record.previous_location else '本次扫描'
        )
        print(
            f'  {fingerprint(secret.secret_hash)}  {secret.type:<28} '
            f'{filename}:{secret.line_number}  {label_of(secret.is_secret)}'
            f'  <- 继承自 {source}  [{record.reason}]',
        )

    print('\n=== 汇总 ===')
    for reason in (
        INHERITED_EXACT_IDENTITY,
        REAUDIT_DETECTOR_CHANGED,
        REAUDIT_FILE_CHANGED,
        REAUDIT_NEW_FINDING,
    ):
        count = sum(1 for record in records.values() if record.reason == reason)
        print(f'  {reason:<32} {count}')

    with open(os.path.join(project, 'src/app.py')) as f:
        occurrences = f.read().count(FAKE_BASE64)
    print(
        f'\n  同文件重复出现: 指纹 {fingerprint(PotentialSecret.hash_secret(FAKE_BASE64))}'
        f' 的字符串在 src/app.py 中出现 {occurrences} 次,'
        ' 因身份 (filename, hash, type) 相同合并为 1 条 finding, 标签天然共享.',
    )
    print(f'\n更新后的 baseline 已写入: {baseline_v2}')

    # Self-checks: the demo fails loudly if detector behaviour drifts.
    assert sum(1 for r in records.values() if r.reason == INHERITED_EXACT_IDENTITY) == 3
    assert sum(1 for r in records.values() if r.reason == REAUDIT_DETECTOR_CHANGED) == 1
    assert sum(1 for r in records.values() if r.reason == REAUDIT_FILE_CHANGED) == 2
    assert sum(1 for r in records.values() if r.reason == REAUDIT_NEW_FINDING) == 1
    assert len(pending) == 4


if __name__ == '__main__':
    main()
