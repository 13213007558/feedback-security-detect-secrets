"""
后端离线扫描接入示例（对应 detect-secrets 实际调用路径）。

保证扫描期间零出网：
1. 不启用 `is_ignored_due_to_verification_policies` 过滤器
   （等价于 CLI 的 --no-verify，见 detect_secrets/core/usage/filters.py:171）。
2. 即使从客户 baseline 载入配置（可能带回验证过滤器），也显式禁用之。
3. 可选兜底：install_network_guard() 让任何漏网的网络调用立即报错，
   宁可扫描失败也不出网。
"""
import json
import socket
import sys

import requests

VERIFY_FILTER = 'detect_secrets.filters.common.is_ignored_due_to_verification_policies'


class NetworkAttemptError(requests.exceptions.ConnectionError):
    """与真实离线环境异常类型一致，便于上游统一处理。"""


def install_network_guard() -> None:
    """兜底：任何 transport/socket 层网络调用立即抛错。"""
    real_socket = socket.socket

    class GuardedSocket(real_socket):
        def connect(self, address):
            raise NetworkAttemptError(f'blocked socket.connect -> {address}')

        def connect_ex(self, address):
            raise NetworkAttemptError(f'blocked socket.connect_ex -> {address}')

    socket.socket = GuardedSocket

    def guarded_send(self, request, **kwargs):
        raise NetworkAttemptError(f'blocked HTTP {request.method} {request.url}')

    requests.adapters.HTTPAdapter.send = guarded_send


def scan_offline(paths, baseline_config=None, scan_all_files=True):
    # scan_all_files=True：客户源码目录可能不是 git 仓库，
    # 否则 get_files_to_scan 会因拿不到 git 跟踪列表而静默扫 0 个文件
    # (detect_secrets/core/scan.py:70-83)。
    from detect_secrets.core import baseline
    from detect_secrets.settings import configure_settings_from_baseline
    from detect_secrets.settings import default_settings

    if baseline_config:
        # 从客户 baseline 恢复插件/过滤器配置……
        settings = configure_settings_from_baseline(baseline_config)
        # ……但强制离线：验证过滤器一律移除（最小修正点）
        settings.disable_filters(VERIFY_FILTER)
        secrets = baseline.create(*paths, should_scan_all_files=scan_all_files)
    else:
        with default_settings() as settings:
            # default_settings 本就不含验证过滤器；显式禁用防配置漂移
            settings.disable_filters(VERIFY_FILTER)
            secrets = baseline.create(*paths, should_scan_all_files=scan_all_files)
    return json.loads(json.dumps(baseline.format_for_output(secrets)))


if __name__ == '__main__':
    install_network_guard()
    output = scan_offline(sys.argv[1:])
    for filename, items in sorted(output['results'].items()):
        for item in items:
            # 离线模式下所有发现都是「未验证」：is_verified=False 仅表示未联网核实，
            # 绝不是「确认无效」。确认无效(VERIFIED_FALSE)只存在于联网验证，
            # 且默认策略下会被过滤器直接丢弃、不会出现在结果里。
            print(f"{filename}:{item['line_number']} [{item['type']}] "
                  f"is_verified={item['is_verified']} (unverified-offline)")
