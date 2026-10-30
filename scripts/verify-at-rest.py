#!/usr/bin/env python3
"""阶段二 at-rest 字节级断言(Test Plan TP-10/TP-14)。

用法: verify-at-rest.py <vault_dir> <secret_name> <marker>
断言:
  TP-10a 文件字节中不含明文 marker
  TP-10b 前 8 字节 = DSVLT\0\0\0
  TP-10c 文件权限 600(POSIX)
输出: 每项 PASS/FAIL 与 hexdump 摘要;任一 FAIL 退出码 1。
"""
import os
import stat
import sys

MAGIC = b"DSVLT\x00\x00\x00"


def main() -> int:
    vault_dir, name, marker = sys.argv[1], sys.argv[2], sys.argv[3].encode()
    path = os.path.join(vault_dir, name + ".duckdb_secret.vault")
    failed = []

    blob = open(path, "rb").read()
    print(f"[file] {path} size={len(blob)}")
    print(f"[hex-head] {blob[:64].hex()}")

    # TP-10a: 静态密文性——明文 marker 不得出现
    n = blob.count(marker)
    print(f"[TP-10a] plaintext-marker occurrences = {n} (expect 0)")
    if n != 0:
        failed.append("TP-10a")

    # TP-10b: magic
    ok = blob[:8] == MAGIC
    print(f"[TP-10b] magic == DSVLT\\0\\0\\0 : {ok}")
    if not ok:
        failed.append("TP-10b")

    # 头部字段:version=1 BE, provider id 合法(1/2/3)
    version = int.from_bytes(blob[8:10], "big")
    provider = blob[10]
    print(f"[hdr] version={version} provider={provider}")
    if version != 1 or provider not in (1, 2, 3):
        failed.append("hdr")

    # TP-10c: 权限 600(POSIX;Windows 下跳过)
    if os.name == "posix":
        mode = stat.S_IMODE(os.stat(path).st_mode)
        print(f"[TP-10c] mode = {mode:o} (expect 600)")
        if mode != 0o600:
            failed.append("TP-10c")

    if failed:
        print("FAIL: " + ",".join(failed))
        return 1
    print("ALL-PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
