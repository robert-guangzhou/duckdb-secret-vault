#!/usr/bin/env bash
# 重新生成 src/include/secret_vault_rust.h（需 cbindgen CLI，builder 容器已安装）。
# Rust 侧 C ABI 变更后运行本脚本并提交生成的头文件。
set -euo pipefail
cd "$(dirname "$0")"
cbindgen --config cbindgen.toml --output ../src/include/secret_vault_rust.h
# 补闭守卫：插在 include guard #endif 之前（cbindgen trailer 会落在 guard 之外，
# 重复包含时不平衡——nats_rw 2026-10-26 实测教训）。
python3 - <<'PY'
from pathlib import Path

p = Path("../src/include/secret_vault_rust.h")
text = p.read_text()
guard_close = '#endif  /* SECRET_VAULT_RUST_H */'
closing = '#ifdef __cplusplus\n} /* extern "C" */\n#endif\n'
assert text.count(guard_close) == 1, "include guard close not found exactly once"
assert 'extern "C"' in text, "after_includes guard missing"
assert text.count('} /* extern "C" */') == 0, "closing guard already present"
p.write_text(text.replace(guard_close, closing + guard_close))
print('extern "C" closing guard inserted before include guard #endif')
PY
