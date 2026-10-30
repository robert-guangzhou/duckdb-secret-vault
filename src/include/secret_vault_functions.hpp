#pragma once

namespace duckdb {

class ExtensionLoader;

//! 阶段三表函数:migrate(local_file→加密)/ rotate(重加密)/ export+import(一次性封套)
void RegisterVaultFunctions(ExtensionLoader &loader);

} // namespace duckdb
