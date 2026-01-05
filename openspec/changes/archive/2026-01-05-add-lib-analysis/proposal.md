# Change: 添加静态库（.lib）依赖分析功能

## Why

当前 `print_exe_deps.py` 仅支持分析 PE 可执行文件（.exe/.dll）的依赖关系。在实际开发中，静态库（.lib）的依赖分析同样重要，开发者需要了解一个静态库依赖哪些其他库，以便正确配置链接器选项。

## What Changes

- 新增 `.lib` 文件依赖分析功能
- 支持两种类型的 .lib 文件：
  - **导入库**（Import Library）：分析其关联的 DLL
  - **静态库**（Static Library）：分析其引用的外部符号和依赖的其他 .lib
- 递归分析子 .lib 的依赖关系
- 与现有 HTML 报告功能集成，复用树形展示、详情面板等交互功能
- 统一的命令行接口，自动识别文件类型（.exe/.dll/.lib）

## Impact

- Affected specs: `pe-deps-analyzer`（扩展现有规格）
- Affected code: `py/print_exe_deps.py`
- 可能需要新增依赖：解析 COFF 归档格式的库

