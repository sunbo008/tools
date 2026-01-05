## ADDED Requirements

### Requirement: 静态库文件类型识别

工具 SHALL 自动识别 `.lib` 文件类型，区分导入库（Import Library）和静态库（Static Library）。

#### Scenario: 识别导入库
- **WHEN** 用户分析一个与 DLL 配套的导入库文件
- **THEN** 工具识别为导入库类型，提取关联的 DLL 名称

#### Scenario: 识别静态库
- **WHEN** 用户分析一个包含 .obj 目标代码的静态库文件
- **THEN** 工具识别为静态库类型，提取其包含的目标文件和外部符号引用

#### Scenario: 自动文件类型检测
- **WHEN** 用户执行 `python print_exe_deps.py mylib.lib`
- **THEN** 工具自动识别文件为 .lib 格式并选择相应的解析方式

---

### Requirement: 导入库依赖分析

工具 SHALL 分析导入库文件，提取其关联的 DLL 信息。

#### Scenario: 提取关联 DLL
- **WHEN** 用户分析一个导入库文件
- **THEN** 工具显示该导入库关联的 DLL 名称和路径（如果存在）

#### Scenario: 导入库无子依赖
- **WHEN** 导入库仅关联一个 DLL
- **THEN** 依赖树显示该 DLL 为叶子节点，不再递归分析

---

### Requirement: 静态库依赖分析

工具 SHALL 分析静态库文件，提取其引用的外部符号和依赖的其他库文件。

#### Scenario: 提取外部符号引用
- **WHEN** 用户分析一个静态库文件
- **THEN** 工具提取该静态库引用的未定义外部符号

#### Scenario: 推断依赖库
- **WHEN** 静态库引用了其他库提供的符号
- **THEN** 工具尝试通过符号名称推断依赖的 .lib 文件

#### Scenario: 递归分析子库依赖
- **WHEN** 静态库依赖其他 .lib 文件
- **THEN** 工具递归分析子 .lib 的依赖关系，构建完整依赖树

---

### Requirement: 库文件搜索路径

工具 SHALL 支持指定库文件搜索路径，用于定位依赖的 .lib 文件。

#### Scenario: 默认搜索路径
- **WHEN** 用户未指定搜索路径
- **THEN** 工具在被分析文件所在目录搜索依赖库

#### Scenario: 自定义搜索路径
- **WHEN** 用户通过 `-L` 参数指定搜索路径
- **THEN** 工具按指定路径搜索依赖的 .lib 文件

#### Scenario: 多路径搜索
- **WHEN** 用户指定多个搜索路径（多次使用 `-L`）
- **THEN** 工具按顺序在各路径中搜索，返回首个匹配的文件

---

### Requirement: 静态库 HTML 报告集成

工具 SHALL 将 .lib 分析结果集成到现有 HTML 报告框架中。

#### Scenario: 静态库节点图标
- **WHEN** 用户查看 .lib 文件的依赖树
- **THEN** 静态库节点显示 `L` 图标，导入库节点显示 `I` 图标

#### Scenario: 混合依赖树
- **WHEN** 依赖树包含 .lib 和 .dll 混合类型
- **THEN** 报告正确显示各类型节点，使用对应的图标和颜色区分

#### Scenario: 静态库详情面板
- **WHEN** 用户悬停在 .lib 节点上
- **THEN** 详情面板显示：文件名、完整路径、库类型（导入库/静态库）、包含的目标文件数（静态库）

#### Scenario: 静态库统计汇总
- **WHEN** 用户查看报告汇总区域
- **THEN** 显示：静态库数量、导入库数量、总库依赖数


