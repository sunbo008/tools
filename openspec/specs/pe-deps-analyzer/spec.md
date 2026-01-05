# pe-deps-analyzer Specification

## Purpose
TBD - created by archiving change add-html-report. Update Purpose after archive.
## Requirements
### Requirement: HTML 报告生成

工具 SHALL 默认生成静态 HTML 格式的依赖分析报告，报告为单一自包含文件，包含所有必要的 CSS 和 JavaScript。报告文件名固定为 `report.html`。

#### Scenario: 默认生成 HTML 报告
- **WHEN** 用户执行 `python print_exe_deps.py app.exe D:\output`
- **THEN** 在指定输出目录生成固定文件名 `report.html`

#### Scenario: 报告文件覆盖
- **WHEN** 输出目录已存在 `report.html` 文件
- **THEN** 直接覆盖已有文件，无需提示

#### Scenario: HTML 报告可离线查看
- **WHEN** 用户在无网络环境下用浏览器打开生成的 HTML 文件
- **THEN** 报告完整显示，所有功能正常工作

---

### Requirement: 可折叠依赖树展示

HTML 报告 SHALL 以可交互的树形结构展示依赖关系，支持无限深度，每个节点可独立展开或折叠。

#### Scenario: 节点默认展开状态
- **WHEN** 用户打开 HTML 报告
- **THEN** 第一层依赖节点默认展开，更深层级默认折叠

#### Scenario: 点击节点展开/折叠
- **WHEN** 用户点击有子节点的依赖项
- **THEN** 该节点的子节点列表切换显示/隐藏状态，图标在 `+` 和 `-` 之间切换

#### Scenario: 节点图标标识
- **WHEN** 用户查看依赖树
- **THEN** 节点显示对应图标：`+`（折叠）、`-`（展开）、`·`（无子节点本地DLL）、`S`（系统DLL）、`X`（缺失DLL）

#### Scenario: 循环依赖标记
- **WHEN** 依赖树中存在循环引用
- **THEN** 循环节点显示 "(circular)" 标记且不可继续展开

---

### Requirement: 全局展开/折叠控制

HTML 报告 SHALL 提供全局控制按钮，可一键展开或折叠所有节点。

#### Scenario: 展开所有节点
- **WHEN** 用户点击"展开全部"按钮
- **THEN** 依赖树中所有节点展开显示，所有有子节点的本地 DLL 图标变为 `-`

#### Scenario: 折叠所有节点
- **WHEN** 用户点击"折叠全部"按钮
- **THEN** 依赖树中所有节点折叠，只显示根节点，所有有子节点的本地 DLL 图标变为 `+`

---

### Requirement: 节点详情查看

HTML 报告 SHALL 提供固定平铺的详情面板，与依赖树左右并排显示，鼠标悬停节点时动态显示详细信息。

#### Scenario: 悬停查看 DLL 详细信息
- **WHEN** 用户鼠标悬停在某个 DLL 节点上
- **THEN** 右侧详情面板动态显示该节点信息：文件名、完整路径、类型（本地/系统/缺失）

#### Scenario: 详情面板布局
- **WHEN** 用户查看报告
- **THEN** 详情面板始终可见，与依赖树左右平铺显示

---

### Requirement: 依赖汇总统计

HTML 报告 SHALL 包含依赖统计汇总区域，展示各类 DLL 的数量和分类列表。

#### Scenario: 显示统计数据
- **WHEN** 用户查看报告
- **THEN** 报告顶部显示：本地 DLL 数量、系统 DLL 数量、缺失 DLL 数量、总依赖数

#### Scenario: 分类列表展示
- **WHEN** 用户查看报告汇总区域
- **THEN** 按类型分组显示所有依赖 DLL 列表（本地、系统、缺失）

---

### Requirement: 报告元信息

HTML 报告 SHALL 包含分析的基本信息，包括被分析文件信息和报告生成时间。

#### Scenario: 显示文件信息
- **WHEN** 用户查看报告
- **THEN** 报告头部显示：被分析文件名、完整路径、架构（x86/x64）

#### Scenario: 显示生成时间
- **WHEN** 用户查看报告
- **THEN** 报告显示生成时间戳

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

