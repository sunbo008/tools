## ADDED Requirements

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

