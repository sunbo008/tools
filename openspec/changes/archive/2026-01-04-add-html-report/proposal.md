# Change: 添加 HTML 依赖分析报告功能

## Why

当前 `print_exe_deps.py` 只支持终端文本输出，不便于保存、分享和深入分析复杂的依赖关系。用户需要一份可交互的静态 HTML 报告，能够直观地展示完整的依赖树，并支持节点折叠、详情查看等交互功能。

## What Changes

- 新增 HTML 报告生成功能（默认输出到用户指定目录，固定文件名 `report.html`）
- 支持无限深度的依赖树展示（可折叠）
- 添加全局展开/折叠控制按钮
- 详情面板与依赖树左右平铺布局，鼠标悬停节点时动态显示详情
- 树节点使用简洁图标：`+`（折叠）、`-`（展开）、`·`（无子节点）、`S`（系统）、`X`（缺失）
- 报告包含依赖汇总统计

## Impact

- Affected specs: `pe-deps-analyzer` (新建)
- Affected code: `py/print_exe_deps.py`

