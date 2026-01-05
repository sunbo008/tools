# 🛠️ Tools - 实用工具脚本集合

一个包含各种实用工具脚本的项目，用于日常开发和系统管理任务。

## 📁 项目结构

```
tools/
├── py/          # Python 脚本
├── sh/          # Shell 脚本 (计划中)
├── bat/         # Windows 批处理脚本 (计划中)
└── README.md    # 本文件
```

## 📋 工具索引

### Python 脚本 (`py/`)

| 脚本名称 | 描述 | 用法 |
|---------|------|------|
| [print_exe_deps.py](#print_exe_depspy) | Windows PE 文件依赖分析与复制工具 | `python print_exe_deps.py <exe文件> [输出目录]` |

---

## 📖 工具详细说明

### print_exe_deps.py

**功能**: 分析 Windows PE 可执行文件（.exe/.dll）和静态库（.lib）的依赖关系，以树状结构展示，并生成可交互的 HTML 报告。

**支持的文件类型**:
- **PE 文件** (.exe, .dll): 分析 DLL 依赖关系
- **静态库** (.lib): 分析导入库和静态库的依赖关系
  - 导入库 (Import Library): 提取关联的 DLL 名称
  - 静态库 (Static Library): 提取依赖的其他库

**特性**:
- 🌲 树状结构展示依赖关系
- 🔍 自动区分本地 DLL 和系统 DLL
- 📦 支持将所有依赖复制到指定目录 (PE 文件)
- 🎯 自动检测并复制 Qt 插件
- ⚡ 支持延迟加载 DLL 分析
- 📚 **支持静态库 (.lib) 分析**
  - 自动识别导入库和静态库
  - 递归分析子库依赖
  - 支持自定义库搜索路径 (`-L`)
- 📊 **生成可交互的 HTML 报告** (report.html)
  - 可折叠的无限深度依赖树
  - 一键展开/折叠所有节点
  - 悬停查看详细信息
  - 依赖统计汇总

**依赖**: `pefile` (首次运行时自动安装)

**用法**:
```bash
python print_exe_deps.py <文件> [输出目录] [选项]
```

**选项**:
| 参数 | 说明 |
|------|------|
| `-s, --system` | 显示系统 DLL (仅 PE 分析) |
| `-d, --depth N` | 设置树的最大显示深度 (默认 5) |
| `-n, --no-copy` | 只分析不复制文件，不生成报告 |
| `-L, --lib-path` | 指定库搜索路径 (可多次使用) |
| `-h, --help` | 显示帮助信息 |

**输出**:
- 终端打印依赖树和汇总信息
- 在输出目录生成 `report.html` 交互式报告
- 复制所有本地依赖到输出目录 (仅 PE 分析，除非使用 `-n`)

**示例**:
```bash
# === PE 文件分析 ===
# 分析并复制依赖到默认目录，生成 HTML 报告
python print_exe_deps.py myapp.exe

# 分析并复制到指定目录
python print_exe_deps.py myapp.exe D:\output

# 只分析，不复制（也不生成报告）
python print_exe_deps.py myapp.exe -n

# 显示系统 DLL
python print_exe_deps.py myapp.exe -s

# === 静态库分析 ===
# 分析静态库
python print_exe_deps.py mylib.lib

# 指定输出目录
python print_exe_deps.py mylib.lib D:\output

# 指定额外的库搜索路径
python print_exe_deps.py mylib.lib D:\output -L C:\SDK\lib -L C:\vcpkg\lib
```

**PE 分析图例**:
- `[+]` / `[-]` 本地/应用 DLL (可展开/折叠)
- `[·]` 本地 DLL (无子依赖)
- `[S]` 系统 DLL
- `[X]` 未找到的 DLL

**静态库分析图例**:
- `[L]` 静态库
- `[I]` 导入库
- `[D]` DLL
- `[X]` 未找到

**HTML 报告预览**:

报告包含以下内容：
- 📋 文件信息（名称、路径、架构/类型、生成时间）
- 📊 依赖统计卡片
- 🌲 可交互依赖树（点击展开/折叠，悬停查看详情）
- 📝 分类依赖列表

---

## 🚀 未来计划

- [ ] 添加更多 Python 工具脚本
- [ ] 添加 Shell 脚本 (`sh/`)
- [ ] 添加 Windows 批处理脚本 (`bat/`)

## 📝 贡献

欢迎提交新的工具脚本！请确保：
1. 脚本有清晰的注释和文档
2. 在本 README 中添加相应的索引条目
3. 遵循现有的目录结构

## 📄 许可证

MIT License

