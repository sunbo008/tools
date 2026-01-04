# -*- coding: utf-8 -*-
"""
打印 Windows PE 可执行文件的所有依赖 (DLL) 并支持复制到指定目录
以树状结构展示依赖关系
"""

import os
import sys
import shutil

try:
    import pefile
except ImportError:
    print("正在安装 pefile 库...")
    os.system("pip install pefile")
    import pefile


# 系统DLL列表 - 这些不需要复制
SYSTEM_DLLS = {
    'kernel32.dll', 'user32.dll', 'gdi32.dll', 'advapi32.dll', 
    'shell32.dll', 'ole32.dll', 'oleaut32.dll', 'comdlg32.dll',
    'comctl32.dll', 'ws2_32.dll', 'wsock32.dll', 'winmm.dll',
    'winspool.drv', 'version.dll', 'imm32.dll', 'msvcrt.dll',
    'ntdll.dll', 'rpcrt4.dll', 'secur32.dll', 'crypt32.dll',
    'shlwapi.dll', 'setupapi.dll', 'cfgmgr32.dll', 'devobj.dll',
    'wintrust.dll', 'imagehlp.dll', 'psapi.dll', 'userenv.dll',
    'netapi32.dll', 'iphlpapi.dll', 'dnsapi.dll', 'mswsock.dll',
    'uxtheme.dll', 'dwmapi.dll', 'd3d9.dll', 'd3d11.dll',
    'dxgi.dll', 'opengl32.dll', 'glu32.dll', 'dbghelp.dll',
    'bcrypt.dll', 'ncrypt.dll', 'powrprof.dll', 'propsys.dll',
    'winhttp.dll', 'wininet.dll', 'urlmon.dll', 'normaliz.dll',
    'mpr.dll', 'wtsapi32.dll', 'credui.dll', 'cryptui.dll',
}


def get_pe_dependencies(pe_path):
    """获取PE文件的所有直接依赖DLL"""
    if not os.path.exists(pe_path):
        return []
    
    try:
        pe = pefile.PE(pe_path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT']
        ])
    except Exception:
        return []
    
    dependencies = []
    
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore')
            dependencies.append(dll_name)
    
    if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore')
            if dll_name not in dependencies:
                dependencies.append(dll_name)
    
    pe.close()
    return dependencies


def is_system_dll(dll_name, dll_path=None):
    """
    判断是否为系统DLL
    
    Args:
        dll_name: DLL文件名
        dll_path: DLL完整路径 (可选)
    """
    name_lower = dll_name.lower()
    
    # 检查已知系统DLL名称
    if name_lower in SYSTEM_DLLS:
        return True
    
    # api-ms-win-* 和 ext-ms-* 是Windows API集
    if name_lower.startswith('api-ms-win-') or name_lower.startswith('ext-ms-'):
        return True
    
    # 如果提供了路径，检查是否在Windows系统目录下
    if dll_path:
        path_lower = dll_path.lower()
        system_root = os.environ.get('SystemRoot', 'C:\\Windows').lower()
        
        # 检查是否在 Windows 目录下 (System32, SysWOW64, WinSxS 等)
        if path_lower.startswith(system_root):
            return True
        
        # 检查是否在 C:\Windows 下 (兼容不同的 SystemRoot)
        if path_lower.startswith('c:\\windows\\'):
            return True
    
    return False


def find_dll(dll_name, search_paths):
    """在搜索路径中查找DLL"""
    for path in search_paths:
        full_path = os.path.join(path, dll_name)
        if os.path.exists(full_path):
            return full_path
    return None


class DependencyNode:
    """依赖节点"""
    def __init__(self, name, path=None, is_system=False, found=True):
        self.name = name
        self.path = path
        self.is_system = is_system
        self.found = found
        self.children = []  # 子依赖
    
    def add_child(self, child):
        self.children.append(child)


def build_dependency_tree(exe_path, search_paths=None, max_depth=10):
    """
    构建依赖树
    
    Returns:
        (root_node, all_nodes_dict)
    """
    if search_paths is None:
        exe_dir = os.path.dirname(os.path.abspath(exe_path))
        search_paths = [exe_dir]
        system_root = os.environ.get('SystemRoot', 'C:\\Windows')
        search_paths.append(os.path.join(system_root, 'System32'))
        search_paths.append(os.path.join(system_root, 'SysWOW64'))
    
    # 所有节点的缓存 (避免重复创建)
    all_nodes = {}
    
    # 创建根节点
    exe_name = os.path.basename(exe_path)
    root = DependencyNode(exe_name, exe_path, is_system=False, found=True)
    all_nodes[exe_name.lower()] = root
    
    def build_subtree(parent_node, parent_path, depth):
        """递归构建子树"""
        if depth > max_depth:
            return
        
        deps = get_pe_dependencies(parent_path)
        
        for dep_name in deps:
            dep_lower = dep_name.lower()
            dep_path = find_dll(dep_name, search_paths)
            # 判断是否为系统DLL时传入路径
            is_sys = is_system_dll(dep_name, dep_path)
            
            # 检查是否已存在该节点
            if dep_lower in all_nodes:
                # 已存在，添加引用但不重复展开
                existing_node = all_nodes[dep_lower]
                parent_node.add_child(existing_node)
            else:
                # 创建新节点
                new_node = DependencyNode(
                    dep_name, 
                    dep_path, 
                    is_system=is_sys, 
                    found=(dep_path is not None)
                )
                all_nodes[dep_lower] = new_node
                parent_node.add_child(new_node)
                
                # 如果找到了且不是系统DLL，继续递归
                if dep_path and not is_sys:
                    build_subtree(new_node, dep_path, depth + 1)
    
    build_subtree(root, exe_path, 0)
    return root, all_nodes


def print_tree(node, prefix="", is_last=True, visited=None, show_system=False, depth=0, max_print_depth=5):
    """
    打印依赖树
    
    Args:
        node: 当前节点
        prefix: 前缀字符串
        is_last: 是否是最后一个子节点
        visited: 已访问节点集合(用于检测循环引用)
        show_system: 是否显示系统DLL
        depth: 当前深度
        max_print_depth: 最大打印深度
    """
    if visited is None:
        visited = set()
    
    # 构建当前行
    connector = "`-- " if is_last else "|-- "
    
    # 状态标记
    if not node.found:
        status = "[X]"
    elif node.is_system:
        status = "[S]"
    else:
        status = "[+]"
    
    # 检测循环引用
    node_key = node.name.lower()
    is_circular = node_key in visited
    
    if depth == 0:
        print(f"{status} {node.name}")
    else:
        circular_mark = " (circular)" if is_circular else ""
        print(f"{prefix}{connector}{status} {node.name}{circular_mark}")
    
    if is_circular or depth >= max_print_depth:
        if depth >= max_print_depth and node.children:
            new_prefix = prefix + ("    " if is_last else "|   ")
            print(f"{new_prefix}`-- ... ({len(node.children)} more deps)")
        return
    
    visited.add(node_key)
    
    # 过滤子节点
    children_to_show = node.children
    if not show_system:
        children_to_show = [c for c in node.children if not c.is_system]
    
    # 打印子节点
    for i, child in enumerate(children_to_show):
        is_child_last = (i == len(children_to_show) - 1)
        new_prefix = prefix + ("    " if is_last else "|   ")
        print_tree(child, new_prefix, is_child_last, visited.copy(), show_system, depth + 1, max_print_depth)


def print_flat_dependency_list(all_nodes, exe_name):
    """打印扁平化的依赖列表，按类别分组"""
    local_deps = []
    system_deps = []
    missing_deps = []
    
    for name, node in all_nodes.items():
        if name == exe_name.lower():
            continue
        if not node.found:
            missing_deps.append(node)
        elif node.is_system:
            system_deps.append(node)
        else:
            local_deps.append(node)
    
    return local_deps, system_deps, missing_deps


def check_qt_dependency(all_nodes):
    """检查是否依赖Qt库，返回Qt相关信息"""
    qt_dlls = []
    qt_source_dir = None
    
    for name, node in all_nodes.items():
        name_lower = name.lower()
        # 检测 Qt5*Kso.dll 或 Qt5*.dll 或 Qt6*.dll
        if name_lower.startswith('qt5') or name_lower.startswith('qt6'):
            if node.path and not node.is_system:
                qt_dlls.append(node.name)
                if qt_source_dir is None:
                    qt_source_dir = os.path.dirname(node.path)
    
    return qt_dlls, qt_source_dir


def find_qt_plugins_dir(exe_dir):
    """查找Qt插件目录"""
    # 常见的Qt插件目录位置
    possible_paths = [
        os.path.join(exe_dir, 'qt', 'plugins'),
        os.path.join(exe_dir, 'plugins'),
        os.path.join(exe_dir, 'Qt', 'plugins'),
        os.path.join(exe_dir, '..', 'qt', 'plugins'),
        os.path.join(exe_dir, '..', 'plugins'),
    ]
    
    for path in possible_paths:
        if os.path.isdir(path):
            return os.path.abspath(path)
    
    return None


def copy_qt_plugins(qt_plugins_dir, output_dir):
    """复制Qt插件到输出目录"""
    copied_count = 0
    
    # 必须的插件子目录
    required_plugins = ['platforms']
    # 可选但推荐的插件子目录
    optional_plugins = ['imageformats', 'iconengines', 'styles', 'printsupport']
    
    all_plugins = required_plugins + optional_plugins
    
    for plugin_subdir in all_plugins:
        src_dir = os.path.join(qt_plugins_dir, plugin_subdir)
        if not os.path.isdir(src_dir):
            continue
        
        dest_dir = os.path.join(output_dir, plugin_subdir)
        
        try:
            if os.path.exists(dest_dir):
                shutil.rmtree(dest_dir)
            shutil.copytree(src_dir, dest_dir)
            
            # 统计复制的文件数
            file_count = sum(1 for f in os.listdir(dest_dir) if os.path.isfile(os.path.join(dest_dir, f)))
            copied_count += file_count
            print(f"  [复制] {plugin_subdir}/ ({file_count} 个文件)")
        except Exception as e:
            print(f"  [失败] {plugin_subdir}/: {e}")
    
    return copied_count


def copy_dependencies(exe_path, all_nodes, output_dir):
    """复制exe和所有本地依赖到指定目录"""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"\n[创建目录] {output_dir}")
    
    copied_files = []
    failed_files = []
    
    # 复制exe本身
    exe_name = os.path.basename(exe_path)
    dest_exe = os.path.join(output_dir, exe_name)
    try:
        shutil.copy2(exe_path, dest_exe)
        copied_files.append(exe_name)
        print(f"  [复制] {exe_name}")
    except Exception as e:
        failed_files.append((exe_name, str(e)))
        print(f"  [失败] {exe_name}: {e}")
    
    # 复制本地依赖
    for name, node in all_nodes.items():
        if node.is_system or not node.found or not node.path:
            continue
        if name == exe_name.lower():
            continue
        
        src_path = node.path
        dest_path = os.path.join(output_dir, node.name)
        
        if os.path.normpath(src_path).lower() == os.path.normpath(dest_path).lower():
            continue
        
        try:
            shutil.copy2(src_path, dest_path)
            copied_files.append(node.name)
            print(f"  [复制] {node.name}")
        except Exception as e:
            failed_files.append((node.name, str(e)))
            print(f"  [失败] {node.name}: {e}")
    
    # 检查Qt依赖并复制插件
    qt_dlls, qt_source_dir = check_qt_dependency(all_nodes)
    if qt_dlls:
        print(f"\n  [Qt依赖] 检测到 {len(qt_dlls)} 个Qt库")
        
        # 查找Qt插件目录
        exe_dir = os.path.dirname(exe_path)
        qt_plugins_dir = find_qt_plugins_dir(exe_dir)
        
        if qt_plugins_dir:
            print(f"  [Qt插件] 源目录: {qt_plugins_dir}")
            plugin_count = copy_qt_plugins(qt_plugins_dir, output_dir)
            if plugin_count > 0:
                print(f"  [Qt插件] 共复制 {plugin_count} 个插件文件")
        else:
            print(f"  [警告] 未找到Qt插件目录，程序可能无法运行!")
            print(f"         请确保 platforms/qwindows.dll 存在于输出目录")
    
    return copied_files, failed_files


def print_help():
    """打印帮助信息"""
    print("用法: python print_exe_deps.py <exe/dll文件> [输出目录] [选项]")
    print("\n位置参数:")
    print("  <exe/dll文件>      要分析的可执行文件或DLL")
    print("  [输出目录]         复制依赖文件的目标目录 (可选)")
    print("\n选项:")
    print("  -s, --system       显示系统DLL")
    print("  -d, --depth N      设置树的最大显示深度 (默认5)")
    print("  -n, --no-copy      只分析不复制文件")
    print("  -h, --help         显示帮助")
    print("\n示例:")
    print("  python print_exe_deps.py myapp.exe")
    print("  python print_exe_deps.py myapp.exe D:\\output")
    print("  python print_exe_deps.py myapp.dll D:\\output -s")
    print("  python print_exe_deps.py myapp.exe -n")
    print("\n图例:")
    print("  [+] 本地/应用DLL (已找到)")
    print("  [S] 系统DLL")
    print("  [X] 未找到的DLL")


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 解析参数
    exe_path = None
    output_dir = None
    show_system = False
    max_depth = 5
    no_copy = False
    positional_args = []
    
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ('-s', '--system'):
            show_system = True
        elif arg in ('-d', '--depth'):
            if i + 1 < len(args):
                max_depth = int(args[i + 1])
                i += 2
                continue
        elif arg in ('-n', '--no-copy'):
            no_copy = True
        elif arg in ('-h', '--help'):
            print_help()
            return 0
        elif not arg.startswith('-'):
            positional_args.append(arg)
        i += 1
    
    # 处理位置参数
    if len(positional_args) >= 1:
        # 第一个参数: exe/dll文件
        arg = positional_args[0]
        if os.path.exists(arg):
            exe_path = os.path.abspath(arg)
        elif os.path.exists(os.path.join(script_dir, arg)):
            exe_path = os.path.join(script_dir, arg)
        else:
            print(f"错误: 文件不存在 - {arg}")
            return 1
    
    if len(positional_args) >= 2:
        # 第二个参数: 输出目录
        output_dir = os.path.abspath(positional_args[1])
    
    # 如果没有提供exe路径，显示帮助
    if exe_path is None:
        print("错误: 请指定要分析的exe或dll文件\n")
        print_help()
        return 1
    
    # 默认输出目录: 与exe同目录下，以exe名称命名的文件夹
    if output_dir is None:
        exe_dir = os.path.dirname(exe_path)
        exe_name = os.path.splitext(os.path.basename(exe_path))[0]
        output_dir = os.path.join(exe_dir, exe_name)
    
    # 检查exe是否存在
    if not os.path.exists(exe_path):
        print(f"错误: 文件不存在 - {exe_path}")
        return 1
    
    # 获取PE信息
    print("=" * 80)
    print(f"分析文件: {exe_path}")
    print("=" * 80)
    
    try:
        pe = pefile.PE(exe_path, fast_load=True)
        machine = pe.FILE_HEADER.Machine
        if machine == 0x14c:
            arch = "x86 (32位)"
        elif machine == 0x8664:
            arch = "x64 (64位)"
        else:
            arch = f"未知 (0x{machine:x})"
        print(f"架构: {arch}")
        pe.close()
    except:
        pass
    
    print(f"\n正在构建依赖树...")
    
    # 构建依赖树
    root, all_nodes = build_dependency_tree(exe_path)
    
    # 打印依赖树
    print("\n" + "=" * 80)
    print("依赖树 (只显示本地DLL)")
    print("图例: [+]=本地DLL  [S]=系统DLL  [X]=未找到")
    print("=" * 80 + "\n")
    
    print_tree(root, show_system=show_system, max_print_depth=max_depth)
    
    # 获取分类统计
    exe_name = os.path.basename(exe_path)
    local_deps, system_deps, missing_deps = print_flat_dependency_list(all_nodes, exe_name)
    
    # 打印汇总
    print("\n" + "=" * 80)
    print("依赖汇总")
    print("=" * 80)
    
    print(f"\n[本地/应用DLL] 共 {len(local_deps)} 个:")
    for node in sorted(local_deps, key=lambda x: x.name.lower()):
        print(f"  {node.name}")
    
    if show_system:
        print(f"\n[系统DLL] 共 {len(system_deps)} 个:")
        for node in sorted(system_deps, key=lambda x: x.name.lower()):
            print(f"  {node.name}")
    else:
        print(f"\n[系统DLL] 共 {len(system_deps)} 个 (使用 -s 参数显示详情)")
    
    if missing_deps:
        print(f"\n[未找到] 共 {len(missing_deps)} 个:")
        for node in sorted(missing_deps, key=lambda x: x.name.lower())[:20]:
            print(f"  {node.name}")
        if len(missing_deps) > 20:
            print(f"  ... 还有 {len(missing_deps) - 20} 个")
    
    print(f"\n总计: {len(all_nodes) - 1} 个依赖")
    
    # 复制文件
    if not no_copy:
        print("\n" + "=" * 80)
        print(f"复制文件到: {output_dir}")
        print("=" * 80)
        copied, failed = copy_dependencies(exe_path, all_nodes, output_dir)
        
        print(f"\n复制完成: {len(copied)} 个文件")
        if failed:
            print(f"失败: {len(failed)} 个")
        print(f"输出目录: {output_dir}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
