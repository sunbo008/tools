# -*- coding: utf-8 -*-
"""
打印 Windows PE 可执行文件和静态库的所有依赖并支持复制到指定目录
以树状结构展示依赖关系，并生成可交互的 HTML 报告

支持的文件类型：
- PE 可执行文件 (.exe, .dll)
- 静态库 (.lib) - 包括导入库和静态库
"""

import os
import sys
import shutil
import json
import struct
import subprocess
from datetime import datetime

try:
    import pefile
except ImportError:
    print("正在安装 pefile 库...")
    os.system("pip install pefile")
    import pefile


# COFF 归档文件魔数
COFF_ARCHIVE_MAGIC = b'!<arch>\n'


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


# ============================================================================
# .lib 文件解析功能
# ============================================================================

def is_lib_file(file_path):
    """检查文件是否为 .lib 文件"""
    return file_path.lower().endswith('.lib')


def is_coff_archive(file_path):
    """检查文件是否为 COFF 归档格式（.lib 文件）"""
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(8)
            return magic == COFF_ARCHIVE_MAGIC
    except Exception:
        return False


def parse_lib_file(lib_path):
    """
    解析 .lib 文件，返回库信息
    
    Returns:
        dict: {
            'type': 'import' | 'static',  # 库类型
            'dll_name': str | None,        # 导入库关联的 DLL 名称
            'members': list,               # 成员文件列表
            'symbols': list,               # 符号列表
            'dependencies': list,          # 依赖的库名称
        }
    """
    if not is_coff_archive(lib_path):
        return None
    
    result = {
        'type': 'unknown',
        'dll_name': None,
        'members': [],
        'symbols': [],
        'dependencies': [],
    }
    
    # 尝试使用 dumpbin 解析（更准确）
    dumpbin_result = parse_lib_with_dumpbin(lib_path)
    if dumpbin_result:
        return dumpbin_result
    
    # 回退到纯 Python 解析
    return parse_lib_pure_python(lib_path)


def parse_lib_with_dumpbin(lib_path):
    """使用 dumpbin.exe 解析 .lib 文件"""
    try:
        # 尝试运行 dumpbin
        result = subprocess.run(
            ['dumpbin', '/headers', '/archivemembers', lib_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            return None
        
        output = result.stdout
        
        lib_info = {
            'type': 'static',
            'dll_name': None,
            'members': [],
            'symbols': [],
            'dependencies': [],
        }
        
        # 解析输出
        lines = output.split('\n')
        in_archive_members = False
        
        for line in lines:
            line = line.strip()
            
            # 检测导入库
            if 'DLL name' in line:
                # 这是导入库
                lib_info['type'] = 'import'
                # 提取 DLL 名称
                parts = line.split(':')
                if len(parts) > 1:
                    lib_info['dll_name'] = parts[1].strip()
            
            # 收集成员文件
            if 'Archive member name at' in line:
                in_archive_members = True
            elif in_archive_members and line.startswith('/'):
                # 成员名称
                member_name = line.split()[0] if line.split() else line
                if member_name and not member_name.startswith('//'):
                    lib_info['members'].append(member_name)
        
        return lib_info
        
    except FileNotFoundError:
        # dumpbin 不可用
        return None
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def parse_lib_pure_python(lib_path):
    """
    使用纯 Python 解析 .lib 文件
    解析 COFF 归档格式
    """
    lib_info = {
        'type': 'static',
        'dll_name': None,
        'members': [],
        'symbols': [],
        'dependencies': [],
    }
    
    try:
        with open(lib_path, 'rb') as f:
            # 跳过魔数
            f.read(8)
            
            # 解析归档成员
            while True:
                # 读取成员头（60字节）
                header = f.read(60)
                if len(header) < 60:
                    break
                
                # 解析成员头
                name = header[0:16].decode('ascii', errors='ignore').strip()
                size_str = header[48:58].decode('ascii', errors='ignore').strip()
                
                try:
                    size = int(size_str)
                except ValueError:
                    break
                
                # 处理成员名称
                if name.startswith('/'):
                    # 特殊成员（符号表等）
                    if name == '/':
                        # 第一个链接器成员（符号表）
                        pass
                    elif name == '//':
                        # 长名称表
                        pass
                else:
                    # 普通成员
                    clean_name = name.rstrip('/')
                    if clean_name:
                        lib_info['members'].append(clean_name)
                
                # 读取成员内容
                content = f.read(size)
                
                # 检查是否为导入库成员
                if len(content) > 20:
                    # 导入库的成员通常很小，包含导入描述符
                    # 检查是否包含 DLL 名称的特征
                    try:
                        content_str = content.decode('ascii', errors='ignore')
                        if '.dll' in content_str.lower():
                            # 可能是导入库
                            lib_info['type'] = 'import'
                            # 尝试提取 DLL 名称
                            for part in content_str.split('\x00'):
                                if part.lower().endswith('.dll'):
                                    lib_info['dll_name'] = part
                                    break
                    except Exception:
                        pass
                
                # 对齐到偶数边界
                if size % 2 == 1:
                    f.read(1)
        
        return lib_info
        
    except Exception as e:
        return {
            'type': 'unknown',
            'dll_name': None,
            'members': [],
            'symbols': [],
            'dependencies': [],
            'error': str(e)
        }


def find_lib(lib_name, search_paths):
    """在搜索路径中查找 .lib 文件"""
    for path in search_paths:
        full_path = os.path.join(path, lib_name)
        if os.path.exists(full_path):
            return full_path
        # 尝试添加 .lib 扩展名
        if not lib_name.lower().endswith('.lib'):
            full_path_with_ext = os.path.join(path, lib_name + '.lib')
            if os.path.exists(full_path_with_ext):
                return full_path_with_ext
    return None


class LibDependencyNode:
    """静态库依赖节点"""
    def __init__(self, name, path=None, lib_type='unknown', found=True):
        self.name = name
        self.path = path
        self.lib_type = lib_type  # 'import', 'static', 'dll', 'unknown'
        self.found = found
        self.children = []
        self.dll_name = None  # 导入库关联的 DLL 名称
        self.member_count = 0  # 静态库包含的成员数
    
    def add_child(self, child):
        self.children.append(child)


def build_lib_dependency_tree(lib_path, search_paths=None, max_depth=10):
    """
    构建 .lib 文件的依赖树
    
    Returns:
        (root_node, all_nodes_dict)
    """
    if search_paths is None:
        lib_dir = os.path.dirname(os.path.abspath(lib_path))
        search_paths = [lib_dir]
    
    all_nodes = {}
    
    # 解析根 .lib 文件
    lib_name = os.path.basename(lib_path)
    lib_info = parse_lib_file(lib_path)
    
    if lib_info is None:
        # 无法解析
        root = LibDependencyNode(lib_name, lib_path, 'unknown', found=True)
        all_nodes[lib_name.lower()] = root
        return root, all_nodes
    
    # 创建根节点
    root = LibDependencyNode(
        lib_name, 
        lib_path, 
        lib_type=lib_info['type'],
        found=True
    )
    root.dll_name = lib_info.get('dll_name')
    root.member_count = len(lib_info.get('members', []))
    all_nodes[lib_name.lower()] = root
    
    def build_subtree(parent_node, parent_path, lib_info, depth):
        """递归构建子树"""
        if depth > max_depth:
            return
        
        # 如果是导入库，添加关联的 DLL 作为子节点
        if lib_info['type'] == 'import' and lib_info.get('dll_name'):
            dll_name = lib_info['dll_name']
            dll_lower = dll_name.lower()
            
            if dll_lower not in all_nodes:
                # 查找 DLL
                dll_path = find_dll(dll_name, search_paths)
                is_sys = is_system_dll(dll_name, dll_path)
                
                dll_node = LibDependencyNode(
                    dll_name,
                    dll_path,
                    lib_type='dll',
                    found=(dll_path is not None)
                )
                all_nodes[dll_lower] = dll_node
                parent_node.add_child(dll_node)
        
        # 如果是静态库，分析其依赖
        elif lib_info['type'] == 'static':
            # 从依赖列表中查找
            for dep_name in lib_info.get('dependencies', []):
                dep_lower = dep_name.lower()
                
                if dep_lower in all_nodes:
                    parent_node.add_child(all_nodes[dep_lower])
                else:
                    dep_path = find_lib(dep_name, search_paths)
                    
                    if dep_path:
                        dep_info = parse_lib_file(dep_path)
                        dep_type = dep_info['type'] if dep_info else 'unknown'
                    else:
                        dep_info = None
                        dep_type = 'unknown'
                    
                    dep_node = LibDependencyNode(
                        dep_name,
                        dep_path,
                        lib_type=dep_type,
                        found=(dep_path is not None)
                    )
                    
                    if dep_info:
                        dep_node.dll_name = dep_info.get('dll_name')
                        dep_node.member_count = len(dep_info.get('members', []))
                    
                    all_nodes[dep_lower] = dep_node
                    parent_node.add_child(dep_node)
                    
                    # 递归分析
                    if dep_path and dep_info:
                        build_subtree(dep_node, dep_path, dep_info, depth + 1)
    
    build_subtree(root, lib_path, lib_info, 0)
    return root, all_nodes


def lib_dependency_tree_to_json(node, visited=None):
    """将 .lib 依赖树转换为 JSON 可序列化的字典格式"""
    if visited is None:
        visited = set()
    
    node_key = node.name.lower()
    is_circular = node_key in visited
    
    # 确定节点类型
    if not node.found:
        node_type = "missing"
    elif node.lib_type == 'import':
        node_type = "lib-import"
    elif node.lib_type == 'static':
        node_type = "lib-static"
    elif node.lib_type == 'dll':
        node_type = "dll"
    else:
        node_type = "unknown"
    
    result = {
        "name": node.name,
        "path": node.path or "",
        "type": node_type,
        "circular": is_circular,
        "children": [],
        "dll_name": node.dll_name,
        "member_count": node.member_count,
    }
    
    if not is_circular:
        visited.add(node_key)
        for child in node.children:
            result["children"].append(lib_dependency_tree_to_json(child, visited))
    
    return result


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


def dependency_tree_to_json(node, visited=None):
    """将依赖树转换为 JSON 可序列化的字典格式
    
    使用共享的 visited 集合避免同一个 DLL 在树中重复展开子节点。
    当某个 DLL 已经在树中展开过，后续出现时标记为 circular 并不再展开。
    """
    if visited is None:
        visited = set()
    
    node_key = node.name.lower()
    is_circular = node_key in visited
    
    # 确定节点类型
    if not node.found:
        node_type = "missing"
    elif node.is_system:
        node_type = "system"
    else:
        node_type = "local"
    
    result = {
        "name": node.name,
        "path": node.path or "",
        "type": node_type,
        "circular": is_circular,
        "children": []
    }
    
    if not is_circular:
        visited.add(node_key)
        for child in node.children:
            # 使用共享的 visited 集合，避免同一 DLL 重复展开
            result["children"].append(dependency_tree_to_json(child, visited))
    
    return result


def generate_html_report(exe_path, arch, root, all_nodes, local_deps, system_deps, missing_deps, output_dir):
    """生成 HTML 依赖分析报告"""
    
    # 构建数据
    tree_data = dependency_tree_to_json(root)
    
    report_data = {
        "exe_info": {
            "name": os.path.basename(exe_path),
            "path": exe_path,
            "arch": arch
        },
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tree": tree_data,
        "summary": {
            "local_count": len(local_deps),
            "system_count": len(system_deps),
            "missing_count": len(missing_deps),
            "total": len(all_nodes) - 1
        },
        "dependencies": {
            "local": [{"name": n.name, "path": n.path or ""} for n in sorted(local_deps, key=lambda x: x.name.lower())],
            "system": [{"name": n.name, "path": n.path or ""} for n in sorted(system_deps, key=lambda x: x.name.lower())],
            "missing": [{"name": n.name, "path": ""} for n in sorted(missing_deps, key=lambda x: x.name.lower())]
        }
    }
    
    html_content = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>依赖分析报告 - {report_data["exe_info"]["name"]}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif;
            background: #1e1e1e;
            color: #d4d4d4;
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        h1 {{
            color: #569cd6;
            margin-bottom: 10px;
            font-size: 24px;
        }}
        
        h2 {{
            color: #4ec9b0;
            margin: 20px 0 10px;
            font-size: 18px;
            border-bottom: 1px solid #3c3c3c;
            padding-bottom: 5px;
        }}
        
        .header {{
            background: #252526;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        
        .header-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        
        .info-item {{
            background: #2d2d2d;
            padding: 10px 15px;
            border-radius: 4px;
        }}
        
        .info-label {{
            color: #808080;
            font-size: 12px;
            margin-bottom: 3px;
        }}
        
        .info-value {{
            color: #d4d4d4;
            word-break: break-all;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        
        .summary-card {{
            background: #252526;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }}
        
        .summary-card.local {{ border-left: 4px solid #4ec9b0; }}
        .summary-card.system {{ border-left: 4px solid #569cd6; }}
        .summary-card.missing {{ border-left: 4px solid #f14c4c; }}
        .summary-card.total {{ border-left: 4px solid #dcdcaa; }}
        
        .summary-number {{
            font-size: 32px;
            font-weight: bold;
        }}
        
        .summary-card.local .summary-number {{ color: #4ec9b0; }}
        .summary-card.system .summary-number {{ color: #569cd6; }}
        .summary-card.missing .summary-number {{ color: #f14c4c; }}
        .summary-card.total .summary-number {{ color: #dcdcaa; }}
        
        .summary-label {{
            color: #808080;
            font-size: 14px;
        }}
        
        .controls {{
            margin-bottom: 15px;
        }}
        
        .btn {{
            background: #0e639c;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            margin-right: 10px;
            font-size: 14px;
        }}
        
        .btn:hover {{
            background: #1177bb;
        }}
        
        .tree-section {{
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }}
        
        .tree-container {{
            flex: 1;
            min-width: 0;
            background: #252526;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            max-height: 600px;
            overflow-y: auto;
        }}
        
        .detail-panel {{
            width: 320px;
            flex-shrink: 0;
            background: #252526;
            border-radius: 8px;
            height: fit-content;
            position: sticky;
            top: 20px;
        }}
        
        .tree {{
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 14px;
        }}
        
        .tree ul {{
            list-style: none;
            padding-left: 24px;
        }}
        
        .tree > ul {{
            padding-left: 0;
        }}
        
        .tree li {{
            position: relative;
            padding: 3px 0;
        }}
        
        .tree-node {{
            display: inline-flex;
            align-items: center;
            cursor: pointer;
            padding: 2px 6px;
            border-radius: 3px;
        }}
        
        .tree-node:hover {{
            background: #37373d;
        }}
        
        .tree-icon {{
            cursor: pointer;
            width: 18px;
            height: 18px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            margin-right: 6px;
            font-size: 12px;
            font-weight: bold;
            border-radius: 3px;
        }}
        
        .tree-icon.local {{
            background: #4ec9b0;
            color: #1e1e1e;
        }}
        
        .tree-icon.system {{
            background: #569cd6;
            color: #1e1e1e;
        }}
        
        .tree-icon.missing {{
            background: #f14c4c;
            color: #1e1e1e;
        }}
        
        .tree-name {{
            color: #d4d4d4;
        }}
        
        .tree-name.local {{ color: #4ec9b0; }}
        .tree-name.system {{ color: #569cd6; }}
        .tree-name.missing {{ color: #f14c4c; }}
        
        .circular-mark {{
            color: #ce9178;
            font-size: 12px;
            margin-left: 8px;
        }}
        
        .tree ul.collapsed {{
            display: none;
        }}
        
        .detail-header {{
            background: #2d2d2d;
            padding: 12px 16px;
            border-radius: 8px 8px 0 0;
        }}
        
        .detail-title {{
            color: #569cd6;
            font-size: 16px;
            font-weight: 600;
        }}
        
        .detail-content {{
            padding: 16px;
        }}
        
        .detail-placeholder {{
            color: #808080;
            text-align: center;
            padding: 40px 20px;
        }}
        
        .detail-item {{
            margin-bottom: 15px;
        }}
        
        .detail-label {{
            color: #808080;
            font-size: 12px;
            margin-bottom: 3px;
        }}
        
        .detail-value {{
            color: #d4d4d4;
            word-break: break-all;
            font-family: 'Consolas', monospace;
        }}
        
        .deps-section {{
            background: #252526;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        
        .deps-list {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 8px;
        }}
        
        .deps-item {{
            background: #2d2d2d;
            padding: 8px 12px;
            border-radius: 4px;
            font-family: 'Consolas', monospace;
            font-size: 13px;
            cursor: pointer;
        }}
        
        .deps-item:hover {{
            background: #37373d;
        }}
        
        .deps-item.local {{ border-left: 3px solid #4ec9b0; }}
        .deps-item.system {{ border-left: 3px solid #569cd6; }}
        .deps-item.missing {{ border-left: 3px solid #f14c4c; }}
        
        .detail-type-badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }}
        
        .detail-type-badge.local {{
            background: #4ec9b0;
            color: #1e1e1e;
        }}
        
        .detail-type-badge.system {{
            background: #569cd6;
            color: #1e1e1e;
        }}
        
        .detail-type-badge.missing {{
            background: #f14c4c;
            color: #1e1e1e;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 PE 依赖分析报告</h1>
            <div class="header-info">
                <div class="info-item">
                    <div class="info-label">文件名</div>
                    <div class="info-value" id="exe-name"></div>
                </div>
                <div class="info-item">
                    <div class="info-label">完整路径</div>
                    <div class="info-value" id="exe-path"></div>
                </div>
                <div class="info-item">
                    <div class="info-label">架构</div>
                    <div class="info-value" id="exe-arch"></div>
                </div>
                <div class="info-item">
                    <div class="info-label">生成时间</div>
                    <div class="info-value" id="generated-at"></div>
                </div>
            </div>
        </div>
        
        <div class="summary">
            <div class="summary-card local">
                <div class="summary-number" id="local-count">0</div>
                <div class="summary-label">本地 DLL</div>
            </div>
            <div class="summary-card system">
                <div class="summary-number" id="system-count">0</div>
                <div class="summary-label">系统 DLL</div>
            </div>
            <div class="summary-card missing">
                <div class="summary-number" id="missing-count">0</div>
                <div class="summary-label">缺失 DLL</div>
            </div>
            <div class="summary-card total">
                <div class="summary-number" id="total-count">0</div>
                <div class="summary-label">总依赖</div>
            </div>
        </div>
        
        <h2>🌲 依赖树</h2>
        <div class="controls">
            <button class="btn" onclick="expandAll()">展开全部</button>
            <button class="btn" onclick="collapseAll()">折叠全部</button>
        </div>
        <div class="tree-section">
            <div class="tree-container">
                <div class="tree" id="tree"></div>
            </div>
            <div class="detail-panel" id="detail-panel">
                <div class="detail-header">
                    <span class="detail-title">📄 详细信息</span>
                </div>
                <div class="detail-content" id="detail-content">
                    <div class="detail-placeholder">点击左侧节点查看详情</div>
                </div>
            </div>
        </div>
        
        <h2>📋 本地 DLL 列表</h2>
        <div class="deps-section">
            <div class="deps-list" id="local-deps"></div>
        </div>
        
        <h2>🔧 系统 DLL 列表</h2>
        <div class="deps-section">
            <div class="deps-list" id="system-deps"></div>
        </div>
        
        <div id="missing-section" style="display: none;">
            <h2>⚠️ 缺失 DLL 列表</h2>
            <div class="deps-section">
                <div class="deps-list" id="missing-deps"></div>
            </div>
        </div>
    </div>
    
    <script>
        const DATA = {json.dumps(report_data, ensure_ascii=False)};
        
        function init() {{
            // 填充头部信息
            document.getElementById('exe-name').textContent = DATA.exe_info.name;
            document.getElementById('exe-path').textContent = DATA.exe_info.path;
            document.getElementById('exe-arch').textContent = DATA.exe_info.arch;
            document.getElementById('generated-at').textContent = DATA.generated_at;
            
            // 填充统计
            document.getElementById('local-count').textContent = DATA.summary.local_count;
            document.getElementById('system-count').textContent = DATA.summary.system_count;
            document.getElementById('missing-count').textContent = DATA.summary.missing_count;
            document.getElementById('total-count').textContent = DATA.summary.total;
            
            // 渲染依赖树
            document.getElementById('tree').innerHTML = '<ul>' + renderTree(DATA.tree, 0) + '</ul>';
            
            // 渲染依赖列表
            renderDepsList('local-deps', DATA.dependencies.local, 'local');
            renderDepsList('system-deps', DATA.dependencies.system, 'system');
            
            if (DATA.dependencies.missing.length > 0) {{
                document.getElementById('missing-section').style.display = 'block';
                renderDepsList('missing-deps', DATA.dependencies.missing, 'missing');
            }}
        }}
        
        function renderTree(node, depth) {{
            const hasChildren = node.children && node.children.length > 0;
            const isCollapsed = depth > 0;
            
            // 图标：本地DLL有子节点时用+/-表示展开状态，无子节点用·，系统DLL用S，缺失用X
            let iconLabel;
            if (node.type === 'local') {{
                if (hasChildren) {{
                    iconLabel = isCollapsed ? '+' : '-';
                }} else {{
                    iconLabel = '·';
                }}
            }} else if (node.type === 'system') {{
                iconLabel = 'S';
            }} else {{
                iconLabel = 'X';
            }}
            
            const circularMark = node.circular ? '<span class="circular-mark">(circular)</span>' : '';
            
            let html = '<li>';
            html += '<span class="tree-node" onclick="toggleNode(this)" onmouseenter="hoverNode(this)" data-name="' + escapeHtml(node.name) + '" data-path="' + escapeHtml(node.path) + '" data-type="' + node.type + '" data-has-children="' + hasChildren + '">';
            html += '<span class="tree-icon ' + node.type + '">' + iconLabel + '</span>';
            html += '<span class="tree-name ' + node.type + '">' + escapeHtml(node.name) + '</span>';
            html += circularMark;
            html += '</span>';
            
            if (hasChildren && !node.circular) {{
                html += '<ul' + (isCollapsed ? ' class="collapsed"' : '') + '>';
                for (const child of node.children) {{
                    html += renderTree(child, depth + 1);
                }}
                html += '</ul>';
            }}
            
            html += '</li>';
            return html;
        }}
        
        function renderDepsList(containerId, deps, type) {{
            const container = document.getElementById(containerId);
            if (deps.length === 0) {{
                container.innerHTML = '<div style="color: #808080;">无</div>';
                return;
            }}
            container.innerHTML = deps.map(d => 
                '<div class="deps-item ' + type + '" onmouseenter="showDetail(\\'' + escapeHtml(d.name) + '\\', \\'' + escapeHtml(d.path) + '\\', \\'' + type + '\\')">' + 
                escapeHtml(d.name) + '</div>'
            ).join('');
        }}
        
        function escapeHtml(text) {{
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML.replace(/'/g, "\\\\'").replace(/"/g, '&quot;');
        }}
        
        function toggleNode(element) {{
            const li = element.parentElement;
            const childUl = li.querySelector(':scope > ul');
            const icon = element.querySelector('.tree-icon');
            const nodeType = element.dataset.type;
            const hasChildren = element.dataset.hasChildren === 'true';
            
            if (childUl) {{
                childUl.classList.toggle('collapsed');
                // 只有本地 DLL 才切换 +/-
                if (nodeType === 'local' && hasChildren) {{
                    icon.textContent = childUl.classList.contains('collapsed') ? '+' : '-';
                }}
            }}
        }}
        
        function hoverNode(element) {{
            // 显示详情
            const name = element.dataset.name;
            const path = element.dataset.path;
            const type = element.dataset.type;
            showDetail(name, path, type);
        }}
        
        function showDetail(name, path, type) {{
            const typeLabels = {{ local: '本地 DLL', system: '系统 DLL', missing: '缺失 DLL' }};
            const content = document.getElementById('detail-content');
            content.innerHTML = `
                <div class="detail-item">
                    <div class="detail-label">文件名</div>
                    <div class="detail-value">${{escapeHtmlDisplay(name)}}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">完整路径</div>
                    <div class="detail-value">${{escapeHtmlDisplay(path) || '(未找到)'}}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">类型</div>
                    <div class="detail-value"><span class="detail-type-badge ${{type}}">${{typeLabels[type] || type}}</span></div>
                </div>
            `;
        }}
        
        function escapeHtmlDisplay(text) {{
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }}
        
        function expandAll() {{
            document.querySelectorAll('.tree ul.collapsed').forEach(ul => {{
                ul.classList.remove('collapsed');
            }});
            // 更新本地 DLL 图标为 -
            document.querySelectorAll('.tree .tree-node[data-type="local"][data-has-children="true"] .tree-icon').forEach(icon => {{
                icon.textContent = '-';
            }});
        }}
        
        function collapseAll() {{
            document.querySelectorAll('.tree ul').forEach((ul, index) => {{
                if (index > 0) ul.classList.add('collapsed');
            }});
            // 更新本地 DLL 图标为 +（包括根节点）
            document.querySelectorAll('.tree .tree-node[data-type="local"][data-has-children="true"] .tree-icon').forEach(icon => {{
                icon.textContent = '+';
            }});
        }}
        
        init();
    </script>
</body>
</html>'''
    
    # 写入文件
    report_path = os.path.join(output_dir, 'report.html')
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return report_path


def generate_lib_html_report(lib_path, lib_info, root, all_nodes, static_libs, import_libs, dlls, missing, output_dir):
    """生成 .lib 文件的 HTML 依赖分析报告"""
    
    # 构建数据
    tree_data = lib_dependency_tree_to_json(root)
    
    lib_type_str = "导入库" if lib_info['type'] == 'import' else "静态库"
    
    report_data = {
        "lib_info": {
            "name": os.path.basename(lib_path),
            "path": lib_path,
            "type": lib_type_str,
            "dll_name": lib_info.get('dll_name', ''),
            "member_count": len(lib_info.get('members', []))
        },
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tree": tree_data,
        "summary": {
            "static_count": len(static_libs),
            "import_count": len(import_libs),
            "dll_count": len(dlls),
            "missing_count": len(missing),
            "total": len(all_nodes) - 1
        },
        "dependencies": {
            "static": [{"name": n.name, "path": n.path or "", "member_count": n.member_count} for n in sorted(static_libs, key=lambda x: x.name.lower())],
            "import": [{"name": n.name, "path": n.path or "", "dll_name": n.dll_name or ""} for n in sorted(import_libs, key=lambda x: x.name.lower())],
            "dll": [{"name": n.name, "path": n.path or ""} for n in sorted(dlls, key=lambda x: x.name.lower())],
            "missing": [{"name": n.name, "path": ""} for n in sorted(missing, key=lambda x: x.name.lower())]
        }
    }
    
    html_content = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>静态库依赖分析报告 - {report_data["lib_info"]["name"]}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif;
            background: #1e1e1e;
            color: #d4d4d4;
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        h1 {{
            color: #569cd6;
            margin-bottom: 10px;
            font-size: 24px;
        }}
        
        h2 {{
            color: #4ec9b0;
            margin: 20px 0 10px;
            font-size: 18px;
            border-bottom: 1px solid #3c3c3c;
            padding-bottom: 5px;
        }}
        
        .header {{
            background: #252526;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        
        .header-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        
        .info-item {{
            background: #2d2d2d;
            padding: 10px 15px;
            border-radius: 4px;
        }}
        
        .info-label {{
            color: #808080;
            font-size: 12px;
            margin-bottom: 3px;
        }}
        
        .info-value {{
            color: #d4d4d4;
            word-break: break-all;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        
        .summary-card {{
            background: #252526;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }}
        
        .summary-card.static {{ border-left: 4px solid #c586c0; }}
        .summary-card.import {{ border-left: 4px solid #dcdcaa; }}
        .summary-card.dll {{ border-left: 4px solid #4ec9b0; }}
        .summary-card.missing {{ border-left: 4px solid #f14c4c; }}
        .summary-card.total {{ border-left: 4px solid #569cd6; }}
        
        .summary-number {{
            font-size: 32px;
            font-weight: bold;
        }}
        
        .summary-card.static .summary-number {{ color: #c586c0; }}
        .summary-card.import .summary-number {{ color: #dcdcaa; }}
        .summary-card.dll .summary-number {{ color: #4ec9b0; }}
        .summary-card.missing .summary-number {{ color: #f14c4c; }}
        .summary-card.total .summary-number {{ color: #569cd6; }}
        
        .summary-label {{
            color: #808080;
            font-size: 14px;
        }}
        
        .controls {{
            margin-bottom: 15px;
        }}
        
        .btn {{
            background: #0e639c;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            margin-right: 10px;
            font-size: 14px;
        }}
        
        .btn:hover {{
            background: #1177bb;
        }}
        
        .tree-section {{
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }}
        
        .tree-container {{
            flex: 1;
            min-width: 0;
            background: #252526;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            max-height: 600px;
            overflow-y: auto;
        }}
        
        .detail-panel {{
            width: 350px;
            flex-shrink: 0;
            background: #252526;
            border-radius: 8px;
            height: fit-content;
            position: sticky;
            top: 20px;
        }}
        
        .tree {{
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 14px;
        }}
        
        .tree ul {{
            list-style: none;
            padding-left: 24px;
        }}
        
        .tree > ul {{
            padding-left: 0;
        }}
        
        .tree li {{
            position: relative;
            padding: 3px 0;
        }}
        
        .tree-node {{
            display: inline-flex;
            align-items: center;
            cursor: pointer;
            padding: 2px 6px;
            border-radius: 3px;
        }}
        
        .tree-node:hover {{
            background: #37373d;
        }}
        
        .tree-icon {{
            cursor: pointer;
            width: 18px;
            height: 18px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            margin-right: 6px;
            font-size: 12px;
            font-weight: bold;
            border-radius: 3px;
        }}
        
        .tree-icon.lib-static {{
            background: #c586c0;
            color: #1e1e1e;
        }}
        
        .tree-icon.lib-import {{
            background: #dcdcaa;
            color: #1e1e1e;
        }}
        
        .tree-icon.dll {{
            background: #4ec9b0;
            color: #1e1e1e;
        }}
        
        .tree-icon.missing {{
            background: #f14c4c;
            color: #1e1e1e;
        }}
        
        .tree-icon.unknown {{
            background: #808080;
            color: #1e1e1e;
        }}
        
        .tree-name {{
            color: #d4d4d4;
        }}
        
        .tree-name.lib-static {{ color: #c586c0; }}
        .tree-name.lib-import {{ color: #dcdcaa; }}
        .tree-name.dll {{ color: #4ec9b0; }}
        .tree-name.missing {{ color: #f14c4c; }}
        
        .circular-mark {{
            color: #ce9178;
            font-size: 12px;
            margin-left: 8px;
        }}
        
        .dll-link {{
            color: #808080;
            font-size: 12px;
            margin-left: 8px;
        }}
        
        .tree ul.collapsed {{
            display: none;
        }}
        
        .detail-header {{
            background: #2d2d2d;
            padding: 12px 16px;
            border-radius: 8px 8px 0 0;
        }}
        
        .detail-title {{
            color: #569cd6;
            font-size: 16px;
            font-weight: 600;
        }}
        
        .detail-content {{
            padding: 16px;
        }}
        
        .detail-placeholder {{
            color: #808080;
            text-align: center;
            padding: 40px 20px;
        }}
        
        .detail-item {{
            margin-bottom: 15px;
        }}
        
        .detail-label {{
            color: #808080;
            font-size: 12px;
            margin-bottom: 3px;
        }}
        
        .detail-value {{
            color: #d4d4d4;
            word-break: break-all;
            font-family: 'Consolas', monospace;
        }}
        
        .deps-section {{
            background: #252526;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        
        .deps-list {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 8px;
        }}
        
        .deps-item {{
            background: #2d2d2d;
            padding: 8px 12px;
            border-radius: 4px;
            font-family: 'Consolas', monospace;
            font-size: 13px;
            cursor: pointer;
        }}
        
        .deps-item:hover {{
            background: #37373d;
        }}
        
        .deps-item.static {{ border-left: 3px solid #c586c0; }}
        .deps-item.import {{ border-left: 3px solid #dcdcaa; }}
        .deps-item.dll {{ border-left: 3px solid #4ec9b0; }}
        .deps-item.missing {{ border-left: 3px solid #f14c4c; }}
        
        .deps-item-info {{
            color: #808080;
            font-size: 11px;
            margin-top: 2px;
        }}
        
        .detail-type-badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }}
        
        .detail-type-badge.lib-static {{
            background: #c586c0;
            color: #1e1e1e;
        }}
        
        .detail-type-badge.lib-import {{
            background: #dcdcaa;
            color: #1e1e1e;
        }}
        
        .detail-type-badge.dll {{
            background: #4ec9b0;
            color: #1e1e1e;
        }}
        
        .detail-type-badge.missing {{
            background: #f14c4c;
            color: #1e1e1e;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📚 静态库依赖分析报告</h1>
            <div class="header-info">
                <div class="info-item">
                    <div class="info-label">文件名</div>
                    <div class="info-value" id="lib-name"></div>
                </div>
                <div class="info-item">
                    <div class="info-label">完整路径</div>
                    <div class="info-value" id="lib-path"></div>
                </div>
                <div class="info-item">
                    <div class="info-label">库类型</div>
                    <div class="info-value" id="lib-type"></div>
                </div>
                <div class="info-item" id="dll-name-item" style="display: none;">
                    <div class="info-label">关联 DLL</div>
                    <div class="info-value" id="dll-name"></div>
                </div>
                <div class="info-item" id="member-count-item" style="display: none;">
                    <div class="info-label">成员数量</div>
                    <div class="info-value" id="member-count"></div>
                </div>
                <div class="info-item">
                    <div class="info-label">生成时间</div>
                    <div class="info-value" id="generated-at"></div>
                </div>
            </div>
        </div>
        
        <div class="summary">
            <div class="summary-card static">
                <div class="summary-number" id="static-count">0</div>
                <div class="summary-label">静态库</div>
            </div>
            <div class="summary-card import">
                <div class="summary-number" id="import-count">0</div>
                <div class="summary-label">导入库</div>
            </div>
            <div class="summary-card dll">
                <div class="summary-number" id="dll-count">0</div>
                <div class="summary-label">DLL</div>
            </div>
            <div class="summary-card missing">
                <div class="summary-number" id="missing-count">0</div>
                <div class="summary-label">缺失</div>
            </div>
            <div class="summary-card total">
                <div class="summary-number" id="total-count">0</div>
                <div class="summary-label">总依赖</div>
            </div>
        </div>
        
        <h2>🌲 依赖树</h2>
        <div class="controls">
            <button class="btn" onclick="expandAll()">展开全部</button>
            <button class="btn" onclick="collapseAll()">折叠全部</button>
        </div>
        <div class="tree-section">
            <div class="tree-container">
                <div class="tree" id="tree"></div>
            </div>
            <div class="detail-panel" id="detail-panel">
                <div class="detail-header">
                    <span class="detail-title">📄 详细信息</span>
                </div>
                <div class="detail-content" id="detail-content">
                    <div class="detail-placeholder">悬停左侧节点查看详情</div>
                </div>
            </div>
        </div>
        
        <div id="static-section" style="display: none;">
            <h2>📦 静态库列表</h2>
            <div class="deps-section">
                <div class="deps-list" id="static-deps"></div>
            </div>
        </div>
        
        <div id="import-section" style="display: none;">
            <h2>🔗 导入库列表</h2>
            <div class="deps-section">
                <div class="deps-list" id="import-deps"></div>
            </div>
        </div>
        
        <div id="dll-section" style="display: none;">
            <h2>📁 DLL 列表</h2>
            <div class="deps-section">
                <div class="deps-list" id="dll-deps"></div>
            </div>
        </div>
        
        <div id="missing-section" style="display: none;">
            <h2>⚠️ 缺失依赖列表</h2>
            <div class="deps-section">
                <div class="deps-list" id="missing-deps"></div>
            </div>
        </div>
    </div>
    
    <script>
        const DATA = {json.dumps(report_data, ensure_ascii=False)};
        
        function init() {{
            // 填充头部信息
            document.getElementById('lib-name').textContent = DATA.lib_info.name;
            document.getElementById('lib-path').textContent = DATA.lib_info.path;
            document.getElementById('lib-type').textContent = DATA.lib_info.type;
            document.getElementById('generated-at').textContent = DATA.generated_at;
            
            if (DATA.lib_info.dll_name) {{
                document.getElementById('dll-name-item').style.display = 'block';
                document.getElementById('dll-name').textContent = DATA.lib_info.dll_name;
            }}
            
            if (DATA.lib_info.member_count > 0) {{
                document.getElementById('member-count-item').style.display = 'block';
                document.getElementById('member-count').textContent = DATA.lib_info.member_count;
            }}
            
            // 填充统计
            document.getElementById('static-count').textContent = DATA.summary.static_count;
            document.getElementById('import-count').textContent = DATA.summary.import_count;
            document.getElementById('dll-count').textContent = DATA.summary.dll_count;
            document.getElementById('missing-count').textContent = DATA.summary.missing_count;
            document.getElementById('total-count').textContent = DATA.summary.total;
            
            // 渲染依赖树
            document.getElementById('tree').innerHTML = '<ul>' + renderTree(DATA.tree, 0) + '</ul>';
            
            // 渲染依赖列表
            if (DATA.dependencies.static.length > 0) {{
                document.getElementById('static-section').style.display = 'block';
                renderStaticList('static-deps', DATA.dependencies.static);
            }}
            
            if (DATA.dependencies.import.length > 0) {{
                document.getElementById('import-section').style.display = 'block';
                renderImportList('import-deps', DATA.dependencies.import);
            }}
            
            if (DATA.dependencies.dll.length > 0) {{
                document.getElementById('dll-section').style.display = 'block';
                renderDllList('dll-deps', DATA.dependencies.dll);
            }}
            
            if (DATA.dependencies.missing.length > 0) {{
                document.getElementById('missing-section').style.display = 'block';
                renderMissingList('missing-deps', DATA.dependencies.missing);
            }}
        }}
        
        function renderTree(node, depth) {{
            const hasChildren = node.children && node.children.length > 0;
            const isCollapsed = depth > 0;
            
            // 图标
            let iconLabel;
            if (node.type === 'lib-static') {{
                iconLabel = hasChildren ? (isCollapsed ? '+' : '-') : 'L';
            }} else if (node.type === 'lib-import') {{
                iconLabel = 'I';
            }} else if (node.type === 'dll') {{
                iconLabel = 'D';
            }} else if (node.type === 'missing') {{
                iconLabel = 'X';
            }} else {{
                iconLabel = '?';
            }}
            
            const circularMark = node.circular ? '<span class="circular-mark">(circular)</span>' : '';
            const dllLink = node.dll_name ? '<span class="dll-link">→ ' + escapeHtml(node.dll_name) + '</span>' : '';
            
            let html = '<li>';
            html += '<span class="tree-node" onclick="toggleNode(this)" onmouseenter="hoverNode(this)" ';
            html += 'data-name="' + escapeHtml(node.name) + '" ';
            html += 'data-path="' + escapeHtml(node.path) + '" ';
            html += 'data-type="' + node.type + '" ';
            html += 'data-has-children="' + hasChildren + '" ';
            html += 'data-dll-name="' + escapeHtml(node.dll_name || '') + '" ';
            html += 'data-member-count="' + (node.member_count || 0) + '">';
            html += '<span class="tree-icon ' + node.type + '">' + iconLabel + '</span>';
            html += '<span class="tree-name ' + node.type + '">' + escapeHtml(node.name) + '</span>';
            html += dllLink;
            html += circularMark;
            html += '</span>';
            
            if (hasChildren && !node.circular) {{
                html += '<ul' + (isCollapsed ? ' class="collapsed"' : '') + '>';
                for (const child of node.children) {{
                    html += renderTree(child, depth + 1);
                }}
                html += '</ul>';
            }}
            
            html += '</li>';
            return html;
        }}
        
        function renderStaticList(containerId, deps) {{
            const container = document.getElementById(containerId);
            container.innerHTML = deps.map(d => 
                '<div class="deps-item static" onmouseenter="showDetailStatic(\\'' + escapeHtml(d.name) + '\\', \\'' + escapeHtml(d.path) + '\\', ' + d.member_count + ')">' + 
                escapeHtml(d.name) + 
                (d.member_count > 0 ? '<div class="deps-item-info">' + d.member_count + ' 个成员</div>' : '') +
                '</div>'
            ).join('');
        }}
        
        function renderImportList(containerId, deps) {{
            const container = document.getElementById(containerId);
            container.innerHTML = deps.map(d => 
                '<div class="deps-item import" onmouseenter="showDetailImport(\\'' + escapeHtml(d.name) + '\\', \\'' + escapeHtml(d.path) + '\\', \\'' + escapeHtml(d.dll_name) + '\\')">' + 
                escapeHtml(d.name) + 
                (d.dll_name ? '<div class="deps-item-info">→ ' + escapeHtml(d.dll_name) + '</div>' : '') +
                '</div>'
            ).join('');
        }}
        
        function renderDllList(containerId, deps) {{
            const container = document.getElementById(containerId);
            container.innerHTML = deps.map(d => 
                '<div class="deps-item dll" onmouseenter="showDetailDll(\\'' + escapeHtml(d.name) + '\\', \\'' + escapeHtml(d.path) + '\\')">' + 
                escapeHtml(d.name) + '</div>'
            ).join('');
        }}
        
        function renderMissingList(containerId, deps) {{
            const container = document.getElementById(containerId);
            container.innerHTML = deps.map(d => 
                '<div class="deps-item missing">' + escapeHtml(d.name) + '</div>'
            ).join('');
        }}
        
        function escapeHtml(text) {{
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML.replace(/'/g, "\\\\'").replace(/"/g, '&quot;');
        }}
        
        function toggleNode(element) {{
            const li = element.parentElement;
            const childUl = li.querySelector(':scope > ul');
            const icon = element.querySelector('.tree-icon');
            const nodeType = element.dataset.type;
            const hasChildren = element.dataset.hasChildren === 'true';
            
            if (childUl) {{
                childUl.classList.toggle('collapsed');
                if (nodeType === 'lib-static' && hasChildren) {{
                    icon.textContent = childUl.classList.contains('collapsed') ? '+' : '-';
                }}
            }}
        }}
        
        function hoverNode(element) {{
            const name = element.dataset.name;
            const path = element.dataset.path;
            const type = element.dataset.type;
            const dllName = element.dataset.dllName;
            const memberCount = parseInt(element.dataset.memberCount) || 0;
            
            if (type === 'lib-static') {{
                showDetailStatic(name, path, memberCount);
            }} else if (type === 'lib-import') {{
                showDetailImport(name, path, dllName);
            }} else if (type === 'dll') {{
                showDetailDll(name, path);
            }} else {{
                showDetailMissing(name);
            }}
        }}
        
        function showDetailStatic(name, path, memberCount) {{
            const content = document.getElementById('detail-content');
            content.innerHTML = `
                <div class="detail-item">
                    <div class="detail-label">文件名</div>
                    <div class="detail-value">${{escapeHtmlDisplay(name)}}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">完整路径</div>
                    <div class="detail-value">${{escapeHtmlDisplay(path) || '(未找到)'}}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">类型</div>
                    <div class="detail-value"><span class="detail-type-badge lib-static">静态库</span></div>
                </div>
                ${{memberCount > 0 ? `
                <div class="detail-item">
                    <div class="detail-label">成员数量</div>
                    <div class="detail-value">${{memberCount}} 个 .obj 文件</div>
                </div>
                ` : ''}}
            `;
        }}
        
        function showDetailImport(name, path, dllName) {{
            const content = document.getElementById('detail-content');
            content.innerHTML = `
                <div class="detail-item">
                    <div class="detail-label">文件名</div>
                    <div class="detail-value">${{escapeHtmlDisplay(name)}}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">完整路径</div>
                    <div class="detail-value">${{escapeHtmlDisplay(path) || '(未找到)'}}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">类型</div>
                    <div class="detail-value"><span class="detail-type-badge lib-import">导入库</span></div>
                </div>
                ${{dllName ? `
                <div class="detail-item">
                    <div class="detail-label">关联 DLL</div>
                    <div class="detail-value">${{escapeHtmlDisplay(dllName)}}</div>
                </div>
                ` : ''}}
            `;
        }}
        
        function showDetailDll(name, path) {{
            const content = document.getElementById('detail-content');
            content.innerHTML = `
                <div class="detail-item">
                    <div class="detail-label">文件名</div>
                    <div class="detail-value">${{escapeHtmlDisplay(name)}}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">完整路径</div>
                    <div class="detail-value">${{escapeHtmlDisplay(path) || '(未找到)'}}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">类型</div>
                    <div class="detail-value"><span class="detail-type-badge dll">DLL</span></div>
                </div>
            `;
        }}
        
        function showDetailMissing(name) {{
            const content = document.getElementById('detail-content');
            content.innerHTML = `
                <div class="detail-item">
                    <div class="detail-label">文件名</div>
                    <div class="detail-value">${{escapeHtmlDisplay(name)}}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">状态</div>
                    <div class="detail-value"><span class="detail-type-badge missing">未找到</span></div>
                </div>
            `;
        }}
        
        function escapeHtmlDisplay(text) {{
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }}
        
        function expandAll() {{
            document.querySelectorAll('.tree ul.collapsed').forEach(ul => {{
                ul.classList.remove('collapsed');
            }});
            document.querySelectorAll('.tree .tree-node[data-type="lib-static"][data-has-children="true"] .tree-icon').forEach(icon => {{
                icon.textContent = '-';
            }});
        }}
        
        function collapseAll() {{
            document.querySelectorAll('.tree ul').forEach((ul, index) => {{
                if (index > 0) ul.classList.add('collapsed');
            }});
            document.querySelectorAll('.tree .tree-node[data-type="lib-static"][data-has-children="true"] .tree-icon').forEach(icon => {{
                icon.textContent = '+';
            }});
        }}
        
        init();
    </script>
</body>
</html>'''
    
    # 写入文件
    report_path = os.path.join(output_dir, 'report.html')
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return report_path


def print_help():
    """打印帮助信息"""
    print("用法: python print_exe_deps.py <文件> [输出目录] [选项]")
    print("\n支持的文件类型:")
    print("  - PE 可执行文件 (.exe, .dll)")
    print("  - 静态库 (.lib) - 包括导入库和静态库")
    print("\n位置参数:")
    print("  <文件>             要分析的 exe/dll/lib 文件")
    print("  [输出目录]         输出目录 (可选，默认为文件名同名目录)")
    print("\n选项:")
    print("  -s, --system       显示系统 DLL (仅 PE 分析)")
    print("  -d, --depth N      设置树的最大显示深度 (默认5)")
    print("  -n, --no-copy      只分析不复制文件，不生成报告")
    print("  -L, --lib-path     指定库搜索路径 (可多次使用)")
    print("  -h, --help         显示帮助")
    print("\n输出:")
    print("  - 终端打印依赖树和汇总信息")
    print("  - 在输出目录生成 report.html 交互式报告")
    print("  - 复制所有本地依赖到输出目录 (仅 PE 分析，除非使用 -n)")
    print("\n示例:")
    print("  # PE 文件分析")
    print("  python print_exe_deps.py myapp.exe")
    print("  python print_exe_deps.py myapp.exe D:\\output")
    print("  python print_exe_deps.py myapp.dll D:\\output -s")
    print("")
    print("  # 静态库分析")
    print("  python print_exe_deps.py mylib.lib")
    print("  python print_exe_deps.py mylib.lib D:\\output -L C:\\SDK\\lib")
    print("\nPE 分析图例:")
    print("  [+] 本地/应用 DLL (已找到)")
    print("  [S] 系统 DLL")
    print("  [X] 未找到的 DLL")
    print("\n静态库分析图例:")
    print("  [L] 静态库")
    print("  [I] 导入库")
    print("  [D] DLL")
    print("  [X] 未找到")


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 解析参数
    input_path = None
    output_dir = None
    show_system = False
    max_depth = 5
    no_copy = False
    lib_search_paths = []  # -L 参数指定的库搜索路径
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
        elif arg in ('-L', '--lib-path'):
            if i + 1 < len(args):
                lib_search_paths.append(os.path.abspath(args[i + 1]))
                i += 2
                continue
        elif arg in ('-h', '--help'):
            print_help()
            return 0
        elif not arg.startswith('-'):
            positional_args.append(arg)
        i += 1
    
    # 处理位置参数
    if len(positional_args) >= 1:
        # 第一个参数: exe/dll/lib文件
        arg = positional_args[0]
        if os.path.exists(arg):
            input_path = os.path.abspath(arg)
        elif os.path.exists(os.path.join(script_dir, arg)):
            input_path = os.path.join(script_dir, arg)
        else:
            print(f"错误: 文件不存在 - {arg}")
            return 1
    
    if len(positional_args) >= 2:
        # 第二个参数: 输出目录
        output_dir = os.path.abspath(positional_args[1])
    
    # 如果没有提供输入路径，显示帮助
    if input_path is None:
        print("错误: 请指定要分析的文件 (exe/dll/lib)\n")
        print_help()
        return 1
    
    # 检查文件是否存在
    if not os.path.exists(input_path):
        print(f"错误: 文件不存在 - {input_path}")
        return 1
    
    # 检测文件类型
    is_lib = is_lib_file(input_path)
    
    # 默认输出目录
    if output_dir is None:
        input_dir = os.path.dirname(input_path)
        input_name = os.path.splitext(os.path.basename(input_path))[0]
        output_dir = os.path.join(input_dir, input_name)
    
    # 添加输入文件所在目录到库搜索路径
    input_dir = os.path.dirname(input_path)
    if input_dir not in lib_search_paths:
        lib_search_paths.insert(0, input_dir)
    
    print("=" * 80)
    print(f"分析文件: {input_path}")
    print("=" * 80)
    
    if is_lib:
        # .lib 文件分析流程
        return analyze_lib_file(input_path, output_dir, lib_search_paths, max_depth, no_copy)
    else:
        # PE 文件分析流程
        return analyze_pe_file(input_path, output_dir, show_system, max_depth, no_copy)


def analyze_lib_file(lib_path, output_dir, search_paths, max_depth, no_copy):
    """分析 .lib 文件"""
    lib_name = os.path.basename(lib_path)
    
    # 解析库文件
    lib_info = parse_lib_file(lib_path)
    
    if lib_info is None:
        print("错误: 无法解析 .lib 文件")
        return 1
    
    # 显示库信息
    lib_type_str = "导入库" if lib_info['type'] == 'import' else "静态库"
    print(f"库类型: {lib_type_str}")
    
    if lib_info.get('dll_name'):
        print(f"关联 DLL: {lib_info['dll_name']}")
    
    if lib_info.get('members'):
        print(f"成员数量: {len(lib_info['members'])}")
    
    print(f"\n正在构建依赖树...")
    
    # 构建依赖树
    root, all_nodes = build_lib_dependency_tree(lib_path, search_paths, max_depth)
    
    # 打印依赖树
    print("\n" + "=" * 80)
    print("依赖树")
    print("图例: [L]=静态库  [I]=导入库  [D]=DLL  [X]=未找到")
    print("=" * 80 + "\n")
    
    print_lib_tree(root, max_print_depth=max_depth)
    
    # 统计
    import_libs = [n for n in all_nodes.values() if n.lib_type == 'import']
    static_libs = [n for n in all_nodes.values() if n.lib_type == 'static']
    dlls = [n for n in all_nodes.values() if n.lib_type == 'dll']
    missing = [n for n in all_nodes.values() if not n.found]
    
    print("\n" + "=" * 80)
    print("依赖汇总")
    print("=" * 80)
    
    if static_libs:
        print(f"\n[静态库] 共 {len(static_libs)} 个:")
        for node in sorted(static_libs, key=lambda x: x.name.lower()):
            print(f"  {node.name}")
    
    if import_libs:
        print(f"\n[导入库] 共 {len(import_libs)} 个:")
        for node in sorted(import_libs, key=lambda x: x.name.lower()):
            dll_info = f" -> {node.dll_name}" if node.dll_name else ""
            print(f"  {node.name}{dll_info}")
    
    if dlls:
        print(f"\n[DLL] 共 {len(dlls)} 个:")
        for node in sorted(dlls, key=lambda x: x.name.lower()):
            print(f"  {node.name}")
    
    if missing:
        print(f"\n[未找到] 共 {len(missing)} 个:")
        for node in sorted(missing, key=lambda x: x.name.lower()):
            print(f"  {node.name}")
    
    print(f"\n总计: {len(all_nodes) - 1} 个依赖")
    
    # 生成 HTML 报告
    if not no_copy and output_dir:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        print("\n" + "=" * 80)
        print("生成 HTML 报告")
        print("=" * 80)
        
        report_path = generate_lib_html_report(
            lib_path, lib_info, root, all_nodes,
            static_libs, import_libs, dlls, missing, output_dir
        )
        print(f"  [生成] {report_path}")
    
    return 0


def print_lib_tree(node, prefix="", is_last=True, visited=None, depth=0, max_print_depth=5):
    """打印 .lib 依赖树"""
    if visited is None:
        visited = set()
    
    connector = "`-- " if is_last else "|-- "
    
    # 状态标记
    if not node.found:
        status = "[X]"
    elif node.lib_type == 'import':
        status = "[I]"
    elif node.lib_type == 'static':
        status = "[L]"
    elif node.lib_type == 'dll':
        status = "[D]"
    else:
        status = "[?]"
    
    node_key = node.name.lower()
    is_circular = node_key in visited
    
    if depth == 0:
        print(f"{status} {node.name}")
    else:
        circular_mark = " (circular)" if is_circular else ""
        dll_info = f" -> {node.dll_name}" if node.dll_name and node.lib_type == 'import' else ""
        print(f"{prefix}{connector}{status} {node.name}{dll_info}{circular_mark}")
    
    if is_circular or depth >= max_print_depth:
        if depth >= max_print_depth and node.children:
            new_prefix = prefix + ("    " if is_last else "|   ")
            print(f"{new_prefix}`-- ... ({len(node.children)} more deps)")
        return
    
    visited.add(node_key)
    
    for i, child in enumerate(node.children):
        is_child_last = (i == len(node.children) - 1)
        new_prefix = prefix + ("    " if is_last else "|   ")
        print_lib_tree(child, new_prefix, is_child_last, visited.copy(), depth + 1, max_print_depth)


def analyze_pe_file(exe_path, output_dir, show_system, max_depth, no_copy):
    """分析 PE 文件（原有逻辑）"""
    arch = "未知"
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
        
        # 生成 HTML 报告
        print("\n" + "=" * 80)
        print("生成 HTML 报告")
        print("=" * 80)
        report_path = generate_html_report(
            exe_path, arch, root, all_nodes,
            local_deps, system_deps, missing_deps, output_dir
        )
        print(f"  [生成] {report_path}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
