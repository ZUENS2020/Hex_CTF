# 如何为分析器创建新模块

本文档将指导您如何为本CTF文件分析工具编写一个新的、自定义的文件类型分析模块。

## 模块化架构简介

本工具的后端分析器采用模块化设计。核心协调器位于 `main_analyzer.py`，而针对特定文件类型（如ZIP, PNG）的分析逻辑则位于各自独立的模块文件（如`zip.py`, `png.py`）中。

当一个文件被上传时，主分析器会：
1.  通过 `common.py` 中的 `MAGIC_BYTES_DB` 识别文件类型。
2.  在 `main_analyzer.py` 中的 `ANALYZER_MAPPING` 中查找该文件类型对应的模块。
3.  动态加载该模块，并调用其 `analyze` 函数来执行分析。

要添加对新文件类型的支持，您只需要创建一个新模块并在这两个核心数据结构中注册它即可。

---

## 开发步骤

假设您想为一个名为 "MyFormat" 的新文件类型（扩展名为 `.myf`）创建一个分析器。

### 步骤一：创建分析器文件

在 `backend_api/analyzer/` 目录下，创建一个新的Python文件。文件名应该简洁并能代表其功能，例如 `my_format.py`。

### 步骤二：实现 `analyze` 函数

在您创建的 `my_format.py` 文件中，您**必须**定义一个名为 `analyze` 的主函数。这个函数是主分析器调用的入口点。

`analyze` 函数的接口（签名）如下：

```python
def analyze(data_or_path, findings):
    """
    data_or_path: 可能是文件的完整字节流(bytes)，也可能是文件的临时路径(str)。
                  主分析器会根据文件类型智能传入。通常，存档文件（如ZIP）需要路径，而图像文件可以直接处理字节流。
    findings:     一个列表，您可以将新的发现（finding）添加到这个列表中。
    """
    # 您的分析逻辑写在这里...

    # 该函数应返回一个用于填充“文件结构”选项卡的数据结构（通常是字典列表），
    # 如果没有结构化数据可以展示，则返回 None。
    structure = []
    # ...填充 structure
    return structure
```

### 步骤三：在 `common.py` 中注册文件标识头

打开 `backend_api/analyzer/common.py` 文件，找到 `MAGIC_BYTES_DB` 列表。

在列表中添加一个新元组来定义您文件类型的“魔术字节”（Magic Bytes）。格式为 `(魔术字节, 偏移量, 类型名称, MIME类型)`。

例如，如果您的文件以 `MYF!` 四个字节开头：
```python
MAGIC_BYTES_DB = [
    # ... 其他定义
    (b'MYF!', 0, 'MyFormat', 'application/x-my-format'),
]
```

### 步骤四：在 `main_analyzer.py` 中注册模块

打开 `backend_api/analyzer/main_analyzer.py` 文件，找到 `ANALYZER_MAPPING` 字典。

添加一个新条目，将您在上一步中定义的 `类型名称` 映射到您创建的**模块文件名（不含.py）**。

```python
ANALYZER_MAPPING = {
    "ZIP": "zip",
    "PNG": "png",
    # ... 其他映射
    "MyFormat": "my_format", # 添加这一行
}
```

完成以上四步后，您的新模块就已经成功集成到系统中了！当用户上传一个以 `MYF!` 开头的文件时，主分析器会自动调用您的 `my_format.py` 中的 `analyze` 函数。

---

## 代码模板

您可以复制以下代码作为您新模块（例如 `my_format.py`）的起点。

```python
# 导入您需要的任何库
import struct
from .common import add_finding # 强烈建议使用此辅助函数来添加发现

# 模块的主入口点
def analyze(data, findings):
    """
    分析MyFormat文件的示例函数。
    这个例子假设文件结构很简单。
    """

    # 1. 添加您的分析逻辑
    # =================================

    # 示例：检查一个特定的版本号
    try:
        version = struct.unpack('<H', data[4:6])[0]
        if version != 1:
            add_finding(
                findings,
                type="Unsupported MyFormat Version",
                severity="WARNING",
                description=f"Expected version 1, but found version {version}."
            )
    except (struct.error, IndexError):
        add_finding(findings, "MyFormat Parse Error", "CRITICAL", "Failed to parse MyFormat header.")
        return None # 解析失败，没有结构可以返回

    # 2. 构建要返回的结构化数据
    # =================================

    # 这个结构会显示在“文件结构”选项卡中
    structure = [
        {
            "type": "myformat_header",
            "name": "MyFormat Header",
            "details": {
                "Signature": data[0:4].decode(),
                "Version": version
            }
        }
    ]

    # 3. 返回结构
    # =================================
    return structure

```
