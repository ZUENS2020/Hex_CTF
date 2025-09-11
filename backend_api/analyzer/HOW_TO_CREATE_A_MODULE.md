# 如何为分析器创建新模块 (v2.0)

本文档将指导您如何为本CTF文件分析工具编写一个新的、自定义的文件类型分析模块。

## 模块化架构简介

本工具的后端分析器采用**配置文件驱动的模块化**设计。核心协调器位于 `main_analyzer.py`，而所有模块的配置信息都集中存储在 `modules.json` 文件中。

当一个文件被上传时，主分析器会：
1.  在启动时，读取 `modules.json` 并加载所有模块的配置（包括Magic Bytes和它们对应的分析器）。
2.  通过加载的配置来识别上传文件的类型。
3.  如果该文件类型有关联的分析模块，主分析器会动态加载该模块，并调用其 `analyze` 函数来执行分析。

得益于这个新架构，添加对新文件类型的支持变得**极其简单**。您不再需要修改任何Python代码，只需**创建一个新的分析器文件**并在**`modules.json`中添加一行配置**即可。

---

## 开发步骤

假设您想为一个名为 "MyFormat" 的新文件类型（扩展名为 `.myf`）创建一个分析器。

### 步骤一：创建分析器文件

在 `backend_api/analyzer/` 目录下，创建一个新的Python文件。文件名应该简洁并能代表其功能，例如 `my_format.py`。

在这个文件中，您**必须**定义一个名为 `analyze` 的主函数。这个函数是主分析器调用的入口点。

`analyze` 函数的接口（签名）如下：

```python
def analyze(data_or_path, findings):
    """
    data_or_path: 可能是文件的完整字节流(bytes)，也可能是文件的临时路径(str)。
                  主分析器会根据需要智能传入。
    findings:     一个列表，您可以将新的发现（finding）添加到这个列表中。
    """
    # 您的分析逻辑写在这里...

    # 该函数应返回一个用于填充“文件结构”选项卡的数据结构（通常是字典列表），
    # 如果没有结构化数据可以展示，则返回 None。
    structure = []
    # ...填充 structure
    return structure
```
*您可以参考同目录下的 `zip.py` 或 `png.py` 作为实现范例。*

### 步骤二：在 `modules.json` 中注册您的模块

打开 `backend_api/analyzer/modules.json` 文件。

在JSON数组的末尾添加一个新的对象来定义您的模块。

例如，如果您的文件以 `MYF!` (十六进制 `4D594621`) 四个字节开头：
```json
[
  {
    "type_name": "ZIP",
    "module_name": "zip",
    "magic_hex": "504B0304",
    "offset": 0,
    "mime_type": "application/zip"
  },
  ...
  {
    "type_name": "MyFormat",
    "module_name": "my_format",
    "magic_hex": "4D594621",
    "offset": 0,
    "mime_type": "application/x-my-format"
  }
]
```
- **type_name**: 文件的通用名称。
- **module_name**: 您创建的Python文件名（**不含.py**）。如果您的文件类型不需要深度结构分析，可以设为 `null`。
- **magic_hex**: 文件的魔术字节，以十六进制字符串表示。
- **offset**: 魔术字节在文件中的偏移量。
- **mime_type**: 文件的MIME类型。

**完成！**

只需这两步，您的新模块就已经成功集成到系统中了。重新启动Flask服务器，当用户上传一个以 `MYF!` 开头的文件时，主分析器会自动加载并调用您的 `my_format.py` 中的 `analyze` 函数。
