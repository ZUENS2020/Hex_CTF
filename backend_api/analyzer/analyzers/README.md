# 如何创建自定义分析器

本项目的分析引擎采用模块化设计，允许您轻松创建并集成自己的文件分析器。每个分析器都是一个独立的 Python 类，负责处理特定类型的文件。

## 创建分析器步骤

### 1. 创建一个新的分析器文件

在 `backend_api/analyzer/analyzers/` 目录下，创建一个新的 Python 文件。文件名应以 `_analyzer.py` 结尾，例如 `my_new_analyzer.py`。

### 2. 定义分析器类

在新创建的文件中，定义一个继承自 `BaseAnalyzer` 的类。

```python
# backend_api/analyzer/analyzers/my_new_analyzer.py

from .base_analyzer import BaseAnalyzer
from ..core import add_finding

class MyNewAnalyzer(BaseAnalyzer):
    # 为您的分析器提供一个唯一的名称
    name = "my_new_analyzer"

    def can_analyze(self, data, magic_bytes_info):
        """
        判断此分析器是否能处理当前文件。

        :param data: 文件的原始字节数据 (bytes)。
        :param magic_bytes_info: 一个包含 `magic_bytes_type` 和 `mime_type` 的字典。
        :return: 如果可以分析则返回 True，否则返回 False。
        """
        # 示例：通过文件扩展名或魔法字节判断
        # return file_storage.filename.endswith('.ext')
        return magic_bytes_info.get('magic_bytes_type') == 'MY_CUSTOM_TYPE'

    def analyze(self, file_storage, data, findings):
        """
        执行具体的文件分析。

        :param file_storage: Flask 的文件存储对象。
        :param data: 文件的原始字节数据 (bytes)。
        :param findings: 一个列表，用于追加您的分析发现。
        :return: 一个描述文件结构的字典，如果没有结构化数据则返回 None。
        """
        # 在这里实现您的分析逻辑

        # 示例：添加一个发现
        if "some_pattern" in data.decode('latin-1'):
            add_finding(
                findings,
                type="Custom Pattern Found",
                severity="INFO",
                description="在文件中找到了一个自定义的模式。"
            )

        # 示例：返回文件结构
        file_structure = [
            {"type": "custom_section", "offset": 0, "size": 100, "description": "自定义数据段"}
        ]

        return file_structure
```

### 3. 实现 `can_analyze` 方法

此方法决定您的分析器是否应该处理当前上传的文件。您可以基于文件名、`magic_bytes_info`（来自`core.py`的`analyze_magic_bytes`的结果）或文件内容本身来做判断。

### 4. 实现 `analyze` 方法

这是您的分析器执行核心逻辑的地方。
- 使用 `data` 参数来检查文件内容。
- 使用 `add_finding()` 辅助函数来向最终报告中添加发现。`add_finding` 的参数包括 `type`, `severity`, `description` 等。
- 如果您的分析器可以解析文件的内部结构（例如，像PNG的块或ZIP的条目），则返回一个字典列表。否则返回 `None`。

### 5. 完成！

系统会自动发现并加载您的新分析器。当一个匹配 `can_analyze` 条件的文件被上传时，您的 `analyze` 方法将被自动调用。您无需修改任何其他文件来“注册”您的分析器。
