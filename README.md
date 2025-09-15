# 全栈 CTF 文件分析器

本项目是一个为 CTF (Capture The Flag) 竞赛设计的、功能完善的在线文件分析工具。它由一个用于深度文件分析的 Python Flask 后端和一个用于用户交互的轻量级 Vanilla JavaScript 前端组成。该工具旨在帮助参赛者快速识别文件异常、隐藏信息、伪加密、隐写术以及其他常见的CTF线索。

本项目经过精心设计，可轻松部署在 **Windows** 和 **CentOS/Linux** 环境中。

## 项目结构

```
.
├── backend_api/
│   ├── analyzer/
│   │   ├── analyzers/      # <--- 模块化分析器目录
│   │   │   ├── __init__.py
│   │   │   ├── base_analyzer.py
│   │   │   ├── zip_analyzer.py
│   │   │   └── ... (其他分析器)
│   │   ├── __init__.py
│   │   ├── core.py         # <--- 核心函数
│   │   └── main_analyzer.py  # <--- 分析器加载与协调器
│   ├── app.py
│   └── requirements.txt
├── frontend_static/
│   ├── index.html
│   ├── script.js
│   └── style.css
└── README.md
```

## 核心功能

- **🤖 AI 增强分析 (由 Gemini 驱动)**: (可选功能) 集成 Google Gemini Pro，对文件的十六进制内容进行智能分析，提供专家级的 CTF 解题思路和线索。
- **模块化与可扩展的分析器**: 系统的核心是一个动态加载的模块化分析引擎。您可以轻松编写自己的分析器来扩展工具的功能，以应对新的文件类型或挑战。
- **文件上传与十六进制/ASCII预览**: 上传任意文件，并以十六进制编辑器格式查看其头部和尾部数据。
- **文件类型分析**: 通过一个包含数十种常见文件类型的扩展数据库（包括图片、存档、文档、可执行文件等），精确检测文件类型。
- **字符串与URL提取**: 提取所有可打印字符串、URL和常见CTF关键字。
- **熵分析**: 计算香non熵，以识别加壳或加密的数据区域。
- **深度分析与结构解析**:
    - **ZIP**: 详细解析每个文件的本地头，并能发现未被索引的隐藏条目。
    - **PNG**: 解析IHDR块，并校验各数据块的CRC。
    - **BMP, GIF, RAR**: 解析文件头和元数据。
- **推荐工具**: 根据分析发现，自动推荐相关的第三方CTF工具（例如 `binwalk`, `bkcrack` 等）。

---

## 可扩展的分析器

本工具最大的特点之一是其模块化的分析器架构。您可以为任何文件格式创建自己的分析器，而无需修改核心代码。

详细的开发指南请参见 `backend_api/analyzer/analyzers/README.md`。

---

## (可选) 启用 AI 分析功能

您可以选择性地启用由 Google Gemini Pro 驱动的 AI 分析功能。

### 第1步：获取 Gemini API 密钥

前往 **[Google AI Studio](https://makersuite.google.com/app/apikey)** 获取您的免费 API 密钥。

### 第2步：配置密钥

1.  在 `backend_api` 目录下，找到 `config.py.example` 文件。
2.  **复制** 这个文件并将其重命名为 `config.py`。
3.  用您的文本编辑器打开 `config.py` 文件。
4.  将 `"YOUR_API_KEY_HERE"` 替换为您在第一步中获取的真实 API 密钥。

```python
# backend_api/config.py

# ... (注释内容) ...
GEMINI_API_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxx" # <--- 替换为您的密钥
```

完成以上步骤后，下次启动后端服务时，AI 分析功能将被自动激活。如果您没有配置密钥，该功能将被安全地跳过。

---

## 第一部分：后端设置 (Flask API)

后端是一个执行所有分析任务的 Python Flask 应用程序。

### 第1步：环境准备

- **Python 3.8+**
- **pip** (Python 包安装器)

#### 安装指南:
- **Windows**: 从 [python.org](https://www.python.org/) 下载并安装。**请在安装过程中务必勾选 "Add Python to PATH"**。
- **CentOS/RHEL**: `sudo yum install python3 python3-pip` 或 `sudo dnf install python3 python3-pip`。

### 第2步：创建虚拟环境

强烈建议使用虚拟环境来管理项目依赖。

首先，进入项目的根目录。

```bash
# 进入后端目录
cd backend_api

# 创建虚拟环境
python3 -m venv venv
```

### 第3步：激活环境并安装依赖

- **Windows (命令提示符):**
  ```cmd
  .\venv\Scripts\activate
  ```
- **Windows (PowerShell):**
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```
- **CentOS/Linux (Bash):**
  ```bash
  source venv/bin/activate
  ```

激活环境后，安装所需的包：
```bash
pip install -r requirements.txt
```

### 第4步：运行后端服务器

请确保您位于 `backend_api` 目录中，并已激活虚拟环境。

```bash
# 服务器默认将在 http://localhost:5000 运行
flask run --host=0.0.0.0
```
后端 API 现在已成功运行并准备好接受请求。

---

## 第二部分：前端设置 (静态 Web 应用)

前端是一组静态的 HTML、CSS 和 JS 文件，可以由任何简单的 Web 服务器托管。

### 简便方法：使用一键启动脚本

为了方便，您可以使用项目提供的脚本来快速启动前端服务器。

1.  打开一个 **新的终端** (不要关闭您的后端终端)。
2.  进入 `frontend_static` 目录。
    ```bash
    cd frontend_static
    ```
3.  运行对应的启动脚本:
    - **Windows 用户**:
        ```cmd
        .\start_frontend.bat
        ```
    - **Linux / macOS 用户**:
        ```bash
        ./start_frontend.sh
        ```
    脚本会自动在 `http://localhost:8080` 启动服务器。

### 访问应用程序

当后端和前端服务器都成功运行后：

1.  打开您的网络浏览器。
2.  访问前端 URL: **`http://localhost:8080`** (或您用于前端的端口)。

您现在可以上传文件并查看分析结果了。前端将与运行在 5000 端口的后端 API 进行通信。如果您的后端位于不同的 URL，可以编辑 `frontend_static/script.js` 文件顶部的 `API_BASE_URL` 常量。
