# 全栈 CTF 文件分析器

本项目是一个为 CTF (Capture The Flag) 竞赛设计的、功能完善的在线文件分析工具。它由一个用于深度文件分析的 Python Flask 后端和一个用于用户交互的轻量级 Vanilla JavaScript 前端组成。该工具旨在帮助参赛者快速识别文件异常、隐藏信息、伪加密、隐写术以及其他常见的CTF线索。

本项目经过精心设计，可轻松部署在 **Windows** 和 **CentOS/Linux** 环境中，并具备与主流 AI API（如 OpenAI、Gemini 或通过 Ollama 部署的本地模型）集成的能力，以实现增强分析。

## 项目结构

```
.
├── backend_api/
│   ├── analyzer/
│   │   ├── ai_analyzer.py
│   │   └── main_analyzer.py
│   ├── app.py
│   ├── requirements.txt
│   └── .env.example
├── frontend_static/
│   ├── index.html
│   ├── script.js
│   └── style.css
└── README.md
```

##核心功能

- **文件上传与十六进制/ASCII预览**: 上传任意文件，并以十六进制编辑器格式查看其头部和尾部数据。
- **文件类型分析**: 使用 Magic Bytes 和 `libmagic` 检测文件类型，并高亮显示与文件扩展名的不匹配之处。
- **字符串提取**: 提取所有可打印字符串，并使用正则表达式高亮潜在的 `flag{...}` 格式。
- **熵分析**: 计算香农熵，以识别加壳或加密的数据区域。
- **ZIP 分析**: 检测 ZIP 压缩包中的伪加密、CRC 错误和全局注释。
- **EOF 数据检测**: 查找附加在标准文件结束标记（如 JPG、PNG）之后的数据。
- **AI 增强分析**: 集成主流 AI API，对提取的文本进行深度分析，以获取更深层次的见解和潜在线索。

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

### 第4步：配置 AI 分析 (可选，但推荐)

要使用 AI 增强分析功能，您需要提供 API 凭据。

1.  **复制示例文件：** 在 `backend_api` 目录中，将 `.env.example` 复制为名为 `.env` 的新文件。
    - **Windows:** `copy .env.example .env`
    - **CentOS/Linux:** `cp .env.example .env`

2.  **编辑 `.env` 文件** 并填入您的详细信息：
    ```ini
    # 例如 OpenAI
    AI_API_URL="https://api.openai.com/v1/chat/completions"
    AI_API_KEY="your_openai_api_key_here"
    AI_MODEL="gpt-4"

    # 例如本地运行的 Ollama
    # AI_API_URL="http://localhost:11434/api/chat"
    # AI_API_KEY="ollama" # 可以是任意非空字符串
    # AI_MODEL="llama3"
    ```

### 第5步：运行后端服务器

请确保您位于 `backend_api` 目录中，并已激活虚拟环境。

```bash
# 服务器默认将在 http://localhost:5000 运行
flask run --host=0.0.0.0
```
后端 API 现在已成功运行并准备好接受请求。

---

## 第二部分：前端设置 (静态 Web 应用)

前端是一组静态的 HTML、CSS 和 JS 文件，可以由任何简单的 Web 服务器托管。

### 简便方法：使用 Python 内置服务器

只要您安装了 Python，此方法在 Windows 和 CentOS/Linux 上均可使用。

1.  打开一个 **新的终端** (不要关闭您的后端终端)。
2.  进入 `frontend_static` 目录。
    ```bash
    cd frontend_static
    ```
3.  启动 HTTP 服务器。
    ```bash
    # 适用于 Python 3
    python3 -m http.server 8080
    ```
    服务器通常会在 8080 端口上运行。

### 访问应用程序

当后端和前端服务器都成功运行后：

1.  打开您的网络浏览器。
2.  访问前端 URL: **`http://localhost:8080`** (或您用于前端的端口)。

您现在可以上传文件并查看分析结果了。前端将与运行在 5000 端口的后端 API 进行通信。如果您的后端位于不同的 URL，可以编辑 `frontend_static/script.js` 文件顶部的 `API_BASE_URL` 常量。
