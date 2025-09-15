# 全栈 CTF Misc题目文件分析器

本项目是一个为 CTF (Capture The Flag) 竞赛设计的、功能完善的在线文件分析工具。它由一个用于深度文件分析的 Python Flask 后端和一个用于用户交互的轻量级 Vanilla JavaScript 前端组成。该工具旨在帮助参赛者快速识别文件异常、隐藏信息、伪加密、隐写术以及其他常见的CTF线索。

本项目经过精心设计，可轻松部署在 **Windows** 和 **CentOS/Linux** 环境中。

## 项目结构

```
.
├── config.json             # <--- 项目配置文件
├── backend_api/
│   ├── analyzer/
│   │   ├── analyzers/      # <--- 模块化分析器目录
│   │   │   ├── __init__.py
│   │   │   ├── base_analyzer.py
│   │   │   ├── bmp_analyzer.py
│   │   │   ├── gif_analyzer.py
│   │   │   ├── png_analyzer.py
│   │   │   ├── rar_analyzer.py
│   │   │   └── zip_analyzer.py
│   │   ├── __init__.py
│   │   ├── core.py         # <--- 核心函数
│   │   └── main_analyzer.py  # <--- 分析器加载与协调器
│   ├── app.py              # <--- Flask应用主文件
│   ├── run.py              # <--- 应用启动脚本
│   └── requirements.txt    # <--- 依赖包列表
├── frontend_static/
│   ├── index.html
│   ├── script.js
│   └── style.css
└── README.md
```

## 核心功能

- **模块化与可扩展的分析器**: 系统的核心是一个动态加载的模块化分析引擎。您可以轻松编写自己的分析器来扩展工具的功能，以应对新的文件类型或挑战。
- **文件上传与十六进制/ASCII预览**: 上传任意文件，并以十六进制编辑器格式查看其头部和尾部数据。
- **文件类型分析**: 通过专门的魔法字节数据库，精确检测多种文件类型，包括：
    - 图片格式：PNG、JPEG、GIF、BMP
    - 压缩格式：ZIP、RAR(包括RAR5)
    - 音频格式：WAV
- **字符串与特征提取**: 
    - 提取所有可打印字符串（最小长度4个字符）
    - 自动识别CTF格式的flag（如`flag{...}`或`ctf{...}`）
    - 检测常见CTF关键字（flag、ctf、key、password、secret、crypto等）
    - 自动提取URL链接
- **熵分析**: 计算数据熵，以识别加密或压缩的数据区域。
- **深度分析与结构解析**:
    - **ZIP**: 详细解析每个文件的本地头，检测伪加密，发现隐藏文件。
    - **PNG**: 解析IHDR块，进行CRC校验，检测数据块完整性。
    - **BMP**: 解析文件头、颜色表和像素数据。
    - **GIF**: 分析文件头、逻辑屏幕描述符和图像块。
    - **RAR**: 支持RAR4和RAR5格式，解析文件头和存档内容。
- **推荐工具**: 根据分析发现，自动推荐相关的第三方CTF工具（例如 `binwalk`, `bkcrack` 等）。

---

## 可扩展的分析器

本工具最大的特点之一是其模块化的分析器架构。您可以为任何文件格式创建自己的分析器，而无需修改核心代码。

详细的开发指南请参见 `backend_api/analyzer/analyzers/README.md`。

---

## 后端设置 (Flask API)

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

### 第4步：启动应用

在 backend_api 目录下，运行以下命令启动服务器：

```bash
flask run --host=0.0.0.0
```

服务器将在 5000 端口上启动，支持局域网访问。

> 注：如果需要自定义服务器配置，可以编辑项目根目录下的 `config.json` 文件。配置将在运行时自动加载。

---

## 依赖说明

本项目依赖以下Python包：

- **Flask**: Web应用框架
- **Flask-Cors**: 处理跨域资源共享
- **numpy**: 用于数值计算和熵分析
- **Pillow**: 图像处理库
- **rarfile**: RAR文件格式支持

在项目根目录下创建 `config.json` 文件（如果不存在），配置示例如下：

```json
{
    "server": {
        "host": "0.0.0.0",
        "port": 5000,
        "debug": false,
        "max_content_length": 52428800
    },
    "cors": {
        "allow_origins": "*",
        "allow_methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    },
    "cloudflare": {
        "tunnel_domain": "your-domain.example.com",
        "enabled": true
    },
    "security": {
        "allowed_extensions": ["zip", "rar", "png", "jpg", "jpeg", "gif", "bmp"],
        "max_file_size_mb": 50
    },
    "features": {
        "enable_string_extraction": true,
        "enable_entropy_analysis": true,
        "enable_file_structure_analysis": true,
        "enable_hex_preview": true
    }
}
```

配置说明：
- `server`: 服务器基本配置
  - `host`: 监听地址
  - `port`: 监听端口
  - `debug`: 调试模式
  - `max_content_length`: 最大上传文件大小（字节）
- `cors`: 跨域资源共享配置
- `cloudflare`: Cloudflare Tunnel 配置
- `security`: 安全相关配置
- `features`: 功能开关配置

---
