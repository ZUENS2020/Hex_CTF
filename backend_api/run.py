"""
启动 Flask 应用服务器
"""
import os
import sys
from app import app, CONFIG

def main():
    """主函数"""
    host = CONFIG["server"]["host"]
    port = CONFIG["server"]["port"]
    debug = CONFIG["server"]["debug"]
    
    print(f"启动服务器于 {host}:{port}")
    app.run(host=host, port=port, debug=debug)

if __name__ == "__main__":
    # 确保在正确的目录中
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    main()