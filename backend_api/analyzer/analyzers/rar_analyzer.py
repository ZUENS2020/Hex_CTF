try:
    import rarfile
except ImportError:
    rarfile = None

from .base_analyzer import BaseAnalyzer
from ..core import add_finding, _save_temp_file

class RarAnalyzer(BaseAnalyzer):
    name = "rar"

    def can_analyze(self, data, magic_bytes_info):
        return magic_bytes_info.get('magic_bytes_type') in ('RAR', 'RAR5')

    def analyze(self, file_storage, data, findings):
        if not rarfile:
            add_finding(findings, type="RAR Analysis Skipped", severity="INFO", description="The 'rarfile' package is not installed, skipping RAR analysis.")
            return None

        temp_path = _save_temp_file(file_storage)

        try:
            with rarfile.RarFile(temp_path, 'r') as rf:
                return [{"type": "rar_entry", "name": info.filename, "size": info.file_size, "timestamp": info.date_time, "is_dir": info.isdir()} for info in rf.infolist()]
        except Exception as e:
            add_finding(findings, type="RAR Read Error", severity="CRITICAL", description=f"An error occurred reading the RAR file: {e}")

        return None
