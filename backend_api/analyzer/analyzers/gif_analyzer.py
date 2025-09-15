import struct
from .base_analyzer import BaseAnalyzer
from ..core import add_finding

class GifAnalyzer(BaseAnalyzer):
    name = "gif"

    def can_analyze(self, data, magic_bytes_info):
        return magic_bytes_info.get('magic_bytes_type') == 'GIF'

    def analyze(self, file_storage, data, findings):
        try:
            if not (data.startswith(b'GIF87a') or data.startswith(b'GIF89a')):
                return None

            lsd = struct.unpack('<HHBHH', data[6:13])

            return [{
                "type": "gif_header",
                "name": "GIF Header",
                "details": {
                    "Version": data[0:6].decode(),
                    "CanvasWidth": lsd[0],
                    "CanvasHeight": lsd[1]
                }
            }]
        except:
            add_finding(findings, type="GIF Parse Error", severity="WARNING", description="Failed to parse GIF headers.")

        return None
