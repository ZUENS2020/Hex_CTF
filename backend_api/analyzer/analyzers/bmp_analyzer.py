import struct
from .base_analyzer import BaseAnalyzer
from ..core import add_finding

class BmpAnalyzer(BaseAnalyzer):
    name = "bmp"

    def can_analyze(self, data, magic_bytes_info):
        return magic_bytes_info.get('magic_bytes_type') == 'BMP'

    def analyze(self, file_storage, data, findings):
        try:
            if not data.startswith(b'BM'):
                return None

            file_header = struct.unpack('<HIHHI', data[0:14])
            bfOffBits = file_header[4]
            dib_header = struct.unpack('<IiiHHIIiiII', data[14:54])

            return [{
                "type": "bmp_header",
                "name": "BMP Header",
                "details": {
                    "FileSize": f"{file_header[1]} bytes",
                    "PixelDataOffset": f"0x{bfOffBits:X}",
                    "ImageWidth": dib_header[1],
                    "ImageHeight": dib_header[2],
                    "BitsPerPixel": dib_header[4]
                }
            }]
        except:
            add_finding(findings, type="BMP Parse Error", severity="WARNING", description="Failed to parse BMP headers.")

        return None
