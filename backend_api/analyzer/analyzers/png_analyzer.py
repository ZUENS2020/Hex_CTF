import struct
import zlib
from .base_analyzer import BaseAnalyzer
from ..core import add_finding

class PngAnalyzer(BaseAnalyzer):
    name = "png"

    def can_analyze(self, data, magic_bytes_info):
        return magic_bytes_info.get('magic_bytes_type') == 'PNG'

    def analyze(self, file_storage, data, findings):
        PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'
        if not data.startswith(PNG_SIGNATURE):
            return None

        structure = []
        offset = len(PNG_SIGNATURE)
        while offset < len(data):
            try:
                length = struct.unpack('>I', data[offset:offset+4])[0]
                chunk_type_bytes = data[offset+4:offset+8]
                chunk_type_str = chunk_type_bytes.decode('ascii', 'ignore')
                structure.append({"type": "chunk", "name": chunk_type_str, "size": length, "offset": offset})

                offset += 8
                chunk_data = data[offset:offset+length]
                stored_crc = struct.unpack('>I', data[offset+length:offset+length+4])[0]
                calculated_crc = zlib.crc32(chunk_type_bytes + chunk_data)

                if calculated_crc != stored_crc:
                    add_finding(findings, type="PNG CRC Mismatch", severity="CRITICAL", description=f"CRC mismatch in chunk '{chunk_type_str}'.", offset=offset - 8, value=f"Expected: {stored_crc}, Got: {calculated_crc}")

                if chunk_type_bytes == b'IHDR':
                    if length == 13:
                        width, height, bit_depth, color_type, comp, filt, inter = struct.unpack('>IIBBBBB', chunk_data)
                        add_finding(findings, type="PNG Image Dimensions", severity="INFO", description=f"Image dimensions are {width}x{height}.", value=f"Width: {width}, Height: {height}")
                        for item in structure:
                            if item["name"] == "IHDR":
                                item["details"] = {"width": width, "height": height, "bit_depth": bit_depth, "color_type": color_type, "compression": comp, "filter": filt, "interlace": inter}
                                break
                    else:
                        add_finding(findings, type="PNG Malformed IHDR", severity="WARNING", description="IHDR chunk has incorrect length.", offset=offset - 8)

                offset += length + 4
                if chunk_type_bytes == b'IEND':
                    break
            except (struct.error, IndexError):
                add_finding(findings, type="PNG Parse Error", severity="CRITICAL", description="Failed to parse a PNG chunk.", offset=offset)
                break

        return structure
