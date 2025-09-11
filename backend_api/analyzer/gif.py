import struct
from .common import add_finding

def analyze(data, findings):
    """Parses the GIF Header and Logical Screen Descriptor."""
    try:
        # Header (6 bytes)
        header = data[0:6].decode('ascii')
        if not (header.startswith('GIF87a') or header.startswith('GIF89a')):
            return None

        # Logical Screen Descriptor (7 bytes)
        lsd = struct.unpack('<HHBHH', data[6:13])
        (width, height, packed_fields, bg_color_index, pixel_aspect_ratio) = lsd

        has_global_color_table = (packed_fields & 0b10000000) != 0
        color_resolution = ((packed_fields & 0b01110000) >> 4) + 1
        sort_flag = (packed_fields & 0b00001000) != 0
        size_of_global_color_table = 2 ** ((packed_fields & 0b00000111) + 1)

        structure = [{
            "type": "gif_header",
            "name": "Header",
            "details": {
                "Version": header
            }
        }, {
            "type": "gif_lsd",
            "name": "Logical Screen Descriptor",
            "details": {
                "CanvasWidth": width,
                "CanvasHeight": height,
                "HasGlobalColorTable": has_global_color_table,
                "ColorResolution": f"{color_resolution}-bit",
                "IsSorted": sort_flag,
                "GlobalColorTableSize": f"{size_of_global_color_table} entries"
            }
        }]
        return structure

    except (struct.error, IndexError, UnicodeDecodeError):
        add_finding(findings, type="GIF Parse Error", severity="WARNING",
            description="Failed to parse GIF headers. The file may be truncated or malformed.")

    return None
