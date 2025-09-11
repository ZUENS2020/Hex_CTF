import struct
import zlib
from .common import add_finding

def analyze(data, findings):
    """Parses PNG chunks to find dimensions, verify CRC, and return structure."""
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
                add_finding(findings, type="PNG CRC Mismatch", severity="CRITICAL",
                    description=f"CRC mismatch in chunk '{chunk_type_str}'. This indicates data corruption or tampering.",
                    offset=offset - 8, value=f"Expected CRC: {stored_crc}, Calculated CRC: {calculated_crc}")

            if chunk_type_bytes == b'IHDR':
                if length == 13:
                    width, height, bit_depth, color_type, comp_method, filter_method, interlace_method = \
                        struct.unpack('>IIBBBBB', chunk_data)

                    add_finding(findings, type="PNG Image Dimensions", severity="INFO",
                        description=f"PNG IHDR chunk found. Image dimensions are {width}x{height}.",
                        value=f"Width: {width}, Height: {height}")

                    for item in structure:
                        if item["name"] == "IHDR":
                            item["details"] = {
                                "width": width, "height": height, "bit_depth": bit_depth,
                                "color_type": color_type, "compression_method": comp_method,
                                "filter_method": filter_method, "interlace_method": interlace_method
                            }
                            break
                else:
                    add_finding(findings, type="PNG Malformed IHDR", severity="WARNING",
                        description="PNG IHDR chunk has an incorrect length.", offset=offset - 8)

            offset += length + 4
            if chunk_type_bytes == b'IEND':
                break
        except (struct.error, IndexError):
            add_finding(findings, type="PNG Parse Error", severity="CRITICAL",
                description="Failed to parse a PNG chunk. The file may be truncated or malformed.",
                offset=offset)
            break
    return structure
