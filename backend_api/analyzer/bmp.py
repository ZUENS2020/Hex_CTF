import struct
from .common import add_finding

def analyze(data, findings):
    """Parses the BMP file header and DIB header."""
    try:
        # BITMAPFILEHEADER (14 bytes)
        file_header = struct.unpack('<HIHHI', data[0:14])
        bfType, bfSize, bfReserved1, bfReserved2, bfOffBits = file_header

        if bfType != 0x4D42: # 'BM'
            return None

        # BITMAPINFOHEADER (starts at offset 14, size is 40 bytes for V3)
        dib_header_size = struct.unpack('<I', data[14:18])[0]

        # We'll assume a standard BITMAPINFOHEADER for simplicity
        if dib_header_size >= 40:
            dib_header = struct.unpack('<IiiHHIIiiII', data[14:54])
            (biSize, biWidth, biHeight, biPlanes, biBitCount, biCompression,
             biSizeImage, biXPelsPerMeter, biYPelsPerMeter, biClrUsed, biClrImportant) = dib_header

            structure = [{
                "type": "bmp_file_header",
                "name": "BITMAPFILEHEADER",
                "details": {
                    "FileType": f"0x{bfType:X} ('BM')",
                    "FileSize": f"{bfSize} bytes",
                    "PixelDataOffset": f"0x{bfOffBits:X}"
                }
            }, {
                "type": "bmp_info_header",
                "name": "BITMAPINFOHEADER (V3)",
                "details": {
                    "HeaderSize": f"{biSize} bytes",
                    "ImageWidth": biWidth,
                    "ImageHeight": biHeight,
                    "ColorPlanes": biPlanes,
                    "BitsPerPixel": biBitCount,
                    "CompressionMethod": biCompression,
                    "ImageSize": f"{biSizeImage} bytes",
                    "HorizontalResolution": f"{biXPelsPerMeter} px/m",
                    "VerticalResolution": f"{biYPelsPerMeter} px/m",
                    "NumColorsInPalette": biClrUsed,
                    "NumImportantColors": biClrImportant
                }
            }]
            return structure
    except (struct.error, IndexError):
        add_finding(findings, type="BMP Parse Error", severity="WARNING",
            description="Failed to parse BMP headers. The file may be truncated or malformed.")

    return None
