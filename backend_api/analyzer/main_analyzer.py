import os
import hashlib
import re
import struct
import zipfile
import zlib
import numpy as np
from PIL import Image

try:
    import rarfile
except ImportError:
    rarfile = None

# --- Configuration ---
STRING_MIN_LEN = 4
HEX_PREVIEW_BYTES = 256

CTF_FLAG_REGEX = re.compile(r'flag\{[a-zA-Z0-9_!@#$-]+\}|ctf\{[a-zA-Z0-9_!@#$-]+\}', re.IGNORECASE)
CTF_KEYWORD_REGEX = re.compile(r'\b(flag|ctf|key|password|secret|crypto)\b', re.IGNORECASE)
URL_REGEX = re.compile(r'https?://[^\s/$.?#].[^\s]*|www\.[^\s/$.?#].[^\s]*', re.IGNORECASE)

RECOMMENDED_TOOLS = {
    "Potential Known-Plaintext Attack": {"name": "bkcrack", "description": "A tool for breaking ZipCrypto encryption."},
    "Data Appended Past EOF": {"name": "binwalk / foremost", "description": "Tools for carving and extracting hidden files from data streams."},
    "Encrypted ZIP Member": {"name": "7-Zip / John the Ripper", "description": "7-Zip can sometimes open pseudo-encrypted files. John can be used for password cracking."},
    "PNG CRC Mismatch": {"name": "pngcheck / Hex Editor", "description": "pngcheck can diagnose PNG errors. A hex editor allows for manual inspection and repair."},
    "Hidden ZIP Entry Found": {"name": "A hex editor or forensic tool", "description": "These tools can help manually extract or analyze unindexed file entries."}
}

MAGIC_BYTES_DB = [
    (b'\x89PNG\r\n\x1a\n', 0, 'PNG', 'image/png'),
    (b'\xFF\xD8\xFF', 0, 'JPEG', 'image/jpeg'),
    (b'GIF89a', 0, 'GIF', 'image/gif'),
    (b'GIF87a', 0, 'GIF', 'image/gif'),
    (b'BM', 0, 'BMP', 'image/bmp'),
    (b'PK\x03\x04', 0, 'ZIP', 'application/zip'),
    (b'Rar!\x1a\x07\x00', 0, 'RAR', 'application/x-rar-compressed'),
    (b'Rar!\x1a\x07\x01\x00', 0, 'RAR5', 'application/x-rar-compressed'),
    (b'WAVE', 8, 'WAV', 'audio/x-wav'),
]

# --- Helper Functions ---
def add_finding(findings, type, severity, description, **kwargs):
    finding = {"type": type, "severity": severity, "description": description}
    finding.update(kwargs)
    if type in RECOMMENDED_TOOLS:
        finding["recommended_tool"] = RECOMMENDED_TOOLS[type]
    findings.append(finding)

def calculate_hashes(data):
    return {'md5': hashlib.md5(data).hexdigest(), 'sha1': hashlib.sha1(data).hexdigest(), 'sha256': hashlib.sha256(data).hexdigest()}

def get_hex_preview(data):
    head = data[:HEX_PREVIEW_BYTES]
    tail = data[-HEX_PREVIEW_BYTES:] if len(data) > HEX_PREVIEW_BYTES else b''
    return {
        'head': head.hex(), 'head_ascii': ''.join(chr(b) if 32 <= b < 127 else '.' for b in head),
        'tail': tail.hex(), 'tail_ascii': ''.join(chr(b) if 32 <= b < 127 else '.' for b in tail),
    }

def calculate_entropy(data):
    if not data: return 0.0
    _, counts = np.unique(np.frombuffer(data, dtype=np.uint8), return_counts=True)
    probabilities = counts / len(data)
    return -np.sum(probabilities * np.log2(probabilities))

def extract_strings(data):
    strings = []
    for match in re.finditer(rb'[\x20-\x7E\x09\x0A\x0D]{' + str(STRING_MIN_LEN).encode() + rb',}', data):
        try:
            s = match.group().decode('ascii')
            is_flag = bool(CTF_FLAG_REGEX.search(s))
            strings.append({"offset": match.start(), "content": s, "is_flag": is_flag})
        except UnicodeDecodeError:
            continue
    return strings

def analyze_magic_bytes(data):
    for magic_seq, offset, file_type, mime in MAGIC_BYTES_DB:
        if len(data) > offset + len(magic_seq):
            data_slice = data[offset : offset + len(magic_seq)]
            if data_slice == magic_seq:
                if file_type == 'WAV' and not data.startswith(b'RIFF'): continue
                return {"magic_bytes_type": file_type, "mime_type": mime}
    return {"magic_bytes_type": "Unknown", "mime_type": "application/octet-stream"}

# --- Format-Specific Analyzers ---
def analyze_zip(file_path, findings):
    LOCAL_HEADER_SIG = b'PK\x03\x04'
    structure = []
    with open(file_path, 'rb') as f: data = f.read()
    official_filenames = set()
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            official_filenames = {info.filename for info in zf.infolist()}
    except zipfile.BadZipFile: pass
    offset = 0
    while (offset := data.find(LOCAL_HEADER_SIG, offset)) != -1:
        try:
            header_data = data[offset:offset+30]
            if len(header_data) < 30: break
            (sig, ver, gp_flag, comp_meth, mod_time, mod_date, crc32, comp_size, uncomp_size, name_len, extra_len) = struct.unpack('<IHHHHHIIIHH', header_data)
            filename = data[offset+30 : offset+30+name_len].decode('utf-8', 'ignore')
            is_encrypted = (gp_flag & 0x1) != 0
            header_info = {"type": "zip_local_header", "offset": f"0x{offset:X}", "filename": filename, "version_needed": ver, "general_purpose_bit_flag": f"0x{gp_flag:04X}", "compression_method": comp_meth, "crc-32": f"0x{crc32:08X}", "compressed_size": comp_size, "uncompressed_size": uncomp_size, "is_encrypted": is_encrypted, "is_indexed": filename in official_filenames}
            structure.append(header_info)
            if not header_info["is_indexed"] and filename:
                 add_finding(findings, type="Hidden ZIP Entry Found", severity="CRITICAL", description=f"A file entry for '{filename}' was found via raw scan but is not listed in the ZIP's central directory.", offset=offset)
            if is_encrypted:
                add_finding(findings, type="Encrypted ZIP Member", severity="WARNING", description=f"File '{filename}' is marked as encrypted (GP Flag Bit 0 is set).", offset=offset)
                if comp_meth == 8:
                    add_finding(findings, type="Potential Known-Plaintext Attack", severity="WARNING", description=f"File '{filename}' uses traditional ZipCrypto (Deflate), which is vulnerable to known-plaintext attacks.", offset=offset)
            offset += 30 + name_len + extra_len + comp_size
        except (struct.error, IndexError):
            offset += 1
            continue
    return structure

def analyze_png(data, findings):
    PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'
    if not data.startswith(PNG_SIGNATURE): return None
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
                else: add_finding(findings, type="PNG Malformed IHDR", severity="WARNING", description="IHDR chunk has incorrect length.", offset=offset - 8)
            offset += length + 4
            if chunk_type_bytes == b'IEND': break
        except (struct.error, IndexError):
            add_finding(findings, type="PNG Parse Error", severity="CRITICAL", description="Failed to parse a PNG chunk.", offset=offset)
            break
    return structure

def analyze_rar(file_path, findings):
    if not rarfile: return None
    try:
        with rarfile.RarFile(file_path, 'r') as rf:
            return [{"type": "rar_entry", "name": info.filename, "size": info.file_size, "timestamp": info.date_time, "is_dir": info.isdir()} for info in rf.infolist()]
    except Exception as e:
        add_finding(findings, type="RAR Read Error", severity="CRITICAL", description=f"An error occurred reading the RAR file: {e}")
    return None

def analyze_bmp(data, findings):
    try:
        if not data.startswith(b'BM'): return None
        file_header = struct.unpack('<HIHHI', data[0:14])
        bfOffBits = file_header[4]
        dib_header = struct.unpack('<IiiHHIIiiII', data[14:54])
        return [{"type": "bmp_header", "name": "BMP Header", "details": {"FileSize": f"{file_header[1]} bytes", "PixelDataOffset": f"0x{bfOffBits:X}", "ImageWidth": dib_header[1], "ImageHeight": dib_header[2], "BitsPerPixel": dib_header[4]}}]
    except:
        add_finding(findings, type="BMP Parse Error", severity="WARNING", description="Failed to parse BMP headers.")
    return None

def analyze_gif(data, findings):
    try:
        if not (data.startswith(b'GIF87a') or data.startswith(b'GIF89a')): return None
        lsd = struct.unpack('<HHBHH', data[6:13])
        return [{"type": "gif_header", "name": "GIF Header", "details": {"Version": data[0:6].decode(), "CanvasWidth": lsd[0], "CanvasHeight": lsd[1]}}]
    except:
        add_finding(findings, type="GIF Parse Error", severity="WARNING", description="Failed to parse GIF headers.")
    return None

# --- Main Orchestrator ---

def analyze_file(file_storage):
    filename = file_storage.filename
    file_storage.seek(0)
    data = file_storage.read()
    temp_path = None

    findings = []
    file_structure = None

    file_type_analysis = analyze_magic_bytes(data)
    file_type = file_type_analysis.get('magic_bytes_type')

    # Dispatch to specific analyzer
    if file_type == 'ZIP':
        temp_path = _save_temp_file(file_storage)
        file_structure = analyze_zip(temp_path, findings)
    elif file_type == 'PNG':
        file_structure = analyze_png(data, findings)
    elif file_type in ('RAR', 'RAR5'):
        temp_path = _save_temp_file(file_storage)
        file_structure = analyze_rar(temp_path, findings)
    elif file_type == 'BMP':
        file_structure = analyze_bmp(data, findings)
    elif file_type == 'GIF':
        file_structure = analyze_gif(data, findings)

    # Universal string analysis
    extracted_strings = extract_strings(data)
    for s in extracted_strings:
        for match in URL_REGEX.finditer(s['content']):
            add_finding(findings, type="URL Found", severity="INFO", description="Found a URL.", offset=s['offset'] + match.start(), value=match.group(0))
        for match in CTF_KEYWORD_REGEX.finditer(s['content']):
            add_finding(findings, type="Potential CTF Keyword", severity="INFO", description=f"Found keyword '{match.group(0)}'.", offset=s['offset'] + match.start(), value=s['content'])

    if temp_path and os.path.exists(temp_path):
        os.remove(temp_path)

    return {
        "filename": filename, "filesize": len(data),
        "file_digest": calculate_hashes(data), "hex_ascii_preview": get_hex_preview(data),
        "overall_entropy": calculate_entropy(data), "file_type_analysis": file_type_analysis,
        "findings": findings, "extracted_strings": extracted_strings,
        "file_structure": file_structure,
    }

def _save_temp_file(file_storage):
    temp_dir = "/tmp" if os.name == 'posix' else os.environ.get("TEMP", "C:\\temp")
    if not os.path.exists(temp_dir): os.makedirs(temp_dir)
    temp_path = os.path.join(temp_dir, os.path.basename(file_storage.filename))
    file_storage.seek(0)
    with open(temp_path, 'wb') as f:
        f.write(file_storage.read())
    return temp_path
