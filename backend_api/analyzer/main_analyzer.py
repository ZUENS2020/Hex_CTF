import os
import hashlib
import zlib
import zipfile
import re
import math
import struct
import base64
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
    # Each entry is a tuple: (magic_bytes, offset, type_name, mime_type)
    # Images
    (b'\x89PNG\r\n\x1a\n', 0, 'PNG', 'image/png'),
    (b'\xFF\xD8\xFF', 0, 'JPEG', 'image/jpeg'),
    (b'GIF89a', 0, 'GIF', 'image/gif'),
    (b'GIF87a', 0, 'GIF', 'image/gif'),
    (b'II*\x00', 0, 'TIFF (Little-endian)', 'image/tiff'),
    (b'MM\x00*', 0, 'TIFF (Big-endian)', 'image/tiff'),
    (b'BM', 0, 'BMP', 'image/bmp'),
    (b'8BPS', 0, 'PSD', 'image/vnd.adobe.photoshop'),
    # Archives
    (b'PK\x03\x04', 0, 'ZIP', 'application/zip'),
    (b'Rar!\x1a\x07\x00', 0, 'RAR', 'application/x-rar-compressed'),
    (b'Rar!\x1a\x07\x01\x00', 0, 'RAR5', 'application/x-rar-compressed'),
    (b'7z\xbc\xaf\x27\x1c', 0, '7z', 'application/x-7z-compressed'),
    (b'\x1f\x8b', 0, 'GZ', 'application/gzip'),
    (b'BZ', 0, 'BZ2', 'application/x-bzip2'),
    # Documents
    (b'%PDF-', 0, 'PDF', 'application/pdf'),
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 0, 'DOC/XLS/PPT (OLE)', 'application/msword'),
    (b'{\\rtf', 0, 'RTF', 'application/rtf'),
    (b'<?xml', 0, 'XML', 'application/xml'),
    # Executables
    (b'MZ', 0, 'EXE/DLL (Windows)', 'application/x-msdownload'),
    (b'\x7fELF', 0, 'ELF (Linux)', 'application/x-elf'),
    # Audio/Video (with offsets)
    (b'WAVE', 8, 'WAV', 'audio/x-wav'),
    (b'AVI ', 8, 'AVI', 'video/x-msvideo'),
    (b'MThd', 0, 'MIDI', 'audio/midi'),
    # Other
    (b'AC10', 0, 'DWG', 'image/vnd.dwg'),
    (b'Delivery-date:', 0, 'EML', 'message/rfc822'),
    (b'!BDN', 0, 'PST', 'application/vnd.ms-outlook'),
    (b'Standard J', 0, 'MDB', 'application/x-msaccess'),
]

# --- Helper Functions ---

def add_finding(findings, type, severity, description, **kwargs):
    """A helper to create and add a finding, with automatic tool recommendation."""
    finding = {
        "type": type,
        "severity": severity,
        "description": description,
    }
    finding.update(kwargs)

    if type in RECOMMENDED_TOOLS:
        finding["recommended_tool"] = RECOMMENDED_TOOLS[type]

    findings.append(finding)

def calculate_hashes(data):
    return {
        'md5': hashlib.md5(data).hexdigest(),
        'sha1': hashlib.sha1(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest(),
    }

def get_hex_preview(data):
    head = data[:HEX_PREVIEW_BYTES]
    tail = data[-HEX_PREVIEW_BYTES:] if len(data) > HEX_PREVIEW_BYTES else b''
    return {
        'head': head.hex(),
        'head_ascii': ''.join(chr(b) if 32 <= b < 127 else '.' for b in head),
        'tail': tail.hex(),
        'tail_ascii': ''.join(chr(b) if 32 <= b < 127 else '.' for b in tail),
    }

def calculate_entropy(data):
    if not data:
        return 0.0
    # Using numpy for efficient calculation
    _, counts = np.unique(np.frombuffer(data, dtype=np.uint8), return_counts=True)
    probabilities = counts / len(data)
    entropy = -np.sum(probabilities * np.log2(probabilities))
    return entropy

def extract_strings(data):
    strings = []
    # Using a regex to find sequences of printable characters
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
        # Ensure the data is long enough for the check
        if len(data) > offset + len(magic_seq):
            # Read the slice of data from the specified offset
            data_slice = data[offset : offset + len(magic_seq)]
            if data_slice == magic_seq:
                # For files like WAV, an additional check at the start is good practice
                if file_type == 'WAV' and not data.startswith(b'RIFF'):
                    continue
                return {"magic_bytes_type": file_type, "mime_type": mime}
    return {"magic_bytes_type": "Unknown", "mime_type": "application/octet-stream"}

def analyze_png_file(data, findings):
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
                    # Unpack the full IHDR chunk
                    width, height, bit_depth, color_type, comp_method, filter_method, interlace_method = \
                        struct.unpack('>IIBBBBB', chunk_data)

                    # Add a finding with the basic dimensions
                    add_finding(findings, type="PNG Image Dimensions", severity="INFO",
                        description=f"PNG IHDR chunk found. Image dimensions are {width}x{height}.",
                        value=f"Width: {width}, Height: {height}")

                    # Replace the simple chunk entry in the structure with a detailed one
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


def analyze_zip_file(file_path, findings):
    """Performs deep structure analysis on ZIP files by raw-scanning for headers."""
    LOCAL_HEADER_SIG = b'PK\x03\x04'
    structure = []

    with open(file_path, 'rb') as f:
        data = f.read()

    # Get official file list from Central Directory for comparison later
    official_filenames = set()
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            official_filenames = {info.filename for info in zf.infolist()}
    except zipfile.BadZipFile:
        pass # Will be handled by raw scan

    offset = 0
    while (offset := data.find(LOCAL_HEADER_SIG, offset)) != -1:
        try:
            header_data = data[offset:offset+30]
            if len(header_data) < 30:
                break # Truncated header

            # Unpack the local file header structure
            (sig, ver, gp_flag, comp_meth, mod_time, mod_date, crc32, comp_size, uncomp_size, name_len, extra_len) = \
                struct.unpack('<IHHHHHIIIHH', header_data)

            # Decode filename
            filename_bytes = data[offset+30 : offset+30+name_len]
            filename = filename_bytes.decode('utf-8', 'ignore')

            is_encrypted = (gp_flag & 0x1) != 0

            header_info = {
                "type": "zip_local_header",
                "offset": f"0x{offset:X}",
                "filename": filename,
                "version_needed": ver,
                "general_purpose_bit_flag": f"0x{gp_flag:04X}",
                "compression_method": comp_meth,
                "crc-32": f"0x{crc32:08X}",
                "compressed_size": comp_size,
                "uncompressed_size": uncomp_size,
                "is_encrypted": is_encrypted,
                "is_indexed": filename in official_filenames
            }
            structure.append(header_info)

            # Add findings based on parsed data
            if not header_info["is_indexed"] and filename:
                 add_finding(findings, type="Hidden ZIP Entry Found", severity="CRITICAL",
                    description=f"A file entry for '{filename}' was found via raw scan but is not listed in the ZIP's central directory.",
                    offset=offset)

            if is_encrypted:
                add_finding(findings, type="Encrypted ZIP Member", severity="WARNING",
                    description=f"File '{filename}' is marked as encrypted (GP Flag Bit 0 is set).",
                    offset=offset)
                if comp_meth == 8: # Deflate
                    add_finding(findings, type="Potential Known-Plaintext Attack", severity="WARNING",
                        description=f"File '{filename}' uses traditional ZipCrypto (Deflate), which is vulnerable to known-plaintext attacks.",
                        offset=offset)

            offset += 30 + name_len + extra_len + comp_size
        except (struct.error, IndexError):
            offset += 1
            continue

    return structure

def analyze_rar_file(file_path, findings):
    """Lists files inside a RAR archive using the rarfile library."""
    if not rarfile:
        add_finding(findings, type="RAR Support Notice", severity="INFO",
            description="The 'rarfile' library is not installed in the environment. RAR analysis is limited.")
        return None

    try:
        with rarfile.RarFile(file_path, 'r') as rf:
            structure = []
            for info in rf.infolist():
                structure.append({
                    "type": "rar_entry", "name": info.filename,
                    "uncompressed_size": info.file_size,
                    "timestamp": info.date_time,
                    "is_dir": info.isdir(),
                })
            return structure
    except rarfile.NotRarFile:
        add_finding(findings, type="RAR Error", severity="CRITICAL",
            description="The file is not a valid RAR archive, despite matching magic bytes.")
    except rarfile.PasswordRequired:
        add_finding(findings, type="RAR Encrypted", severity="WARNING",
            description="The RAR archive is encrypted and requires a password to list contents.")
    except Exception as e:
        add_finding(findings, type="RAR Read Error", severity="CRITICAL",
            description=f"An error occurred while reading the RAR file: {e}")

    return None


def analyze_strings_for_urls(strings_list, findings):
    """Analyzes extracted strings for URLs."""
    for s in strings_list:
        for match in URL_REGEX.finditer(s['content']):
            add_finding(findings,
                type="URL Found", severity="INFO",
                description="Found a URL in the file.",
                offset=s['offset'] + match.start(),
                value=match.group(0)
            )

def analyze_strings_for_keywords(strings_list, findings):
    """Analyzes extracted strings for CTF-related keywords."""
    for s in strings_list:
        # We search the content of the string for keywords
        for match in CTF_KEYWORD_REGEX.finditer(s['content']):
            add_finding(findings,
                type="Potential CTF Keyword", severity="INFO",
                description=f"Found keyword '{match.group(0)}' in a string.",
                offset=s['offset'] + match.start(),
                value=s['content']
            )

def analyze_eof_data(data, findings):
    eof_markers = {
        'JPEG': b'\xFF\xD9',
        'PNG': b'IEND\xaeB`\x82',
        'GIF': b'\x00\x3b',
    }
    file_type = analyze_magic_bytes(data)['magic_bytes_type']

    if file_type in eof_markers:
        marker = eof_markers[file_type]
        eof_pos = data.rfind(marker)
        if eof_pos != -1:
            extra_data_pos = eof_pos + len(marker)
            if extra_data_pos < len(data):
                extra_data = data[extra_data_pos:]
                add_finding(findings,
                    type="Data Appended Past EOF", severity="WARNING",
                    description=f"Found {len(extra_data)} byte(s) of extra data after the standard {file_type} End-Of-File marker.",
                    offset=extra_data_pos,
                    value=extra_data.hex()
                )


# --- Main Orchestrator ---

def analyze_file(file_storage):
    """
    Main function to analyze a file from a Flask FileStorage object.
    """
    filename = file_storage.filename
    file_storage.seek(0)
    data = file_storage.read()
    file_storage.seek(0) # Reset pointer for other potential reads

    # Save to a temporary file for libraries that need a path
    temp_dir = "/tmp" if os.name == 'posix' else os.environ.get("TEMP", "C:\\temp")
    if not os.path.exists(temp_dir): os.makedirs(temp_dir)
    temp_path = os.path.join(temp_dir, filename)
    file_storage.save(temp_path)

    findings = []
    file_structure = None

    # --- Basic Analysis ---
    file_size = len(data)
    file_hashes = calculate_hashes(data)
    hex_preview = get_hex_preview(data)
    entropy = calculate_entropy(data)
    extracted_strings = extract_strings(data)

    # --- File Type Analysis ---
    magic_analysis = analyze_magic_bytes(data)
    _, extension = os.path.splitext(filename)

    # Since python-magic-bin is unavailable, we rely solely on our internal magic byte DB.
    # The advanced mismatch check is no longer possible. We can add a simple one if needed.
    file_type_analysis = {
        "magic_bytes_type": magic_analysis['magic_bytes_type'],
        "extension": extension,
    }

    # --- Deep Analysis ---
    analyze_strings_for_keywords(extracted_strings, findings)
    analyze_strings_for_urls(extracted_strings, findings)
    analyze_eof_data(data, findings)

    file_type = file_type_analysis['magic_bytes_type']
    if file_type == 'ZIP':
        file_structure = analyze_zip_file(temp_path, findings)
    elif file_type == 'PNG':
        file_structure = analyze_png_file(data, findings)
    elif file_type in ('RAR', 'RAR5'):
        file_structure = analyze_rar_file(temp_path, findings)

    # Clean up temporary file
    os.remove(temp_path)

    return {
        "filename": filename,
        "filesize": file_size,
        "file_digest": file_hashes,
        "hex_ascii_preview": hex_preview,
        "overall_entropy": entropy,
        "file_type_analysis": file_type_analysis,
        "findings": findings,
        "extracted_strings": extracted_strings,
        "metadata": {}, # Placeholder for future metadata extraction
        "file_structure": file_structure,
    }
