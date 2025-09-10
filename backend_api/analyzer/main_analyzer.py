import os
import hashlib
import magic
import zlib
import zipfile
import re
import math
import struct
import numpy as np
from PIL import Image
from .ai_analyzer import analyze_text_with_ai

# --- Configuration ---
STRING_MIN_LEN = 4
HEX_PREVIEW_BYTES = 256
CTF_FLAG_REGEX = re.compile(r'flag\{[a-zA-Z0-9_!@#$-]+\}|ctf\{[a-zA-Z0-9_!@#$-]+\}', re.IGNORECASE)
CTF_KEYWORD_REGEX = re.compile(r'\b(flag|ctf|key|password|secret|crypto)\b', re.IGNORECASE)
MAGIC_BYTES_DB = {
    b'\x89PNG\r\n\x1a\n': ('PNG', 'image/png'),
    b'\xFF\xD8\xFF': ('JPEG', 'image/jpeg'),
    b'GIF87a': ('GIF', 'image/gif'),
    b'GIF89a': ('GIF', 'image/gif'),
    b'%PDF-': ('PDF', 'application/pdf'),
    b'PK\x03\x04': ('ZIP', 'application/zip'),
}

# --- Helper Functions ---

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
    for magic_seq, (file_type, mime) in MAGIC_BYTES_DB.items():
        if data.startswith(magic_seq):
            return {"magic_bytes_type": file_type, "mime_type": mime}
    return {"magic_bytes_type": "Unknown", "mime_type": "application/octet-stream"}

def analyze_png_file(data, findings):
    """Parses PNG chunks to find dimensions and verify CRC checksums."""
    PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'
    if not data.startswith(PNG_SIGNATURE):
        return

    offset = len(PNG_SIGNATURE)
    while offset < len(data):
        try:
            # Read chunk length and type
            length = struct.unpack('>I', data[offset:offset+4])[0]
            chunk_type = data[offset+4:offset+8]
            offset += 8

            # Read chunk data and CRC
            chunk_data = data[offset:offset+length]
            stored_crc = struct.unpack('>I', data[offset+length:offset+length+4])[0]

            # Verify CRC
            # The CRC is calculated over the chunk type and chunk data
            calculated_crc = zlib.crc32(chunk_type + chunk_data)

            if calculated_crc != stored_crc:
                findings.append({
                    "type": "PNG CRC Mismatch", "severity": "CRITICAL",
                    "description": f"CRC mismatch in chunk '{chunk_type.decode()}'. This indicates data corruption or tampering.",
                    "offset": offset - 8,
                    "value": f"Expected CRC: {stored_crc}, Calculated CRC: {calculated_crc}"
                })

            # Special handling for IHDR chunk
            if chunk_type == b'IHDR':
                if length == 13:
                    width, height = struct.unpack('>II', chunk_data[:8])
                    findings.append({
                        "type": "PNG Image Dimensions", "severity": "INFO",
                        "description": f"PNG IHDR chunk found. Image dimensions are {width}x{height}.",
                        "value": f"Width: {width}, Height: {height}"
                    })
                else:
                    findings.append({
                        "type": "PNG Malformed IHDR", "severity": "WARNING",
                        "description": "PNG IHDR chunk has an incorrect length.",
                        "offset": offset - 8,
                    })

            # Move to the next chunk
            offset += length + 4

            if chunk_type == b'IEND':
                break # Stop after the last chunk
        except (struct.error, IndexError):
            findings.append({
                "type": "PNG Parse Error", "severity": "CRITICAL",
                "description": "Failed to parse a PNG chunk. The file may be truncated or malformed.",
                "offset": offset
            })
            break


def analyze_zip_file(file_path, findings):
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            if zf.comment:
                findings.append({
                    "type": "ZIP Comment", "severity": "INFO",
                    "description": "The ZIP archive contains a global comment.",
                    "value": zf.comment.decode('utf-8', 'ignore')
                })

            for info in zf.infolist():
                # Pseudo-encryption check
                is_encrypted = (info.flag_bits & 0x1) != 0
                if is_encrypted and info.compress_size == info.file_size and info.CRC != 0:
                     # A simple heuristic: if encrypted but size hasn't changed much, it could be weak or pseudo
                     pass # More robust check is complex

                # General Purpose Bit Flag - Bit 0 is the encrypted flag
                if info.flag_bits & 0x1:
                    # A common form of pseudo-encryption sets the encryption bit but uses 0 for CRC
                    # This is not a foolproof check but a strong indicator for many CTF challenges.
                    if info.CRC == 0 and info.compress_type == zipfile.ZIP_STORED:
                         findings.append({
                            "type": "Potential ZIP Pseudo-encryption", "severity": "WARNING",
                            "description": f"File '{info.filename}' is marked as encrypted, but has a CRC of 0 and no compression. This is a strong indicator of pseudo-encryption.",
                            "hint": "Try using a tool to fix the ZIP file headers or simply unzipping with a tool that ignores this flag."
                        })

                # CRC check
                try:
                    with zf.open(info, 'r') as member_file:
                        member_data = member_file.read()
                        calculated_crc = zlib.crc32(member_data)
                        if calculated_crc != info.CRC and not is_encrypted:
                             findings.append({
                                "type": "ZIP CRC Mismatch", "severity": "CRITICAL",
                                "description": f"CRC32 mismatch for file '{info.filename}'. Expected {info.CRC}, got {calculated_crc}. The file may be corrupt or tampered with."
                            })
                except Exception as e:
                    findings.append({"type": "ZIP Member Read Error", "severity":"WARNING", "description": f"Could not process member {info.filename}: {e}"})

    except zipfile.BadZipFile:
        findings.append({"type": "ZIP Error", "severity": "CRITICAL", "description": "The file is not a valid ZIP archive or is corrupted."})


def analyze_strings_for_keywords(strings_list, findings):
    """Analyzes extracted strings for CTF-related keywords."""
    for s in strings_list:
        # We search the content of the string for keywords
        for match in CTF_KEYWORD_REGEX.finditer(s['content']):
            findings.append({
                "type": "Potential CTF Keyword",
                "severity": "INFO",
                "description": f"Found keyword '{match.group(0)}' in a string.",
                "offset": s['offset'] + match.start(),
                "value": s['content']
            })

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
                findings.append({
                    "type": "Data Appended Past EOF", "severity": "WARNING",
                    "description": f"Found {len(extra_data)} byte(s) of extra data after the standard {file_type} End-Of-File marker.",
                    "offset": extra_data_pos,
                    "value": extra_data.hex()
                })


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

    # --- Basic Analysis ---
    file_size = len(data)
    file_hashes = calculate_hashes(data)
    hex_preview = get_hex_preview(data)
    entropy = calculate_entropy(data)
    extracted_strings = extract_strings(data)

    # --- File Type Analysis ---
    magic_analysis = analyze_magic_bytes(data)
    try:
        libmagic_type = magic.from_buffer(data, mime=True)
    except Exception as e:
        # If libmagic fails, we can't make a comparison, so we default to a non-mismatching type
        libmagic_type = "N/A"

    _, extension = os.path.splitext(filename)

    # A mismatch occurs ONLY if libmagic provides a valid, different MIME type.
    # We ignore cases where libmagic fails ("N/A") or gives a generic response.
    type_mismatch = (
        libmagic_type not in ("N/A", "application/octet-stream") and
        magic_analysis.get('mime_type') != libmagic_type
    )

    file_type_analysis = {
        "magic_bytes_type": magic_analysis['magic_bytes_type'],
        "extension": extension,
        "libmagic_type": libmagic_type,
        "type_mismatch": type_mismatch
    }
    if type_mismatch:
        findings.append({
            "type": "File Type Mismatch", "severity": "WARNING",
            "description": f"File extension '{extension}' does not match the detected content type '{libmagic_type}'. The file may be disguised."
        })

    # --- Deep Analysis ---
    analyze_strings_for_keywords(extracted_strings, findings)
    analyze_eof_data(data, findings)
    if file_type_analysis['magic_bytes_type'] == 'ZIP':
        analyze_zip_file(temp_path, findings)
    elif file_type_analysis['magic_bytes_type'] == 'PNG':
        analyze_png_file(data, findings)

    # --- AI Analysis ---
    ai_input_text = f"Filename: {filename}\nFile Size: {file_size} bytes\n\n--- Notable Strings ---\n"
    flag_strings = [s['content'] for s in extracted_strings if s['is_flag']]
    if flag_strings:
        ai_input_text += "Found potential flags:\n" + "\n".join(flag_strings) + "\n\n"

    long_strings = [s['content'] for s in extracted_strings if len(s['content']) > 20 and not s['is_flag']]
    if long_strings:
        ai_input_text += "Found long strings:\n" + "\n".join(long_strings[:5]) # Limit to 5 long strings

    ai_results = analyze_text_with_ai(ai_input_text)

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
        "ai_analysis_results": ai_results,
    }
