import os
import hashlib
import zlib
import zipfile
import re
import math
import struct
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
MAGIC_BYTES_DB = {
    b'\x89PNG\r\n\x1a\n': ('PNG', 'image/png'),
    b'\xFF\xD8\xFF': ('JPEG', 'image/jpeg'),
    b'GIF87a': ('GIF', 'image/gif'),
    b'GIF89a': ('GIF', 'image/gif'),
    b'%PDF-': ('PDF', 'application/pdf'),
    b'PK\x03\x04': ('ZIP', 'application/zip'),
    b'Rar!\x1a\x07\x00': ('RAR', 'application/x-rar-compressed'),
    b'Rar!\x1a\x07\x01\x00': ('RAR5', 'application/x-rar-compressed'),
}

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
    for magic_seq, (file_type, mime) in MAGIC_BYTES_DB.items():
        if data.startswith(magic_seq):
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
                    width, height = struct.unpack('>II', chunk_data[:8])
                    add_finding(findings, type="PNG Image Dimensions", severity="INFO",
                        description=f"PNG IHDR chunk found. Image dimensions are {width}x{height}.",
                        value=f"Width: {width}, Height: {height}")
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
    """Performs deep analysis on ZIP files, including raw scans for hidden entries."""
    LOCAL_HEADER_SIG = b'PK\x03\x04'
    structure = []

    # --- Standard Analysis using zipfile library ---
    official_filenames = set()
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            official_filenames = {info.filename for info in zf.infolist()}
            if zf.comment:
                add_finding(findings, type="ZIP Comment", severity="INFO",
                    description="The ZIP archive contains a global comment.",
                    value=zf.comment.decode('utf-8', 'ignore'))

            for info in zf.infolist():
                # Populate structure
                structure.append({
                    "type": "zip_entry", "name": info.filename,
                    "compressed_size": info.compress_size, "uncompressed_size": info.file_size,
                    "timestamp": info.date_time, "crc": info.CRC,
                    "is_encrypted": (info.flag_bits & 0x1) != 0
                })

                is_encrypted = (info.flag_bits & 0x1) != 0
                if is_encrypted:
                    add_finding(findings, type="Encrypted ZIP Member", severity="WARNING",
                        description=f"File '{info.filename}' is marked as encrypted.",
                        hint="If this file is truly encrypted, you may need a password. If it's pseudo-encrypted, some tools can ignore this flag.")
                    if info.compress_type == zipfile.ZIP_DEFLATED:
                        add_finding(findings, type="Potential Known-Plaintext Attack", severity="WARNING",
                            description=f"File '{info.filename}' uses traditional ZipCrypto. This is vulnerable to known-plaintext attacks.",
                            hint="If you have an unencrypted version of this file (at least 12 bytes), use a tool like bkcrack.")

                try:
                    with zf.open(info, 'r') as member_file:
                        member_data = member_file.read()
                        _, inner_ext = os.path.splitext(info.filename)
                        inner_magic = analyze_magic_bytes(member_data)
                        if inner_magic['magic_bytes_type'] != 'Unknown' and inner_ext:
                            expected_type = next((ftype for magic, (ftype, mime) in MAGIC_BYTES_DB.items() if f".{ftype.lower()}" == inner_ext.lower()), 'Unknown')
                            if inner_magic['magic_bytes_type'] != expected_type:
                                add_finding(findings, type="ZIP Inner File Type Mismatch", severity="WARNING",
                                    description=f"File '{info.filename}' inside the ZIP has an extension '{inner_ext}' but its content appears to be '{inner_magic['magic_bytes_type']}'.")
                        if not is_encrypted and zlib.crc32(member_data) != info.CRC:
                             add_finding(findings, type="ZIP CRC Mismatch", severity="CRITICAL",
                                description=f"CRC32 mismatch for file '{info.filename}'. Expected {info.CRC}, got {zlib.crc32(member_data)}.")
                except Exception as e:
                    add_finding(findings, type="ZIP Member Read Error", severity="WARNING", description=f"Could not process member {info.filename}: {e}")

    except zipfile.BadZipFile:
        add_finding(findings, type="ZIP Error", severity="CRITICAL", description="The file is not a valid ZIP archive or is corrupted.")
        return # Stop further analysis if the file isn't a valid zip

    # --- Raw Scan for Hidden Files ---
    with open(file_path, 'rb') as f:
        data = f.read()

    scanned_filenames = set()
    offset = 0
    while (offset := data.find(LOCAL_HEADER_SIG, offset)) != -1:
        try:
            # Parse local file header to get filename length
            filename_len_offset = offset + 26
            filename_length = struct.unpack('<H', data[filename_len_offset:filename_len_offset+2])[0]

            extra_field_len_offset = filename_len_offset + 2
            extra_field_length = struct.unpack('<H', data[extra_field_len_offset:extra_field_len_offset+2])[0]

            # Extract filename
            filename_offset = extra_field_len_offset + 2
            scanned_filename = data[filename_offset:filename_offset+filename_length].decode('utf-8', 'ignore')
            scanned_filenames.add(scanned_filename)

            offset = filename_offset + filename_length + extra_field_length
        except (struct.error, IndexError, UnicodeDecodeError):
            offset += 1 # Move past the current signature to avoid an infinite loop on malformed headers
            continue

    hidden_files = scanned_filenames - official_filenames
    if hidden_files:
        for hidden_file in hidden_files:
            add_finding(findings,
                type="Hidden ZIP Entry Found", severity="CRITICAL",
                description=f"A file entry for '{hidden_file}' was found via raw scan but is not listed in the ZIP's central directory.",
                hint="This file is hidden from standard unzipping tools. Use a forensic tool to extract it."
            )

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
