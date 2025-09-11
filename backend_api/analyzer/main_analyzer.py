import os
import hashlib
import re
import numpy as np

# Assuming 'common.py' and other analyzers will be populated and imported
from .common import add_finding, CTF_FLAG_REGEX, CTF_KEYWORD_REGEX, URL_REGEX, MAGIC_BYTES_DB
from . import zip as zip_analyzer
from . import png as png_analyzer
from . import rar as rar_analyzer

# --- Universal Helper Functions ---

def calculate_hashes(data):
    return {'md5': hashlib.md5(data).hexdigest(), 'sha1': hashlib.sha1(data).hexdigest(), 'sha256': hashlib.sha256(data).hexdigest()}

def get_hex_preview(data):
    hex_preview_bytes = 256
    head = data[:hex_preview_bytes]
    tail = data[-hex_preview_bytes:] if len(data) > hex_preview_bytes else b''
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
    min_len = 4
    for match in re.finditer(rb'[\x20-\x7E\x09\x0A\x0D]{' + str(min_len).encode() + rb',}', data):
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

# --- MCP Dispatcher ---

def analyze_for_mcp(file_storage, command):
    """
    Dispatcher for the MCP endpoint. Executes a single command.
    """
    file_storage.seek(0)
    data = file_storage.read()

    if command == "get_hashes":
        return calculate_hashes(data)
    elif command == "get_strings":
        return [s['content'] for s in extract_strings(data)]
    elif command == "get_entropy":
        return {"entropy": calculate_entropy(data)}
    elif command == "get_zip_structure":
        temp_path = _save_temp_file(file_storage)
        structure = zip_analyzer.analyze(temp_path, [])
        os.remove(temp_path)
        return structure
    elif command == "get_png_structure":
        return png_analyzer.analyze(data, [])
    else:
        return {"error": f"Unknown or unsupported command: {command}"}

# --- Main UI Analyzer ---

def _save_temp_file(file_storage):
    """Saves the file to a temporary location and returns the path."""
    temp_dir = "/tmp" if os.name == 'posix' else os.environ.get("TEMP", "C:\\temp")
    if not os.path.exists(temp_dir): os.makedirs(temp_dir)
    temp_path = os.path.join(temp_dir, file_storage.filename)
    file_storage.save(temp_path)
    return temp_path

def analyze_file(file_storage):
    """
    Main orchestrator for the UI. Runs all analyses.
    """
    filename = file_storage.filename
    data = file_storage.read()
    temp_path = _save_temp_file(file_storage)

    findings = []
    file_structure = None

    file_type_analysis = analyze_magic_bytes(data)
    file_type = file_type_analysis.get('magic_bytes_type')

    # This part will be empty until we migrate the logic back in
    if file_type == "ZIP":
        file_structure = zip_analyzer.analyze(temp_path, findings)
    elif file_type == "PNG":
        file_structure = png_analyzer.analyze(data, findings)
    # ... etc.

    extracted_strings = extract_strings(data)
    for s in extracted_strings:
        for match in URL_REGEX.finditer(s['content']):
            add_finding(findings, type="URL Found", severity="INFO", description="Found a URL in the file.", offset=s['offset'] + match.start(), value=match.group(0))
        for match in CTF_KEYWORD_REGEX.finditer(s['content']):
            add_finding(findings, type="Potential CTF Keyword", severity="INFO", description=f"Found keyword '{match.group(0)}' in a string.", offset=s['offset'] + match.start(), value=s['content'])

    os.remove(temp_path)

    return {
        "filename": filename, "filesize": len(data),
        "file_digest": calculate_hashes(data), "hex_ascii_preview": get_hex_preview(data),
        "overall_entropy": calculate_entropy(data), "file_type_analysis": file_type_analysis,
        "findings": findings, "extracted_strings": extracted_strings,
        "file_structure": file_structure,
    }
