import os
import hashlib
import importlib
import re
import numpy as np
from .common import MAGIC_BYTES_DB, CTF_FLAG_REGEX, CTF_KEYWORD_REGEX, URL_REGEX, add_finding

# A mapping from file type (from MAGIC_BYTES_DB) to the analyzer module
ANALYZER_MAPPING = {
    "ZIP": "zip",
    "PNG": "png",
    "RAR": "rar",
    "RAR5": "rar",
    # "BMP": "bmp", # Placeholder for when bmp analyzer is added
    # "GIF": "gif", # Placeholder for when gif analyzer is added
}

# --- Universal Analysis Functions ---

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

# --- Main Orchestrator ---

def analyze_file(file_storage):
    filename = file_storage.filename
    file_storage.seek(0)
    data = file_storage.read()
    file_storage.seek(0)

    temp_dir = "/tmp" if os.name == 'posix' else os.environ.get("TEMP", "C:\\temp")
    if not os.path.exists(temp_dir): os.makedirs(temp_dir)
    temp_path = os.path.join(temp_dir, filename)
    file_storage.save(temp_path)

    findings = []
    file_structure = None

    # --- Basic Analysis ---
    file_type_analysis = analyze_magic_bytes(data)
    file_type = file_type_analysis.get('magic_bytes_type')

    # --- Dynamic Dispatch to Specific Analyzers ---
    if file_type in ANALYZER_MAPPING:
        try:
            module_name = f".{ANALYZER_MAPPING[file_type]}"
            analyzer_module = importlib.import_module(module_name, package='backend_api.analyzer')
            # The `analyze` function might need the raw data or a file path
            if file_type in ["ZIP", "RAR", "RAR5"]:
                 file_structure = analyzer_module.analyze(temp_path, findings)
            else: # PNG, etc.
                 file_structure = analyzer_module.analyze(data, findings)
        except ImportError:
            add_finding(findings, "Analyzer Error", "CRITICAL", f"Could not find or import the analyzer module for type '{file_type}'.")
        except Exception as e:
            add_finding(findings, "Analyzer Error", "CRITICAL", f"An error occurred in the '{file_type}' analyzer: {e}")

    # --- Universal Deep Analysis ---
    extracted_strings = extract_strings(data)
    for s in extracted_strings:
        for match in URL_REGEX.finditer(s['content']):
            add_finding(findings, type="URL Found", severity="INFO", description="Found a URL in the file.", offset=s['offset'] + match.start(), value=match.group(0))
        for match in CTF_KEYWORD_REGEX.finditer(s['content']):
            add_finding(findings, type="Potential CTF Keyword", severity="INFO", description=f"Found keyword '{match.group(0)}' in a string.", offset=s['offset'] + match.start(), value=s['content'])

    os.remove(temp_path)

    return {
        "filename": filename,
        "filesize": len(data),
        "file_digest": calculate_hashes(data),
        "hex_ascii_preview": get_hex_preview(data),
        "overall_entropy": calculate_entropy(data),
        "file_type_analysis": file_type_analysis,
        "findings": findings,
        "extracted_strings": extracted_strings,
        "file_structure": file_structure,
    }
