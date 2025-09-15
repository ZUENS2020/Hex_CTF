import hashlib
import re
import os
import numpy as np

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

def _save_temp_file(file_storage):
    temp_dir = "/tmp" if os.name == 'posix' else os.environ.get("TEMP", "C:\\temp")
    if not os.path.exists(temp_dir): os.makedirs(temp_dir)
    temp_path = os.path.join(temp_dir, os.path.basename(file_storage.filename))
    file_storage.seek(0)
    with open(temp_path, 'wb') as f:
        f.write(file_storage.read())
    return temp_path
