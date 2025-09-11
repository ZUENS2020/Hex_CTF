import re

# --- Shared Data ---

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

# --- Shared Functions ---

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
