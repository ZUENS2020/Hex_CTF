import zipfile
import struct
from .common import add_finding

def analyze(file_path, findings):
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

            (sig, ver, gp_flag, comp_meth, mod_time, mod_date, crc32, comp_size, uncomp_size, name_len, extra_len) = \
                struct.unpack('<IHHHHHIIIHH', header_data)

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

            # To prevent huge performance issues on large files, we skip the data part
            offset += 30 + name_len + extra_len + comp_size
        except (struct.error, IndexError):
            offset += 1
            continue

    return structure
