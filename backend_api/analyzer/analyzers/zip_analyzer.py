import struct
import zipfile
from .base_analyzer import BaseAnalyzer
from ..core import add_finding, _save_temp_file

class ZipAnalyzer(BaseAnalyzer):
    name = "zip"

    def can_analyze(self, data, magic_bytes_info):
        return magic_bytes_info.get('magic_bytes_type') == 'ZIP'

    def analyze(self, file_storage, data, findings):
        temp_path = _save_temp_file(file_storage)

        LOCAL_HEADER_SIG = b'PK\x03\x04'
        structure = []

        official_filenames = set()
        try:
            with zipfile.ZipFile(temp_path, 'r') as zf:
                official_filenames = {info.filename for info in zf.infolist()}
        except zipfile.BadZipFile:
            pass

        offset = 0
        while (offset := data.find(LOCAL_HEADER_SIG, offset)) != -1:
            try:
                header_data = data[offset:offset+30]
                if len(header_data) < 30:
                    break

                (sig, ver, gp_flag, comp_meth, mod_time, mod_date, crc32, comp_size, uncomp_size, name_len, extra_len) = struct.unpack('<IHHHHHIIIHH', header_data)
                filename = data[offset+30 : offset+30+name_len].decode('utf-8', 'ignore')
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
