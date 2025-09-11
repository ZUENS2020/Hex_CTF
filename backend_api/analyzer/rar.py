from .common import add_finding

try:
    import rarfile
except ImportError:
    rarfile = None

def analyze(file_path, findings):
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
