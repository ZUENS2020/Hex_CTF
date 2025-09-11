import os
import importlib
import inspect
from .core import (
    calculate_hashes, get_hex_preview, calculate_entropy, extract_strings,
    analyze_magic_bytes, add_finding, URL_REGEX, CTF_KEYWORD_REGEX
)
from .analyzers.base_analyzer import BaseAnalyzer

# --- Analyzer Loader ---

def load_analyzers():
    """Dynamically loads all analyzer classes from the 'analyzers' directory."""
    analyzers = []
    analyzer_dir = os.path.join(os.path.dirname(__file__), 'analyzers')
    for filename in os.listdir(analyzer_dir):
        if filename.endswith('_analyzer.py') and filename != 'base_analyzer.py':
            module_name = f"backend_api.analyzer.analyzers.{filename[:-3]}"
            try:
                module = importlib.import_module(module_name)
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, BaseAnalyzer) and obj is not BaseAnalyzer:
                        analyzers.append(obj())
            except ImportError as e:
                print(f"Error loading analyzer {module_name}: {e}")
    return analyzers

# --- Main Orchestrator ---

def analyze_file(file_storage):
    """
    Analyzes a file by orchestrating various analysis components.
    """
    # --- Initial Setup ---
    filename = file_storage.filename
    file_storage.seek(0)
    data = file_storage.read()

    findings = []
    file_structure = None

    # --- Load Analyzers ---
    loaded_analyzers = load_analyzers()

    # --- Core Analysis (Always Runs) ---
    file_type_analysis = analyze_magic_bytes(data)

    # --- Dispatch to Specific Analyzer ---
    for analyzer in loaded_analyzers:
        if analyzer.can_analyze(data, file_type_analysis):
            try:
                file_structure = analyzer.analyze(file_storage, data, findings)
            except Exception as e:
                add_finding(findings, "Analyzer Error", "CRITICAL", f"Error in '{analyzer.name}' analyzer: {e}")
            break # Stop after the first matching analyzer

    # --- Universal String and Keyword Analysis ---
    extracted_strings = extract_strings(data)
    for s in extracted_strings:
        for match in URL_REGEX.finditer(s['content']):
            add_finding(findings, type="URL Found", severity="INFO", description="Found a URL.", offset=s['offset'] + match.start(), value=match.group(0))
        for match in CTF_KEYWORD_REGEX.finditer(s['content']):
            add_finding(findings, type="Potential CTF Keyword", severity="INFO", description=f"Found keyword '{match.group(0)}'.", offset=s['offset'] + match.start(), value=s['content'])

    # --- Final Result Aggregation ---
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
