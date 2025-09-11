# CTF File Analyzer - MCP/Tool-Use API

This document describes the Model-Controller-Plugin (MCP) interface for the CTF File Analyzer tool. This API is designed to be called by a Large Language Model (LLM) to perform specific file analysis tasks.

## Endpoint

- **URL:** `/mcp/analyze`
- **Method:** `POST`
- **Content-Type:** `multipart/form-data`

## Request Format

The request must contain two fields:
1.  `file`: The binary file to be analyzed.
2.  `command`: A string specifying which analysis to perform.

---

## Available Tools (Commands)

Below is a list of available commands and their expected outputs.

### 1. `get_hashes`

**Description:** Calculates the MD5, SHA1, and SHA256 hashes of the entire file.
**Input:** `file`
**Output (JSON):**
```json
{
  "md5": "string",
  "sha1": "string",
  "sha256": "string"
}
```

### 2. `get_entropy`

**Description:** Calculates the Shannon entropy of the entire file. The value ranges from 0.0 (no randomness) to 8.0 (maximum randomness).
**Input:** `file`
**Output (JSON):**
```json
{
  "entropy": "float"
}
```

### 3. `get_strings`

**Description:** Extracts all printable ASCII strings (4 characters or longer) from the file.
**Input:** `file`
**Output (JSON):**
```json
[
  "string",
  "string",
  ...
]
```

### 4. `get_zip_structure`

**Description:** Parses a ZIP file and returns a detailed list of its local file headers, including any unindexed (hidden) entries.
**Input:** `file` (must be a ZIP file)
**Output (JSON):** A list of objects, where each object has the following structure:
```json
[
  {
    "type": "zip_local_header",
    "offset": "string (hex)",
    "filename": "string",
    "version_needed": "integer",
    "general_purpose_bit_flag": "string (hex)",
    "compression_method": "integer",
    "crc-32": "string (hex)",
    "compressed_size": "integer",
    "uncompressed_size": "integer",
    "is_encrypted": "boolean",
    "is_indexed": "boolean"
  },
  ...
]
```

### 5. `get_png_structure`

**Description:** Parses a PNG file and returns a list of its chunks and their properties.
**Input:** `file` (must be a PNG file)
**Output (JSON):** A list of objects. The `IHDR` chunk will contain a nested `details` object.
```json
[
  {
    "type": "chunk",
    "name": "IHDR",
    "size": 13,
    "offset": 8,
    "details": {
      "width": "integer",
      "height": "integer",
      "bit_depth": "integer",
      "color_type": "integer",
      "compression_method": "integer",
      "filter_method": "integer",
      "interlace_method": "integer"
    }
  },
  {
    "type": "chunk",
    "name": "IDAT",
    "size": "integer",
    "offset": "integer"
  },
  ...
]
```
