# GHIDRA-NO-MCP

Export Ghidra decompilation results as source files for use with AI IDEs. 

Runs from cmd, uses pyghidra and headless mode and doesn't require the Ghidra GUI.

**Just copy-paste the uvx command into the agent or skill.**

Inspired by: https://github.com/P4nda0s/IDA-NO-MCP

> Text, Source Code, and Shell are LLM's native languages.

## Installation and Usage

### Install with uv

```bash
uv tool install git+https://github.com/gxenos/GHIDRA-NO-MCP.git
```

Run from anywhere:

```bash
ghidra-no-mcp -g /path/to/GHIDRA /path/to/binary /output/dir
```

### Run with uvx

```bash
uvx git+https://github.com/gxenos/GHIDRA-NO-MCP -g /path/to/GHIDRA /path/to/binary /output/dir
```

Or using environment variable:

```bash
GHIDRA_INSTALL_DIR=/path/to/GHIDRA uvx git+https://github.com/gxenos/GHIDRA-NO-MCP /path/to/binary /output/dir
```

## Other Installation Methods

### Local development 

```bash
uv venv && uv pip install -e .
```

### Examples

```bash
# Using environment variable
export GHIDRA_INSTALL_DIR=/opt/ghidra/ghidra_12.0.4_PUBLIC
uv run ghidra-no-mcp ./malware.exe ./analysis

# Using CLI argument
uv run ghidra-no-mcp -g /opt/ghidra ./malware.exe ./analysis

# With uvx
GHIDRA_INSTALL_DIR=/opt/ghidra uvx git+https://github.com/gxenos/GHIDRA-NO-MCP ./malware.exe ./analysis
```

### Options

| Option | Description |
|--------|-------------|
| `-g, --ghidra-path` | Path to Ghidra installation |
| `-v, --verbose` | Enable verbose logging |
| `-j, --jobs` | Parallel decompiler threads (0 = auto, 1 = serial; default: auto) |
| `--strict` | Fail loudly on errors instead of logging and continuing |

## Output

| Directory/File | Description |
|---------------|-------------|
| `call_graph.json` | Function call graph (nodes + edges), includes function names, addresses, caller/callee counts |
| `decompile/` | Decompiled C files (one per function, named `<name>_<address>.c`), includes function name, address, callers, callees |
| `strings.txt` | Discovered strings, tab-separated: `address  length  type  refs  value` (`refs` = functions that reference the string) |
| `imports.txt` | Import table, tab-separated: `library  name  address  refs` (`refs` = functions that call the import) |
| `exports.txt` | Export table, tab-separated: `address  name  demangled` |
| `sections.txt` | Memory blocks with permissions and Shannon entropy (high entropy ⇒ likely packed/encrypted) |
| `triage.txt` | Entry points and functions calling suspicious APIs (injection, persistence, network, crypto, anti-analysis) |
| `memory/` | Memory hexdumps, 1MB chunks (executable/code blocks excluded by default; use `--all-memory`) |
| `decompile_skipped.txt` | Skipped functions |
| `decompile_failed.txt` | Failed functions |

Each `.c` file includes metadata header:
```c
/*
 * func-name: main
 * func-address: 0x401000
 * callers: 0x402000
 * callees: 0x404000
 */
```

The `call_graph.json` file contains the full call graph:
```json
{
  "nodes": [
    {"address": "0x401000", "name": "main", "is_external": false, "caller_count": 0, "callee_count": 2},
    {"address": "0x402000", "name": "validate_input", "is_external": false, "caller_count": 1, "callee_count": 3}
  ],
  "edges": [
    {"caller": "0x401000", "caller_name": "main", "callee": "0x402000", "callee_name": "validate_input"}
  ],
  "stats": {"total_functions": 150, "total_calls": 342, "external_calls": 45}
}
```

## Analysis

By default, the script runs Ghidra with the default analysis options.

### Analysis Options

| Option | Description |
|--------|-------------|
| `--no-memory` | Skip memory hexdump export |
| `--all-memory` | Include executable (code) blocks in memory hexdumps (excluded by default) |
| `--no-strings` | Skip string extraction |
| `--no-imports` | Skip import table export |
| `--no-exports` | Skip export table export |
| `--decompiler-timeout` | Timeout per function in seconds (0 = unlimited, default: 60) |
| `--max-payload` | Max decompiler payload size in MB (default: 100) |

## Safety

Analysis is **static** — Ghidra disassembles and decompiles the sample but never
executes it. The loader still parses untrusted, potentially malicious input, so for
real malware run inside a disposable VM or container as defense in depth.
