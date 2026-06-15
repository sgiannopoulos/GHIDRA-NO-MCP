# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A headless CLI that drives Ghidra (via `pyghidra`) to decompile a binary and dump the
results as plain text/source files — decompiled C per function, a call graph, strings,
imports, exports, and memory hexdumps — for consumption by AI IDEs. No GUI, no MCP server;
the output is just files on disk.

## Commands

```bash
# Local dev setup
uv venv && uv pip install -e .

# Run (requires Ghidra; set GHIDRA_INSTALL_DIR or pass -g)
export GHIDRA_INSTALL_DIR=/path/to/ghidra_xx.x_PUBLIC
uv run ghidra-no-mcp ./binary ./output_dir
uv run ghidra-no-mcp -g /path/to/ghidra ./binary ./output_dir -v
```

Requires Python >= 3.12 and a local Ghidra installation (not bundled; download from
NationalSecurityAgency/ghidra). There is **no test suite, linter config, or CI** in this
repo — to validate a change, run the tool against a real binary and inspect `output_dir`.

## Architecture

Three source files under `src/ghidra_no_mcp/`:

- `cli.py` — argument parsing, resolves the Ghidra path, calls `pyghidra.start()`, loads the
  binary with `program_loader`, then hands the `Program` object to `GhidraExporter`.
- `exporter.py` — `GhidraExporter` class; all the actual export logic. `export_all()` runs
  `pyghidra.analyze()` first, then writes each artifact.
- `__main__.py` / `__init__.py` — entrypoint shim and version.

### The critical pattern: lazy Ghidra imports

Ghidra's Java classes are only importable **after** `pyghidra.start()` boots the JVM. That is
why `exporter.py` imports `ghidra.*` (and `jpype`) **inside methods**, not at module top.
The top-level `from ghidra... import` block is guarded by `TYPE_CHECKING` and exists purely
for type hints — it never runs at runtime. When adding code that touches Ghidra APIs, follow
this: import `ghidra.*` / `jpype` locally inside the function, never at module scope.

### JPype bridge gotchas

The Ghidra API is Java accessed through JPype. Java `byte` is signed, so reading memory uses
`JByte[size]` to allocate a Java array and `b & 0xFF` to get unsigned values (see
`_read_hexdump`). Most Java getters (`getName()`, `getEntryPoint()`, etc.) return Java objects;
wrap them in `str(...)` before using as Python strings/dict keys, as the existing code does.

### Export flow and resilience

`export_all()` first runs `pyghidra.analyze()`, then builds `self.call_info` (a plain-Python
map of every function's callers/callees) **once** via `_build_call_info()`, which both the call
graph and the per-function `.c` headers read from. This is the single place that calls Ghidra's
`getCalledFunctions(monitor)` / `getCallingFunctions(monitor)` — **these require a `TaskMonitor`
argument**; calling them with none (the historical bug) silently produced an empty call graph.
It then writes: `call_graph.json`, `decompile/`, strings, imports, exports, `sections.txt`
(with per-block Shannon entropy for packing detection), `triage.txt` (entry points +
suspicious-API callers), and memory. Each text export is tab-separated with a `#` header row.

Errors are routed through `_handle_exc()`: by default logged at debug and skipped; with
`--strict` they re-raise (fail-loud for debugging a specific sample). Per-function decompile
failures are recorded in `decompile_failed.txt` / `decompile_skipped.txt` and counted in
`self.stats`. Decompiled filenames are `<sanitized_name>_<entrypoint>.c` — the address suffix
guarantees uniqueness (distinct functions can share a sanitized name).

### Parallel decompilation

`export_functions` decompiles via a `ThreadPoolExecutor` (`--jobs`, default auto). `DecompInterface`
is **not thread-safe**, so each worker thread gets its own instance via `_thread_decompiler()`
(a `threading.local`); JPype auto-attaches the worker threads to the JVM. Caller/callee data is
precomputed into `call_info` on the main thread, so workers only call the decompiler and write
their own `.c` file — keeping output order-independent and deterministic. `--jobs 1` is the
serial fallback.

See the README's Output table for the exact files produced and their formats.
