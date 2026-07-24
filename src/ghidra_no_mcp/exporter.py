import json
import logging
import math
import re
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ghidra.app.decompiler import DecompileResults, DecompInterface
    from ghidra.program.model.listing import Program
    from ghidra.program.model.mem import MemoryBlock
    from ghidra.program.model.symbol import Symbol

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

DIAGNOSTICS_FILENAME = "analysis-diagnostics.json"
ANALYSIS_LOG_LIMIT = 32 * 1024


# --- Pure helpers (no Ghidra/JVM dependency; unit-testable on their own) ---

# Curated Windows API substrings grouped by malware behaviour. Matching is
# case-insensitive substring against the (leading-underscore-stripped) symbol
# name, so e.g. "VirtualAllocEx" matches "virtualalloc".
SUSPICIOUS_APIS: dict[str, list[str]] = {
    "process-injection": [
        "virtualalloc",
        "virtualprotect",
        "writeprocessmemory",
        "createremotethread",
        "ntwritevirtualmemory",
        "queueuserapc",
        "setthreadcontext",
        "mapviewofsection",
        "ntmapviewofsection",
        "rtlcreateuserthread",
        "ntunmapviewofsection",
    ],
    "process-exec": [
        "createprocess",
        "shellexecute",
        "winexec",
        "loadlibrary",
        "getprocaddress",
        "ntcreateprocess",
        "createprocessinternal",
    ],
    "persistence": [
        "regsetvalue",
        "regcreatekey",
        "createservice",
        "startservice",
        "schtasks",
        "regsetkeyvalue",
    ],
    "network": [
        "wininet",
        "winhttp",
        "internetopen",
        "internetconnect",
        "httpopenrequest",
        "httpsendrequest",
        "urldownloadtofile",
        "wsastartup",
        "wsasocket",
        "wsaconnect",
        "wsasend",
        "wsarecv",
        "closesocket",
        "getaddrinfo",
        "gethostbyname",
        "inet_addr",
    ],
    "crypto": [
        "cryptencrypt",
        "cryptdecrypt",
        "cryptacquirecontext",
        "cryptgenkey",
        "bcryptencrypt",
        "bcryptdecrypt",
        "cryptderivekey",
    ],
    "anti-analysis": [
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "ntqueryinformationprocess",
        "outputdebugstring",
        "gettickcount",
        "queryperformancecounter",
    ],
    "discovery": [
        "getcomputername",
        "getusername",
        "getadaptersinfo",
        "createtoolhelp32snapshot",
        "process32first",
        "process32next",
    ],
}


def sanitize_filename(name: str) -> str:
    name = name.replace("/", "_").replace("\\", "_")
    name = re.sub(r"[^\w\-_.]", "_", name)
    if len(name) > 200:
        name = name[:200]
    return name


def escape_string_value(value: str) -> str:
    """Escape control chars so one extracted string stays on one line."""
    return (
        value.replace("\\", "\\\\")
        .replace("\t", "\\t")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def shannon_entropy(histogram: list[int], total: int) -> float:
    """Shannon entropy in bits/byte (0..8) from a 256-bin byte histogram."""
    if total <= 0:
        return 0.0
    ent = 0.0
    for count in histogram:
        if count:
            p = count / total
            ent -= p * math.log2(p)
    return ent


def match_suspicious(name: str) -> list[str]:
    """Return the suspicious categories a symbol name matches (may be empty)."""
    n = name.lower().lstrip("_")
    return [cat for cat, kws in SUSPICIOUS_APIS.items() if any(k in n for k in kws)]


def classify_decompile_result(result: Any) -> tuple[bool, str]:
    """Return ``(completed, message)`` for a Ghidra DecompileResults object.

    ``getErrorMessage()`` is not a completion flag: Ghidra may return a warning
    there after a successful decompilation. ``decompileCompleted()`` is the
    authoritative status check.
    """
    message = str(result.getErrorMessage() or "")
    if result.decompileCompleted():
        return True, message

    if not message:
        try:
            if result.failedToStart():
                message = "decompiler executable failed to start"
        except Exception:
            pass
    return False, message or "decompilation did not complete"


def _new_stats() -> dict[str, Any]:
    return {
        "total_functions": 0,
        "exported": 0,
        "skipped": 0,
        "failed": 0,
        "warnings": 0,
        "memory_files": 0,
        "memory_bytes": 0,
        "disassembly": {
            "attempted": 0,
            "exported": 0,
            "failed": 0,
            "external_skipped": 0,
            "instruction_count": 0,
            "instruction_bytes": 0,
        },
    }


class GhidraExporter:
    # Cap bytes read per block when estimating entropy; representative enough
    # for packing detection without re-reading huge sections.
    ENTROPY_SAMPLE_BYTES = 16 * 1024 * 1024

    def __init__(
        self,
        program: "Program",
        skip_memory: bool = False,
        skip_strings: bool = False,
        skip_imports: bool = False,
        skip_exports: bool = False,
        decompiler_timeout: int = 60,
        max_payload_mb: int = 100,
        jobs: int = 1,
        strict: bool = False,
        dump_executable: bool = False,
        skip_disassembly: bool = False,
    ):
        self.program = program
        self.skip_memory = skip_memory
        self.skip_strings = skip_strings
        self.skip_imports = skip_imports
        self.skip_exports = skip_exports
        self.decompiler_timeout = decompiler_timeout
        self.max_payload_mb = max_payload_mb
        self.jobs = max(1, jobs)
        self.strict = strict
        self.dump_executable = dump_executable
        self.skip_disassembly = skip_disassembly

        # Populated immediately before export, after the caller's final analysis
        # or function-recovery pass.
        self.functions: list = []
        self.call_info: dict[str, dict] = {}

        # Per-thread decompilers (DecompInterface is not thread-safe).
        self._tls = threading.local()
        self._lock = threading.Lock()
        self._decompilers: list = []

        self.stats = _new_stats()
        self._analysis_log = ""
        self._analysis_performed_by_exporter = False
        self._export_errors: list[dict[str, str]] = []
        self._decompile_records: list[dict[str, Any]] = []
        self._disassembly_records: list[dict[str, Any]] = []
        self.last_diagnostics: dict[str, Any] | None = None

    # --- Error handling ---

    def _handle_exc(self, context: str, exc: Exception):
        """Log a swallowed exception, or re-raise it in --strict mode."""
        if self.strict:
            raise exc
        logger.debug(f"  [skip] {context}: {exc}")

    # --- Decompiler lifecycle ---

    def _new_decompiler(self) -> "DecompInterface":
        from ghidra.app.decompiler import DecompileOptions, DecompInterface

        prog_options = DecompileOptions()
        prog_options.grabFromProgram(self.program)
        prog_options.setMaxPayloadMBytes(self.max_payload_mb)

        decomp = DecompInterface()
        decomp.setOptions(prog_options)
        decomp.openProgram(self.program)
        return decomp

    def _thread_decompiler(self) -> "DecompInterface":
        decomp = getattr(self._tls, "decomp", None)
        if decomp is None:
            decomp = self._new_decompiler()
            self._tls.decomp = decomp
            with self._lock:
                self._decompilers.append(decomp)
        return decomp

    def _dispose_decompilers(self):
        for decomp in self._decompilers:
            try:
                decomp.dispose()
            except Exception:
                pass
        self._decompilers = []
        # Serial export stores its interface on the calling thread. Do not
        # return a disposed instance if this exporter is reused.
        if hasattr(self._tls, "decomp"):
            del self._tls.decomp

    # --- Orchestration ---

    def analyze(self) -> str:
        """Run Ghidra auto-analysis and return its analysis log."""
        import pyghidra

        logger.info("Analyzing program...")
        analysis_log = str(pyghidra.analyze(self.program) or "")
        self._analysis_log = analysis_log
        self._analysis_performed_by_exporter = True
        logger.info("Analysis complete.")
        return analysis_log

    def export_all(self, output_dir: Path) -> dict:
        """Analyze the program, then export all configured artifacts."""
        self.analyze()
        return self.export_preanalyzed(output_dir, analysis_log=self._analysis_log)

    def export_preanalyzed(
        self,
        output_dir: Path,
        *,
        analysis_log: str | None = None,
    ) -> dict:
        """Export a program whose final analysis/recovery pass is complete.

        This public entry point lets callers configure analyzers, recover
        functions, or otherwise mutate the Ghidra Program before the exporter
        snapshots FunctionManager. It never invokes auto-analysis itself.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        self._reset_export_state()
        if analysis_log is not None:
            self._analysis_log = str(analysis_log)

        logger.info(f"Exporting to: {output_dir}")
        logger.info("-" * 50)

        fm = self.program.getFunctionManager()
        self.functions = list(fm.getFunctions(True))
        self.stats["total_functions"] = len(self.functions)
        self.call_info = self._build_call_info()

        self._run_export("Call graph", self.export_call_graph, output_dir)
        self._run_export("Functions", self.export_functions, output_dir)

        if not self.skip_disassembly:
            self._run_export("Disassembly", self.export_disassembly, output_dir)
        else:
            logger.info("  Disassembly: skipped")

        if not self.skip_strings:
            self._run_export("Strings", self.export_strings, output_dir)
        else:
            logger.info("  Strings: skipped")

        if not self.skip_imports:
            self._run_export("Imports", self.export_imports, output_dir)
        else:
            logger.info("  Imports: skipped")

        if not self.skip_exports:
            self._run_export("Exports", self.export_exports, output_dir)
        else:
            logger.info("  Exports: skipped")

        self._run_export("Sections", self.export_sections, output_dir)
        self._run_export("Triage", self.export_triage, output_dir)

        if not self.skip_memory:
            self._run_export("Memory", self.export_memory, output_dir)
        else:
            logger.info("  Memory: skipped")

        self.export_diagnostics(output_dir)
        self._print_statistics()
        return dict(self.stats)

    def _reset_export_state(self):
        self.stats = _new_stats()
        self._export_errors = []
        self._decompile_records = []
        self._disassembly_records = []
        self.last_diagnostics = None

    def _run_export(self, label: str, fn, output_dir: Path):
        """Run one export step in isolation so a failure can't abort the rest.

        Re-raises in --strict mode; otherwise logs and continues.
        """
        try:
            fn(output_dir)
        except Exception as e:
            if self.strict:
                raise
            self._export_errors.append({"artifact": label, "error": str(e)})
            logger.warning(f"  {label}: FAILED ({e})")

    # --- Call relationships (computed once, reused everywhere) ---

    def _build_call_info(self) -> dict[str, dict]:
        """Map each function entry point to its callers/callees.

        Centralizes the getCalledFunctions/getCallingFunctions calls (which
        REQUIRE a TaskMonitor argument in current Ghidra) so the call graph and
        the per-function headers share one correct, monitored implementation.
        """
        from ghidra.util.task import TaskMonitor

        monitor = TaskMonitor.DUMMY
        info: dict[str, dict] = {}

        logger.info("Building call relationships...")
        for func in self.functions:
            addr = str(func.getEntryPoint())
            callers: list[tuple[str, str]] = []
            callees: list[tuple[str, str, bool]] = []

            try:
                called = func.getCalledFunctions(monitor)
                if called:
                    callees = [
                        (str(f.getEntryPoint()), f.getName(), f.isExternal())
                        for f in called
                    ]
            except Exception as e:
                self._handle_exc(f"getCalledFunctions {addr}", e)

            try:
                calling = func.getCallingFunctions(monitor)
                if calling:
                    callers = [(str(f.getEntryPoint()), f.getName()) for f in calling]
            except Exception as e:
                self._handle_exc(f"getCallingFunctions {addr}", e)

            info[addr] = {
                "name": func.getName(),
                "is_external": func.isExternal(),
                "callers": callers,
                "callees": callees,
            }
        return info

    def export_call_graph(self, output_dir: Path):
        import json

        graph_file = output_dir / "call_graph.json"

        nodes = []
        edges = []
        external_calls = 0

        for addr, data in self.call_info.items():
            for callee_addr, callee_name, callee_external in data["callees"]:
                if callee_external:
                    external_calls += 1
                edges.append(
                    {
                        "caller": addr,
                        "caller_name": data["name"],
                        "callee": callee_addr,
                        "callee_name": callee_name,
                    }
                )

        for addr, data in self.call_info.items():
            nodes.append(
                {
                    "address": addr,
                    "name": data["name"],
                    "is_external": data["is_external"],
                    "caller_count": len(data["callers"]),
                    "callee_count": len(data["callees"]),
                }
            )

        graph_data = {
            "nodes": nodes,
            "edges": edges,
            "stats": {
                "total_functions": len(nodes),
                "total_calls": len(edges),
                "external_calls": external_calls,
            },
        }

        with open(graph_file, "w") as f:
            json.dump(graph_data, f, indent=2)

        logger.info(f"  Call graph: {len(nodes)} nodes, {len(edges)} edges")

    # --- Function decompilation ---

    def export_functions(self, output_dir: Path):
        decompile_dir = output_dir / "decompile"
        decompile_dir.mkdir(parents=True, exist_ok=True)

        failed_file = output_dir / "decompile_failed.txt"
        skipped_file = output_dir / "decompile_skipped.txt"
        warnings_file = output_dir / "decompile_warnings.txt"

        self.stats["total_functions"] = len(self.functions)

        to_decompile: list[tuple] = []
        skipped: list[tuple[str, str, str]] = []
        for func in self.functions:
            name = str(func.getName())
            addr = str(func.getEntryPoint())
            if func.isExternal():
                skipped.append((addr, name, "external"))
            elif func.isThunk():
                skipped.append((addr, name, "thunk"))
            else:
                to_decompile.append((func, addr, name))

        logger.info(f"Exporting {len(to_decompile)} functions (jobs={self.jobs})...")

        try:
            if self.jobs == 1:
                results = self._decompile_serial(to_decompile, decompile_dir)
            else:
                results = self._decompile_parallel(to_decompile, decompile_dir)
        finally:
            self._dispose_decompilers()

        with open(skipped_file, "w") as f:
            for addr, name, reason in skipped:
                f.write(f"{addr}:{name} ({reason})\n")
                self._decompile_records.append(
                    {
                        "address": addr,
                        "name": name,
                        "status": "skipped",
                        "reason": reason,
                    }
                )
        self.stats["skipped"] = len(skipped)

        results.sort(key=lambda item: (item[1], item[2]))
        exported = 0
        warnings = 0
        with open(failed_file, "w") as f:
            for status, addr, name, msg, warning in results:
                if status == "exported":
                    exported += 1
                else:
                    f.write(f"{addr}:{name} - {msg}\n")
                if warning:
                    warnings += 1
                record = {
                    "address": addr,
                    "name": name,
                    "status": status,
                }
                if msg:
                    record["error"] = msg
                if warning:
                    record["warning"] = warning
                self._decompile_records.append(record)
        with open(warnings_file, "w") as f:
            for status, addr, name, _, warning in results:
                if status == "exported" and warning:
                    f.write(f"{addr}:{name} - {warning}\n")
        self.stats["exported"] = exported
        self.stats["failed"] = len(results) - exported
        self.stats["warnings"] = warnings

        logger.info(f"  Decompiled: {exported} functions")
        logger.info(f"  Skipped: {len(skipped)} (external/thunk)")
        logger.info(f"  Failed: {self.stats['failed']}")
        logger.info(f"  Warnings: {warnings}")

    def _decompile_serial(self, items: list[tuple], decompile_dir: Path) -> list[tuple]:
        results = []
        for i, item in enumerate(items):
            results.append(self._decompile_one(item, decompile_dir))
            if i > 0 and i % 100 == 0:
                logger.info(f"  Progress: {i}/{len(items)}")
        return results

    def _decompile_parallel(
        self, items: list[tuple], decompile_dir: Path
    ) -> list[tuple]:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        results = []
        with ThreadPoolExecutor(max_workers=self.jobs) as executor:
            futures = [
                executor.submit(self._decompile_one, item, decompile_dir)
                for item in items
            ]
            for i, future in enumerate(as_completed(futures)):
                results.append(future.result())  # re-raises in --strict mode
                if (i + 1) % 200 == 0:
                    logger.info(f"  Progress: {i + 1}/{len(items)}")
        return results

    def _decompile_one(self, item: tuple, decompile_dir: Path) -> tuple:
        from ghidra.util.task import TaskMonitor

        func, addr, name = item
        try:
            decomp = self._thread_decompiler()
            result: "DecompileResults" = decomp.decompileFunction(
                func, self.decompiler_timeout, TaskMonitor.DUMMY
            )
            completed, message = classify_decompile_result(result)
            if not completed:
                return ("failed", addr, name, message, "")

            # Use the explicit getter (not JPype property access) and null-check:
            # a timed-out/incomplete result has no decompiled function.
            decompiled = result.getDecompiledFunction()
            if decompiled is None:
                return (
                    "failed",
                    addr,
                    name,
                    "decompilation completed but returned no C output",
                    message,
                )

            code = str(decompiled.getC())
            content = self._build_function_file(addr, name, code)

            filename = f"{sanitize_filename(name)}_{sanitize_filename(addr)}.c"
            (decompile_dir / filename).write_text(content, encoding="utf-8")
            return ("exported", addr, name, "", message)
        except Exception as e:
            if self.strict:
                raise
            return ("failed", addr, name, str(e), "")

    def _build_function_file(self, addr: str, name: str, code: str) -> str:
        info = self.call_info.get(addr, {})
        callers = [a for a, _ in info.get("callers", [])]
        callees = [a for a, _, _ in info.get("callees", [])]

        callers_str = ", ".join(callers) if callers else "none"
        callees_str = ", ".join(callees) if callees else "none"

        header = f"""/*
 * func-name: {name}
 * func-address: {addr}
 * callers: {callers_str}
 * callees: {callees_str}
 */

"""
        return header + code

    # --- Function disassembly ---

    def export_disassembly(self, output_dir: Path):
        """Export raw bytes and Ghidra's instruction text for every function body.

        Internal thunks are included because their instructions can be
        analytically important. External/imported functions have no local body
        and are reported as skipped in diagnostics.
        """
        disassembly_dir = output_dir / "disassembly"
        disassembly_dir.mkdir(parents=True, exist_ok=True)
        listing = self.program.getListing()

        internal = [func for func in self.functions if not func.isExternal()]
        external_skipped = len(self.functions) - len(internal)
        exported = 0
        failed = 0
        instruction_total = 0
        byte_total = 0

        for func in internal:
            name = str(func.getName())
            addr = str(func.getEntryPoint())
            record: dict[str, Any] = {
                "address": addr,
                "name": name,
                "status": "failed",
            }
            try:
                lines = [
                    f"; func-name: {name}",
                    f"; func-address: {addr}",
                    f"; thunk: {str(bool(func.isThunk())).lower()}",
                    "; format: address<TAB>raw-bytes<TAB>instruction",
                    "",
                ]
                instruction_count = 0
                function_bytes = 0
                for instruction in listing.getInstructions(func.getBody(), True):
                    raw_bytes = [int(value) & 0xFF for value in instruction.getBytes()]
                    raw = " ".join(f"{value:02x}" for value in raw_bytes)
                    lines.append(f"{instruction.getAddress()}\t{raw}\t{instruction}")
                    instruction_count += 1
                    function_bytes += len(raw_bytes)

                if instruction_count == 0:
                    record["error"] = "function body contains no defined instructions"
                    failed += 1
                    self._disassembly_records.append(record)
                    continue

                filename = f"{sanitize_filename(name)}_{sanitize_filename(addr)}.asm"
                (disassembly_dir / filename).write_text(
                    "\n".join(lines) + "\n",
                    encoding="utf-8",
                )
                record.update(
                    {
                        "status": "exported",
                        "instructionCount": instruction_count,
                        "instructionBytes": function_bytes,
                    }
                )
                exported += 1
                instruction_total += instruction_count
                byte_total += function_bytes
            except Exception as exc:
                if self.strict:
                    raise
                record["error"] = str(exc)
                failed += 1
            self._disassembly_records.append(record)

        self.stats["disassembly"] = {
            "attempted": len(internal),
            "exported": exported,
            "failed": failed,
            "external_skipped": external_skipped,
            "instruction_count": instruction_total,
            "instruction_bytes": byte_total,
        }
        logger.info(
            "  Disassembly: "
            f"{exported}/{len(internal)} functions, "
            f"{instruction_total} instructions, {failed} failed"
        )

    # --- Cross references ---

    def _xrefs_to(self, addr) -> list[str]:
        """Functions (name@entry) that reference an address."""
        rm = self.program.getReferenceManager()
        fm = self.program.getFunctionManager()
        out: list[str] = []
        try:
            for ref in rm.getReferencesTo(addr):
                from_addr = ref.getFromAddress()
                f = fm.getFunctionContaining(from_addr)
                out.append(
                    f"{f.getName()}@{f.getEntryPoint()}" if f else str(from_addr)
                )
        except Exception as e:
            self._handle_exc(f"xrefs to {addr}", e)
        return list(dict.fromkeys(out))

    def _symbol_xrefs(self, symbol: "Symbol") -> list[str]:
        """Functions (name@entry) that reference a symbol."""
        fm = self.program.getFunctionManager()
        out: list[str] = []
        try:
            for ref in symbol.getReferences():
                from_addr = ref.getFromAddress()
                f = fm.getFunctionContaining(from_addr)
                out.append(
                    f"{f.getName()}@{f.getEntryPoint()}" if f else str(from_addr)
                )
        except Exception as e:
            self._handle_exc(f"xrefs to symbol {symbol.getName()}", e)
        return list(dict.fromkeys(out))

    # --- Strings ---

    def export_strings(self, output_dir: Path):
        from ghidra.program.model.data import StringDataInstance

        strings_file = output_dir / "strings.txt"
        count = 0
        listing = self.program.getListing()

        with open(strings_file, "w") as f:
            f.write("# address\tlength\ttype\trefs\tvalue\n")
            for data in listing.getDefinedData(True):
                try:
                    if not StringDataInstance.isString(data):
                        continue
                    value = data.getValue()
                    if value is None:
                        continue
                    addr = data.getAddress()
                    dt_name = data.getDataType().getName()
                    refs = self._xrefs_to(addr)
                    refs_str = ",".join(refs) if refs else "-"
                    svalue = escape_string_value(str(value))
                    f.write(
                        f"{addr}\t{data.getLength()}\t{dt_name}\t{refs_str}\t{svalue}\n"
                    )
                    count += 1
                except Exception as e:
                    self._handle_exc("string export", e)

        logger.info(f"  Strings: {count} exported")

    # --- Imports / Exports ---

    def export_imports(self, output_dir: Path):
        imports_file = output_dir / "imports.txt"
        count = 0

        st = self.program.getSymbolTable()

        with open(imports_file, "w") as f:
            f.write("# library\tname\taddress\trefs\n")
            for symbol in st.getExternalSymbols():
                try:
                    library = str(symbol.getParentNamespace())
                    name = symbol.getName()
                    addr = symbol.getAddress()
                    refs = self._symbol_xrefs(symbol)
                    refs_str = ",".join(refs) if refs else "-"
                    f.write(f"{library}\t{name}\t{addr}\t{refs_str}\n")
                    count += 1
                except Exception as e:
                    self._handle_exc("import export", e)

        logger.info(f"  Imports: {count} exported")

    def export_exports(self, output_dir: Path):
        exports_file = output_dir / "exports.txt"
        count = 0

        st = self.program.getSymbolTable()

        with open(exports_file, "w") as f:
            f.write("# address\tname\tdemangled\n")
            for symbol in st.getAllSymbols(True):
                if symbol.isExternalEntryPoint():
                    addr = symbol.getAddress()
                    name = symbol.getName()
                    demangled = self._demangle(name) or "-"
                    f.write(f"{addr}\t{name}\t{demangled}\n")
                    count += 1

        logger.info(f"  Exports: {count} exported")

    def _demangle(self, name: str):
        """Best-effort demangle of mangled-looking names; never raises."""
        if not name:
            return None
        if "?" not in name and "_Z" not in name and "@" not in name:
            return None
        try:
            from ghidra.app.util.demangler import DemanglerUtil

            results = list(DemanglerUtil.demangle(self.program, name, None) or [])
            if results:
                return str(results[0].getSignature(False))
        except Exception:
            return None
        return None

    # --- Sections / entropy ---

    def export_sections(self, output_dir: Path):
        sections_file = output_dir / "sections.txt"
        mem = self.program.getMemory()
        count = 0

        with open(sections_file, "w") as f:
            f.write("# name\tstart\tend\tsize\tperms\tinitialized\tentropy\n")
            for block in mem.getBlocks():
                try:
                    perms = (
                        ("r" if block.isRead() else "-")
                        + ("w" if block.isWrite() else "-")
                        + ("x" if block.isExecute() else "-")
                    )
                    initialized = block.isInitialized()
                    entropy = self._block_entropy(block) if initialized else 0.0
                    f.write(
                        f"{block.getName()}\t{block.getStart()}\t{block.getEnd()}\t"
                        f"{block.getSize()}\t{perms}\t{initialized}\t{entropy:.3f}\n"
                    )
                    count += 1
                except Exception as e:
                    self._handle_exc("section export", e)

        logger.info(f"  Sections: {count} exported")

    def _block_entropy(self, block: "MemoryBlock") -> float:
        from jpype import JByte

        mem = self.program.getMemory()
        start = block.getStart()
        size = block.getSize()

        histogram = [0] * 256
        total = 0
        offset = 0
        chunk = 1024 * 1024

        while offset < size and total < self.ENTROPY_SAMPLE_BYTES:
            n = min(chunk, size - offset)
            buf = JByte[n]  # type: ignore[reportInvalidTypeArguments]
            read = mem.getBytes(start.add(offset), buf)
            if read <= 0:
                break
            for b in buf[:read]:  # type: ignore[reportGeneralTypeIssues]
                histogram[b & 0xFF] += 1
            total += read
            offset += n

        return shannon_entropy(histogram, total)

    # --- Triage hints ---

    def export_triage(self, output_dir: Path):
        triage_file = output_dir / "triage.txt"
        st = self.program.getSymbolTable()
        fm = self.program.getFunctionManager()

        lines: list[str] = ["== Entry Points =="]
        try:
            lines.append(f"image_base: {self.program.getImageBase()}")
        except Exception as e:
            self._handle_exc("image base", e)
        try:
            for addr in st.getExternalEntryPointIterator():
                f = fm.getFunctionContaining(addr)
                label = f"{f.getName()}@{f.getEntryPoint()}" if f else str(addr)
                lines.append(f"entry: {addr}  {label}")
        except Exception as e:
            self._handle_exc("entry points", e)

        lines.append("")
        lines.append("== Suspicious API Usage ==")
        found = 0
        try:
            for symbol in st.getExternalSymbols():
                name = symbol.getName()
                cats = match_suspicious(name)
                if not cats:
                    continue
                refs = self._symbol_xrefs(symbol)
                refs_str = ", ".join(refs) if refs else "(no direct refs)"
                lines.append(f"[{','.join(cats)}] {name}: {refs_str}")
                found += 1
        except Exception as e:
            self._handle_exc("suspicious api scan", e)
        if found == 0:
            lines.append("(none detected)")

        triage_file.write_text("\n".join(lines) + "\n")
        logger.info(f"  Triage: {found} suspicious imports flagged")

    # --- Memory ---

    def export_memory(self, output_dir: Path):
        memory_dir = output_dir / "memory"
        memory_dir.mkdir(parents=True, exist_ok=True)

        mem = self.program.getMemory()
        blocks = mem.getBlocks()

        MAX_SIZE = 1024 * 1024
        file_count = 0
        total_bytes = 0

        for block in blocks:
            if block.isOverlay():
                continue

            if not block.isInitialized():
                continue

            if block.isExecute() and not self.dump_executable:
                logger.info(
                    f"  Memory: skipping executable block {block.getName()} "
                    "(use --all-memory to include)"
                )
                continue

            start = block.getStart()
            end = block.getEnd()
            size = block.getSize()

            if size <= 0:
                continue

            logger.info(f"  Memory: {start} - {end} ({size} bytes)")

            offset = 0

            while offset < size:
                chunk_size = min(size - offset, MAX_SIZE)
                chunk_start_addr = start.add(offset)

                try:
                    content = self._read_hexdump(chunk_start_addr, chunk_size)

                    filename = (
                        f"{chunk_start_addr}--{chunk_start_addr.add(chunk_size)}.txt"
                    )
                    filepath = memory_dir / filename
                    filepath.write_text(content)

                    file_count += 1
                    total_bytes += chunk_size
                except Exception as e:
                    self._handle_exc(f"memory read at {chunk_start_addr}", e)

                offset += chunk_size

        self.stats["memory_files"] = file_count
        self.stats["memory_bytes"] = total_bytes

        logger.info(f"  Memory: {file_count} files ({total_bytes} bytes)")

    def _read_hexdump(self, start, size: int) -> str:
        from jpype import JByte

        mem = self.program.getMemory()
        buf = JByte[size]  # type: ignore[reportInvalidTypeArguments]
        n = mem.getBytes(start, buf)

        if n <= 0:
            return ""

        data = [b & 0xFF for b in buf[:n]]  # type: ignore[reportGeneralTypeIssues]

        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            addr = start.add(i)

            hex_part = " ".join(f"{b:02x}" for b in chunk)
            hex_part = hex_part.ljust(48)

            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)

            lines.append(f"{addr}  {hex_part}  {ascii_part}")

        return "\n".join(lines)

    # --- Diagnostics ---

    def _program_diagnostics(self) -> dict[str, Any]:
        def read(getter, default="unknown"):
            try:
                value = getter()
                return default if value is None else str(value)
            except Exception:
                return default

        try:
            from ghidra.framework import Application

            ghidra_version = str(Application.getApplicationVersion())
        except Exception:
            ghidra_version = "unknown"

        return {
            "name": read(self.program.getName),
            "ghidraVersion": ghidra_version,
            "language": read(self.program.getLanguageID),
            "compilerSpec": read(
                lambda: self.program.getCompilerSpec().getCompilerSpecID()
            ),
            "executableFormat": read(self.program.getExecutableFormat),
            "imageBase": read(self.program.getImageBase),
        }

    def build_diagnostics(self) -> dict[str, Any]:
        """Build a JSON-serializable summary of analysis and artifact quality."""
        internal_functions = [func for func in self.functions if not func.isExternal()]
        external_count = len(self.functions) - len(internal_functions)
        thunk_count = sum(1 for func in internal_functions if func.isThunk())

        decompiled_addresses = {
            record["address"]
            for record in self._decompile_records
            if record["status"] == "exported"
        }
        disassembled_addresses = {
            record["address"]
            for record in self._disassembly_records
            if record["status"] == "exported"
        }
        if self.skip_disassembly:
            required_addresses = {
                str(func.getEntryPoint())
                for func in internal_functions
                if not func.isThunk()
            }
        else:
            required_addresses = {
                str(func.getEntryPoint()) for func in internal_functions
            }
        artifact_addresses = decompiled_addresses | disassembled_addresses
        covered = len(required_addresses & artifact_addresses)
        artifact_coverage = (
            covered / len(required_addresses) if required_addresses else None
        )
        self.stats["artifact_coverage"] = artifact_coverage

        diagnostics_status = (
            "complete"
            if not self._export_errors
            and (artifact_coverage is None or artifact_coverage == 1.0)
            else "degraded"
        )
        analysis_log = self._analysis_log[-ANALYSIS_LOG_LIMIT:]
        return {
            "schemaVersion": 1,
            "status": diagnostics_status,
            "program": self._program_diagnostics(),
            "analysis": {
                "performedByExporter": self._analysis_performed_by_exporter,
                "logTruncated": len(self._analysis_log) > ANALYSIS_LOG_LIMIT,
                "logTail": analysis_log,
            },
            "functions": {
                "total": len(self.functions),
                "internal": len(internal_functions),
                "external": external_count,
                "internalThunks": thunk_count,
                "artifactCovered": covered,
                "artifactCoverage": artifact_coverage,
            },
            "decompilation": {
                "attempted": self.stats["exported"] + self.stats["failed"],
                "exported": self.stats["exported"],
                "failed": self.stats["failed"],
                "skipped": self.stats["skipped"],
                "warnings": self.stats["warnings"],
                "records": sorted(
                    self._decompile_records,
                    key=lambda record: (
                        record["address"],
                        record["name"],
                    ),
                ),
            },
            "disassembly": {
                **self.stats["disassembly"],
                "records": sorted(
                    self._disassembly_records,
                    key=lambda record: (
                        record["address"],
                        record["name"],
                    ),
                ),
            },
            "artifacts": {
                "errors": list(self._export_errors),
            },
        }

    def export_diagnostics(self, output_dir: Path) -> dict[str, Any]:
        diagnostics = self.build_diagnostics()
        self.last_diagnostics = diagnostics
        diagnostics_path = Path(output_dir) / DIAGNOSTICS_FILENAME
        diagnostics_path.write_text(
            json.dumps(diagnostics, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        logger.info(
            "  Diagnostics: "
            f"{diagnostics['status']} "
            f"(artifact coverage="
            f"{diagnostics['functions']['artifactCoverage']})"
        )
        return diagnostics

    def _print_statistics(self):
        logger.info("-" * 50)
        logger.info("Export Summary:")
        logger.info(f"  Total functions: {self.stats['total_functions']}")
        logger.info(f"  Exported:        {self.stats['exported']}")
        logger.info(f"  Skipped:         {self.stats['skipped']}")
        logger.info(f"  Failed:          {self.stats['failed']}")
        logger.info(f"  Warnings:        {self.stats['warnings']}")
        logger.info(
            "  Assembly:        "
            f"{self.stats['disassembly']['exported']}/"
            f"{self.stats['disassembly']['attempted']}"
        )
        logger.info(f"  Memory files:    {self.stats['memory_files']}")
        logger.info(f"  Memory bytes:    {self.stats['memory_bytes']}")
